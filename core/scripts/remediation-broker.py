#!/usr/bin/env python3
"""Rank runtime CVE findings into deterministic remediation campaigns.

The broker is intentionally boring: it reads the normalized Grype JSON emitted
by scan-vulnerabilities.mjs and decides which findings are actionable before an
LLM is allowed to draft a patch recipe.
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone


PRODUCTION_TIERS = {"slim", "distroless"}
SEVERITY_WEIGHT = {
    "critical": 1000,
    "high": 700,
    "medium": 300,
    "low": 100,
    "negligible": 10,
    "unknown": 0,
}


def parse_version(value):
    try:
        return [int(part) for part in value.lstrip("v").split(".")]
    except Exception:
        return [0, 0, 0]


def latest_vulnerability_dir(root):
    if not os.path.isdir(root):
        return None
    dirs = [
        name
        for name in os.listdir(root)
        if os.path.isdir(os.path.join(root, name))
    ]
    if not dirs:
        return None
    dirs.sort(key=parse_version, reverse=True)
    return os.path.join(root, dirs[0])


def vulnerability_root_stats(root):
    abs_root = os.path.abspath(root)
    exists = os.path.isdir(root)
    version_dirs = []
    scan_files = []
    if exists:
        version_dirs = sorted(
            name
            for name in os.listdir(root)
            if os.path.isdir(os.path.join(root, name))
        )
        scan_files = glob.glob(os.path.join(root, "*", "*.json"))
        if not scan_files:
            scan_files = glob.glob(os.path.join(root, "*.json"))
    return {
        "root": root,
        "abs_root": abs_root,
        "exists": exists,
        "version_dirs": version_dirs,
        "scan_file_count": len(scan_files),
    }


def print_vulnerability_root_diagnostics(root, selected_dir=None):
    stats = vulnerability_root_stats(root)
    print(f"[broker] cwd={os.getcwd()}", file=sys.stderr)
    print(f"[broker] checked_vuln_root={stats['root']}", file=sys.stderr)
    print(f"[broker] absolute_vuln_root={stats['abs_root']}", file=sys.stderr)
    print(f"[broker] vuln_root_exists={str(stats['exists']).lower()}", file=sys.stderr)
    print(
        f"[broker] scan_artifacts_present={str(stats['scan_file_count'] > 0).lower()}",
        file=sys.stderr,
    )
    print(f"[broker] version_dir_count={len(stats['version_dirs'])}", file=sys.stderr)
    print(f"[broker] scan_json_count={stats['scan_file_count']}", file=sys.stderr)
    if stats["version_dirs"]:
        print(
            "[broker] newest_version_dirs="
            + ", ".join(sorted(stats["version_dirs"], key=parse_version, reverse=True)[:5]),
            file=sys.stderr,
        )
    if selected_dir:
        print(f"[broker] selected_vuln_dir={selected_dir}", file=sys.stderr)


def split_target_file(path):
    name = os.path.basename(path)
    match = re.match(r"^(.+)-(amd64|arm64)\.json$", name)
    if not match:
        return None
    target, arch = match.groups()
    idx = target.rfind("-")
    if idx == -1:
        return None
    return {
        "target": target,
        "language": target[:idx],
        "tier": target[idx + 1 :],
        "arch": arch,
        "sourceFile": path,
    }


def fixed_version(value):
    if not value:
        return ""
    return str(value).split(",", 1)[0].strip()


def finding_score(campaign):
    severity = SEVERITY_WEIGHT.get(campaign["severity"].lower(), 0)
    prod_fanout = sum(
        1 for target in campaign["affectedTargets"] if target["tier"] in PRODUCTION_TIERS
    )
    fanout = len(campaign["affectedTargets"])
    risk = campaign.get("riskScore") or 0
    epss = campaign.get("epssScore") or 0
    fixed_bonus = 150 if campaign.get("fixedVersion") else 0
    return severity + (prod_fanout * 40) + (fanout * 5) + fixed_bonus + risk + (epss * 100)


def normalize_campaigns(vuln_dir):
    campaigns = {}
    deferred = []

    for file_path in sorted(glob.glob(os.path.join(vuln_dir, "*.json"))):
        target = split_target_file(file_path)
        if not target:
            continue
        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for finding in data.get("findings", []):
            package = finding.get("packageName")
            cve = finding.get("id")
            if not package or not cve:
                continue

            severity = str(finding.get("severity", "Unknown"))
            severity_key = severity.lower()
            layer = finding.get("layer", "base")
            fix = fixed_version(finding.get("fixedIn"))
            reason = None
            if layer != "runtime":
                reason = "base_layer"
            elif severity_key not in {"critical", "high"}:
                reason = "below_priority_threshold"
            elif not fix:
                reason = "no_fixed_version"

            if reason:
                deferred.append(
                    {
                        "reason": reason,
                        "cve": cve,
                        "package": package,
                        "severity": severity,
                        "layer": layer,
                        "target": target["target"],
                        "tier": target["tier"],
                        "arch": target["arch"],
                        "fixState": finding.get("fixState", "unknown"),
                    }
                )
                continue

            key = (package, cve, finding.get("packageVersion") or "", fix)
            if key not in campaigns:
                campaigns[key] = {
                    "package": package,
                    "cve": cve,
                    "installedVersion": finding.get("packageVersion") or "",
                    "fixedVersion": fix,
                    "fixState": finding.get("fixState", "unknown"),
                    "severity": severity,
                    "layer": layer,
                    "cvssScore": finding.get("cvssScore"),
                    "cvssVector": finding.get("cvssVector"),
                    "epssScore": finding.get("epssScore"),
                    "epssPercentile": finding.get("epssPercentile"),
                    "riskScore": finding.get("riskScore"),
                    "dataSource": finding.get("dataSource"),
                    "namespace": finding.get("namespace"),
                    "description": finding.get("description"),
                    "recommendedRoute": "version_bump",
                    "affectedTargets": [],
                }
            campaigns[key]["affectedTargets"].append(target)

    normalized = []
    for campaign in campaigns.values():
        campaign["affectedTargets"].sort(
            key=lambda item: (item["tier"] not in PRODUCTION_TIERS, item["target"], item["arch"])
        )
        campaign["productionTargetCount"] = sum(
            1 for target in campaign["affectedTargets"] if target["tier"] in PRODUCTION_TIERS
        )
        campaign["targetCount"] = len(campaign["affectedTargets"])
        campaign["score"] = round(finding_score(campaign), 3)
        normalized.append(campaign)

    normalized.sort(
        key=lambda item: (
            item["productionTargetCount"] == 0,
            -item["score"],
            item["package"],
            item["cve"],
            item["installedVersion"],
        )
    )
    return normalized, deferred


def build_plan(vuln_dir, limit=0, include_dev_only=False):
    campaigns, deferred = normalize_campaigns(vuln_dir)
    candidate_campaign_count = len(campaigns)
    dev_only_campaign_count = sum(
        1 for campaign in campaigns if campaign["productionTargetCount"] == 0
    )
    deferred_reason_counts = {}
    production_deferred_reason_counts = {}
    for item in deferred:
        reason = item.get("reason", "unknown")
        deferred_reason_counts[reason] = deferred_reason_counts.get(reason, 0) + 1
        if item.get("tier") in PRODUCTION_TIERS:
            production_deferred_reason_counts[reason] = (
                production_deferred_reason_counts.get(reason, 0) + 1
            )
    if not include_dev_only:
        campaigns = [
            campaign for campaign in campaigns if campaign["productionTargetCount"] > 0
        ]
    if limit > 0:
        campaigns = campaigns[:limit]
    return {
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "sourceDir": vuln_dir,
        "campaigns": campaigns,
        "deferred": deferred,
        "summary": {
            "campaignCount": len(campaigns),
            "candidateCampaignCount": candidate_campaign_count,
            "deferredCount": len(deferred),
            "deferredReasonCounts": deferred_reason_counts,
            "productionDeferredReasonCounts": production_deferred_reason_counts,
            "devOnlyCampaignCount": dev_only_campaign_count,
            "includeDevOnly": include_dev_only,
            "productionCampaignCount": sum(
                1 for campaign in campaigns if campaign["productionTargetCount"] > 0
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Build a ClearCutt remediation campaign plan.")
    parser.add_argument(
        "--vuln-root",
        default=os.path.join("site", "src", "data", "vulnerabilities"),
        help="Root directory containing versioned vulnerability scan outputs.",
    )
    parser.add_argument("--vuln-dir", default="", help="Specific vulnerability directory to read.")
    parser.add_argument("--limit", type=int, default=0, help="Maximum campaigns to emit.")
    parser.add_argument("--out", default="", help="Optional output JSON path.")
    parser.add_argument(
        "--include-dev-only",
        action="store_true",
        help="Include dev-tier-only campaigns. By default auto-remediation is production-only.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Write the plan without printing the full JSON payload to stdout.",
    )
    args = parser.parse_args()

    vuln_dir = args.vuln_dir or latest_vulnerability_dir(args.vuln_root)
    if not vuln_dir:
        print("[broker] no vulnerability scan directory found", file=sys.stderr)
        print_vulnerability_root_diagnostics(args.vuln_root)
        return 1
    if not os.path.isdir(vuln_dir):
        print(f"[broker] vulnerability directory does not exist: {vuln_dir}", file=sys.stderr)
        print_vulnerability_root_diagnostics(args.vuln_root, selected_dir=vuln_dir)
        return 1

    plan = build_plan(vuln_dir, args.limit, include_dev_only=args.include_dev_only)
    rendered = json.dumps(plan, indent=2, sort_keys=True)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    if args.quiet:
        summary = plan["summary"]
        print(
            "[broker] "
            f"campaigns={summary['campaignCount']} "
            f"candidates={summary['candidateCampaignCount']} "
            f"production={summary['productionCampaignCount']} "
            f"dev_only={summary['devOnlyCampaignCount']} "
            f"deferred={summary['deferredCount']} "
            f"criteria=high-critical-runtime-with-fixed-version "
            f"source={vuln_dir}"
        )
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
