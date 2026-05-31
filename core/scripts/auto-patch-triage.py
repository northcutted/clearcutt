#!/usr/bin/env python3
# ClearCutt Automated AI CVE Triage & Auto-Patch Dispatcher
# Author: Eddie Northcutt
# Paradigm: Ephemeral Scan Parsing, Filtering, & Hands-Free PR Gating (Stage 2)

import os
import sys
import json
import subprocess

BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

def log_info(msg): print(f"{BLUE}[Auto-Patch]{RESET} {msg}")
def log_pass(msg): print(f"{GREEN}[Auto-Patch] ✔ {msg}{RESET}")
def log_warn(msg): print(f"{YELLOW}[Auto-Patch] ⚠ {msg}{RESET}")
def log_fail(msg): print(f"{RED}[Auto-Patch] ✘ {msg}{RESET}", file=sys.stderr); sys.exit(1)

def env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        log_warn(f"Ignoring invalid integer value for {name}.")
        return default

def load_remediation_plan(cap):
    plan_path = os.path.join("build-outputs", "remediation-plan.json")
    cmd = ["./scripts/remediation-broker.py", "--out", plan_path, "--quiet"]
    vuln_root = os.environ.get("VULN_ROOT")
    vuln_dir = os.environ.get("REMEDIATION_VULN_DIR")
    if vuln_root:
        cmd.extend(["--vuln-root", vuln_root])
    if vuln_dir:
        cmd.extend(["--vuln-dir", vuln_dir])
    include_dev_only = os.environ.get("INCLUDE_DEV_ONLY_REMEDIATION", "").lower()
    if include_dev_only in {"1", "true", "yes"}:
        cmd.append("--include-dev-only")
    if cap > 0:
        cmd.extend(["--limit", str(cap)])

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.stdout:
        print(res.stdout)
    if res.stderr:
        print(res.stderr, file=sys.stderr)
    if res.returncode != 0:
        log_fail("Remediation broker failed to build an actionable campaign plan.")

    with open(plan_path, "r") as f:
        return json.load(f)

def campaign_slug(campaign):
    package = campaign["package"].lower()
    cve = campaign["cve"].lower()
    safe = "".join(ch if ch.isalnum() else "-" for ch in f"{cve}-{package}")
    return "-".join(part for part in safe.split("-") if part)

def execute_patch_for_campaign(campaign):
    pkg = campaign["package"]
    cve = campaign["cve"]
    ver = campaign["installedVersion"]
    fix = campaign.get("fixedVersion", "")

    log_info(f"Dispatching AI Patching Agent for: {pkg} ({ver}) -> {cve}...")

    env = os.environ.copy()
    env["CVE_ID"] = cve
    env["PACKAGE_NAME"] = pkg
    env["INSTALLED_VERSION"] = ver
    env["FIXED_VERSION"] = fix
    env["REMEDIATION_CAMPAIGN"] = json.dumps(campaign, sort_keys=True)
    env["AFFECTED_TARGETS"] = json.dumps(campaign.get("affectedTargets", []), sort_keys=True)
    summary_path = os.path.join("build-outputs", f"remediation-summary-{campaign_slug(campaign)}.json")
    env["REMEDIATION_SUMMARY_PATH"] = summary_path

    res = subprocess.run(
        ["./scripts/cve-draft-agent.py"],
        env=env,
        capture_output=True,
        text=True,
    )

    if res.stdout:
        print(res.stdout)
    if res.stderr:
        print(res.stderr, file=sys.stderr)

    if res.returncode != 0:
        log_warn(f"AI Patching Agent failed to draft a patch for {pkg} ({cve}).")
        return False

    log_pass(f"AI Patching Agent drafted a patch for {pkg} ({cve}); checking for branch...")

    branch_res = subprocess.run(
        ["git", "branch", "--show-current"],
        capture_output=True, text=True,
    )
    branch_name = branch_res.stdout.strip()

    if not branch_name.startswith("cve-remediation/"):
        log_warn("No remediation branch produced by the agent — skipping PR.")
        return False

    # Delegate PR opening to the shared script so the title/body never drifts
    # between the manual cve-patch-agent workflow and this auto-dispatcher.
    pr_res = subprocess.run(
        ["./scripts/open-remediation-pr.sh", branch_name, pkg, cve, ver, summary_path],
        capture_output=True, text=True,
    )
    if pr_res.stdout:
        print(pr_res.stdout)
    if pr_res.stderr:
        print(pr_res.stderr, file=sys.stderr)
    if pr_res.returncode != 0:
        log_warn(f"PR open failed for {pkg} ({cve}) — branch is still pushed.")
        # Continue so the next finding still gets a chance.

    subprocess.run(["git", "checkout", "main"], capture_output=True)
    return True

def main():
    log_info("Initializing AI CVE Triage & Auto-Patch Dispatcher...")

    # Bound per-run work so a backlog of findings can't blow past the workflow
    # timeout. Anything above the cap rolls into the next scheduled run.
    cap = env_int("MAX_FINDINGS_PER_RUN", 0)
    max_failures = env_int("MAX_PATCH_FAILURES_PER_RUN", 1)
    plan = load_remediation_plan(cap)
    campaigns = plan.get("campaigns", [])
    if not campaigns:
        summary = plan.get("summary", {})
        dev_only = summary.get("devOnlyCampaignCount", 0)
        prod_deferred = summary.get("productionDeferredReasonCounts", {})
        if dev_only:
            log_pass(
                "No fixable production runtime remediation campaigns selected; "
                f"{dev_only} dev-tier-only campaign(s) deferred by policy."
            )
            log_info(
                "Set INCLUDE_DEV_ONLY_REMEDIATION=1, or use the include_dev_only "
                "workflow input, for an explicit dev-tier remediation run."
            )
        else:
            log_pass(
                "Zero fixable High or Critical runtime vulnerabilities selected for "
                "automated remediation."
            )
        if prod_deferred:
            reason_summary = ", ".join(
                f"{reason}={count}" for reason, count in sorted(prod_deferred.items())
            )
            log_info(
                "Production findings outside auto-remediation policy: "
                f"{reason_summary}."
            )
        return

    log_info(
        f"Broker selected {len(campaigns)} remediation campaign(s) "
        f"from {plan.get('sourceDir', 'unknown source')}."
    )
    deferred_count = plan.get("summary", {}).get("deferredCount", 0)
    if deferred_count:
        log_warn(f"Broker deferred {deferred_count} finding occurrence(s) outside auto-remediation policy.")
    for index, campaign in enumerate(campaigns, start=1):
        log_info(
            f"Campaign {index}: {campaign['package']} {campaign['cve']} "
            f"{campaign.get('installedVersion', '?')} -> {campaign.get('fixedVersion', '?')} "
            f"targets={campaign.get('targetCount', len(campaign.get('affectedTargets', [])))} "
            f"prod_targets={campaign.get('productionTargetCount', 0)}"
        )

    success_count = 0
    failure_count = 0
    for campaign in campaigns:
        # Prevent runaway parallel API calls by processing findings sequentially
        if execute_patch_for_campaign(campaign):
            success_count += 1
        else:
            failure_count += 1
            if max_failures > 0 and failure_count >= max_failures:
                remaining = len(campaigns) - success_count - failure_count
                log_warn(
                    f"Stopping after {failure_count} failed patch attempt(s); "
                    f"{remaining} campaign(s) remain queued for a later run."
                )
                break

    attempted = success_count + failure_count
    log_pass(
        f"Auto-Patch Dispatcher complete. Drafted {success_count}/{attempted} attempted "
        f"remediation PR(s)."
    )

if __name__ == "__main__":
    main()
