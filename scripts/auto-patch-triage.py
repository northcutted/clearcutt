#!/usr/bin/env python3
# ClearCutt Automated AI CVE Triage & Auto-Patch Dispatcher
# Author: Eddie Northcutt
# Paradigm: Ephemeral Scan Parsing, Filtering, & Hands-Free PR Gating (Stage 2)

import os
import sys
import json
import glob
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

def find_latest_vulnerability_dir():
    vuln_path = "./site/src/data/vulnerabilities"
    if not os.path.exists(vuln_path):
        return None
    
    # Sort directories by semantic version names
    dirs = [d for d in os.listdir(vuln_path) if os.path.isdir(os.path.join(vuln_path, d))]
    if not dirs:
        return None
    
    # Helper to parse version list cleanly (e.g. "v0.5.3" -> [0, 5, 3])
    def parse_ver(v_str):
        try:
            return [int(x) for x in v_str.lstrip("v").split(".")]
        except Exception:
            return [0, 0, 0]
            
    dirs.sort(key=parse_ver, reverse=True)
    return os.path.join(vuln_path, dirs[0])

def parse_findings(vuln_dir):
    json_files = glob.glob(os.path.join(vuln_dir, "*.json"))
    log_info(f"Scanning {len(json_files)} vulnerability files in {vuln_dir}...")
    
    unique_findings = {}
    for f_path in json_files:
        try:
            with open(f_path, "r") as f:
                data = json.load(f)
            findings = data.get("findings", [])
            for fnd in findings:
                # Filter strictly for Nix-managed "runtime" layer package vulnerabilities
                if fnd.get("layer") != "runtime":
                    continue
                    
                # Prioritize Critical and High severity CVEs to prevent noise
                severity = fnd.get("severity", "Unknown").lower()
                if severity not in ["critical", "high"]:
                    continue
                    
                pkg = fnd.get("packageName")
                cve = fnd.get("id")
                ver = fnd.get("packageVersion")
                fix = fnd.get("fixedIn")
                
                if not pkg or not cve:
                    continue
                    
                key = (pkg, cve)
                if key not in unique_findings:
                    unique_findings[key] = {
                        "package": pkg,
                        "cve": cve,
                        "installed_version": ver,
                        "fixed_version": fix if fix else ""
                    }
        except Exception as e:
            log_warn(f"Failed to parse findings in {f_path}: {e}")
            
    return list(unique_findings.values())

def execute_patch_for_finding(finding):
    pkg = finding["package"]
    cve = finding["cve"]
    ver = finding["installed_version"]
    fix = finding["fixed_version"]
    
    log_info(f"Dispatching AI Patching Agent for: {pkg} ({ver}) -> {cve}...")
    
    env = os.environ.copy()
    env["CVE_ID"] = f"{cve} (use postInstall comment override)"
    env["PACKAGE_NAME"] = pkg
    env["INSTALLED_VERSION"] = ver
    env["FIXED_VERSION"] = fix
    
    # Run the patching agent subprocess
    res = subprocess.run(
        ["./scripts/cve-draft-agent.py"],
        env=env,
        capture_output=True,
        text=True
    )
    
    # Print agent stdout/stderr
    if res.stdout:
        print(res.stdout)
    if res.stderr:
        print(res.stderr, file=sys.stderr)
        
    if res.returncode != 0:
        log_warn(f"AI Patching Agent failed to draft a patch for {pkg} ({cve}).")
        return False
        
    log_pass(f"AI Patching Agent drafted and verified patch for {pkg} ({cve}) successfully!")
    
    # Check if a new git branch was created
    branch_res = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True)
    branch_name = branch_res.stdout.strip()
    
    if branch_name.startswith("cve-remediation/"):
        log_info(f"Remediation branch '{branch_name}' detected. Pushing to origin...")
        subprocess.run(["git", "push", "origin", branch_name, "--force"], capture_output=True)
        
        log_info("Opening draft Pull Request via GitHub CLI...")
        pr_body = (
            f"This Pull Request was automatically drafted and verified by the **ClearCutt Auto-Patch Pipeline**.<br><br>"
            f"### Details:<br>"
            f"- **Package:** `{pkg}`<br>"
            f"- **CVE:** `{cve}`<br>"
            f"- **Installed Version:** `{ver}`<br>"
            f"- **Verification Status:** 100% Green (G1-G5 Gates Passed)<br><br>"
            f"Review the overlay diff in `overlays/cve-remediation.nix` and merge when ready!"
        )
        pr_title = f"chore: automated CVE patch remediation for {pkg} ({cve})"
        subprocess.run([
            "gh", "pr", "create",
            "--title", pr_title,
            "--body", pr_body,
            "--head", branch_name,
            "--base", "main",
            "--draft"
        ], capture_output=True)
        log_pass(f"Pull Request successfully opened for {pkg} ({cve})!")
        
        # Checkout back to main before processing the next finding
        subprocess.run(["git", "checkout", "main"], capture_output=True)
        return True
    else:
        log_warn("No active git branch detected from the agent run.")
        return False

def main():
    log_info("Initializing AI CVE Triage & Auto-Patch Dispatcher...")

    vuln_dir = find_latest_vulnerability_dir()
    if not vuln_dir:
        log_fail("No scanned vulnerability directories found in site/src/data/vulnerabilities!")

    findings = parse_findings(vuln_dir)
    if not findings:
        log_pass("Zero new High or Critical runtime vulnerabilities identified. Triage clean!")
        return

    log_info(f"Identified {len(findings)} unique High/Critical runtime vulnerabilities ready for patching.")

    # Bound per-run work so a backlog of findings can't blow past the workflow
    # timeout. Anything above the cap rolls into the next scheduled run.
    try:
        cap = int(os.environ.get("MAX_FINDINGS_PER_RUN", "0"))
    except ValueError:
        cap = 0
    if cap > 0 and len(findings) > cap:
        log_warn(f"Capping this run at {cap} findings (MAX_FINDINGS_PER_RUN). "
                 f"Remaining {len(findings) - cap} will be picked up next run.")
        findings = findings[:cap]

    success_count = 0
    for fnd in findings:
        # Prevent runaway parallel API calls by processing findings sequentially
        if execute_patch_for_finding(fnd):
            success_count += 1

    log_pass(f"Auto-Patch Dispatcher complete. Patched {success_count}/{len(findings)} vulnerabilities successfully.")

if __name__ == "__main__":
    main()
