#!/usr/bin/env python3
# ClearCutt SBOM Generator
# Generates valid SPDX 2.3 SBOM from Nix derivation dependency graphs

import sys
import os
import json
import re
from datetime import datetime, timezone

def parse_nix_store_path(path):
    """
    Parses a Nix store path to extract the hash, package name, and version.
    E.g. /nix/store/h164m5b18m8c87xmd8szc4k31b5l4n7z-glibc-2.39
    returns ("h164m5b18m8c87xmd8szc4k31b5l4n7z", "glibc", "2.39")
    """
    basename = os.path.basename(path)
    match = re.match(r"^([a-z0-9]{32})-(.+)$", basename)
    if not match:
        return None, basename, "unknown"
    
    pkg_hash = match.group(1)
    full_name = match.group(2)
    
    # Try to separate package name and version
    # Matches name followed by a dash and version numbers (e.g., python3-3.11.2 or nodejs-20.1)
    version_match = re.search(r"^(.*?)-([0-9]+(\.[0-9a-zA-Z-]+)*)$", full_name)
    if version_match:
        return pkg_hash, version_match.group(1), version_match.group(2)
    
    return pkg_hash, full_name, "LTS"

def generate_spdx(path_info_list, output_name="clearcutt-hardened-fleet"):
    doc_namespace = f"http://spdx.org/spdxdocs/{output_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": output_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "creators": [
                "Tool: ClearCutt-SBOM-Generator-1.0",
                "Organization: ClearCutt"
            ]
        },
        "packages": [],
        "relationships": []
    }
    
    # Track documented package IDs to avoid duplicates
    seen_ids = set()
    
    for item in path_info_list:
        path = item.get("path")
        if not path:
            continue
            
        pkg_hash, name, version = parse_nix_store_path(path)
        
        # Construct standard SPDX reference ID
        # SPDX Ref IDs must be alphanumeric and dashes only
        safe_name = re.sub(r"[^a-zA-Z0-9-]", "-", name)
        spdx_id = f"SPDXRef-{safe_name}-{pkg_hash[:8]}"
        
        if spdx_id in seen_ids:
            continue
        seen_ids.add(spdx_id)
        
        # Map package parameters
        pkg = {
            "name": name,
            "SPDXID": spdx_id,
            "versionInfo": version,
            "packageFileName": path,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "summary": f"Nix cryptographic store path: {path}"
        }
        
        spdx["packages"].append(pkg)
        
        # Link document root to all immediate top-level packages (those that represent the outputs)
        # For simplicity, we also connect standard relationships
        spdx["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id
        })
        
        # Map direct dependencies to SPDX relationships
        for ref in item.get("references", []):
            if ref == path:
                continue
            ref_hash, ref_name, _ = parse_nix_store_path(ref)
            safe_ref_name = re.sub(r"[^a-zA-Z0-9-]", "-", ref_name)
            ref_spdx_id = f"SPDXRef-{safe_ref_name}-{ref_hash[:8]}"
            
            spdx["relationships"].append({
                "spdxElementId": spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ref_spdx_id
            })
            
    return spdx

def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        try:
            with open(input_file, "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Read from stdin
        try:
            data = json.load(sys.stdin)
        except Exception as e:
            print(f"Error reading from standard input: {e}", file=sys.stderr)
            sys.exit(1)
            
    # Nix output can be a single dict or a list. Normalize to list.
    if isinstance(data, dict):
        # nix path-info outputs a dict where keys are paths
        normalized_data = []
        for path, info in data.items():
            info["path"] = path
            normalized_data.append(info)
        data = normalized_data
    elif not isinstance(data, list):
        print("Invalid input format. Expected Nix path-info JSON.", file=sys.stderr)
        sys.exit(1)
        
    spdx_doc = generate_spdx(data)
    print(json.dumps(spdx_doc, indent=2))

if __name__ == "__main__":
    main()
