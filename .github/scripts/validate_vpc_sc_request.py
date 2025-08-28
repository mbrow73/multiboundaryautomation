#!/usr/bin/env python3
"""
validate_vpc_sc_request.py

Validates a VPC Service Controls request by parsing the issue body and
checking for common mistakes:
  * Project IDs must be 10 digits when using projects/<id> format
  * Each perimeter referenced must exist in router.yml
  * 'sources'/'From' may only appear in ingress rules
  * IP addresses must be in CIDR notation x.x.x.x/xx and require a TLM-ID on ingress
Outputs are written to $GITHUB_OUTPUT:
  - valid: 'true' or 'false'
  - errors: JSON array of strings describing each problem
"""

import argparse
import json
import re
import os
from typing import Dict, Any, List
import yaml  # type: ignore

def parse_issue_body(issue_text: str) -> Dict[str, Any]:
    # Strip markdown formatting for easier parsing
    clean_text = re.sub(r"[\*`]+", "", issue_text)
    reqid_match = re.search(r"Request ID.*?:\s*([A-Za-z0-9_-]+)", clean_text, re.IGNORECASE)
    reqid = reqid_match.group(1).strip() if reqid_match else "REQ"
    # Gather perimeters (global default)
    perimeters: List[str] = []
    match_global_perimeter = re.search(r"^Perimeter Name\s*:?(.*)$", clean_text, re.IGNORECASE | re.MULTILINE)
    if match_global_perimeter:
        value = match_global_perimeter.group(1).strip()
        for part in re.split(r",", value):
            perim = part.strip()
            if perim and perim != "(s)":
                perimeters.append(perim)
    # TLM-ID or third-party fallback
    tlm_match = re.search(r"TLM[-\u2011\u2012\u2013\u2014]?ID.*?:\s*(.+)", issue_text, re.IGNORECASE)
    third_party_match = re.search(r"Third\s*-?Party\s*Name.*?:\s*(.+)", issue_text, re.IGNORECASE)
    tlm_id = ""
    if tlm_match:
        tlm_id = tlm_match.group(1).strip()
    elif third_party_match:
        tlm_id = third_party_match.group(1).strip()

    rules: List[Dict[str, Any]] = []
    # Split issue into rule blocks
    rule_pattern = re.compile(
        r"Perimeter Name\(s\)?[^\n]*\n.*?(?=(?:\n\s*Perimeter Name\(s\)?|\Z))",
        re.IGNORECASE | re.DOTALL,
    )
    for match in rule_pattern.finditer(clean_text):
        block = match.group(0)
        dir_match = re.search(r"Direction[^\n]*\n\s*(INGRESS|EGRESS)", block, re.IGNORECASE)
        direction = dir_match.group(1).upper() if dir_match else ""
        # Helper to extract list values under a given heading
        def extract_values(label: str) -> List[str]:
            pattern = rf"{label}[^\n]*\n((?:\s+[^\n]+\n)*)"
            m = re.search(pattern, block, re.IGNORECASE)
            result: List[str] = []
            if m:
                for line in m.group(1).splitlines():
                    stripped = line.strip()
                    if stripped:
                        result.extend([p.strip() for p in stripped.split(",") if p.strip()])
            return result

        services = extract_values("Services")
        methods_raw = extract_values("Methods")
        permissions_raw = extract_values("Permissions")
        sources = extract_values("Source / From") + extract_values("From")
        destinations = extract_values("Destination / To") + extract_values("To")
        identities = extract_values("Identities")

        # Map service-specific methods and permissions (optional)
        service_methods = {svc: [] for svc in services}
        for item in methods_raw:
            if ":" in item:
                svc, mlist = item.split(":", 1)
                svc = svc.strip()
                if svc in service_methods:
                    service_methods[svc] = [v.strip() for v in mlist.split(",") if v.strip()]
        service_permissions = {svc: [] for svc in services}
        for item in permissions_raw:
            if ":" in item:
                svc, plist = item.split(":", 1)
                svc = svc.strip()
                if svc in service_permissions:
                    service_permissions[svc] = [v.strip() for v in plist.split(",") if v.strip()]

        rules.append({
            "direction": direction,
            "services": services,
            "service_methods": service_methods,
            "service_permissions": service_permissions,
            "sources": sources,
            "destinations": destinations,
            "identities": identities,
            "perimeters": perimeters,
        })
    return {"reqid": reqid, "rules": rules, "tlm_id": tlm_id}

def validate_data(parsed: Dict[str, Any], router: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    router_perims = set(router.get("perimeters", {}).keys())
    reqid = parsed.get("reqid", "REQ")
    tlm_id = parsed.get("tlm_id", "").strip()
    ip_cidr_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

    for rule in parsed.get("rules", []):
        direction = rule.get("direction", "").upper()
        for p in rule.get("perimeters", []):
            if p not in router_perims:
                errors.append(f"Perimeter '{p}' in request {reqid} does not exist in router.yml.")
        for res in rule.get("sources", []) + rule.get("destinations", []):
            if res.startswith("projects/"):
                proj_id = res.split("/", 1)[-1]
                if not re.fullmatch(r"\d{10}", proj_id):
                    errors.append(f"Resource '{res}' must be of form projects/<10-digit ID>.")
        if direction == "EGRESS" and rule.get("sources"):
            errors.append("The 'From' or 'sources' field is not allowed on EGRESS rules.")
        for src in rule.get("sources", []):
            if "." in src and not src.startswith("projects/"):
                if not ip_cidr_re.fullmatch(src):
                    errors.append(f"IP '{src}' is not in CIDR format (x.x.x.x/xx).")
                if direction == "INGRESS" and not tlm_id:
                    errors.append("TLM-ID is required when specifying IP subnets in an INGRESS rule.")
    return errors

def main():
    parser = argparse.ArgumentParser(description="Validate a VPC SC request")
    parser.add_argument("--issue-file", required=True)
    parser.add_argument("--router-file", required=True)
    args = parser.parse_args()

    with open(args.issue_file, encoding="utf-8") as f:
        issue_text = f.read()
    with open(args.router_file, encoding="utf-8") as f:
        router = yaml.safe_load(f)

    parsed = parse_issue_body(issue_text)
    errors = validate_data(parsed, router)
    is_valid = "true" if not errors else "false"

    # Output via GitHub Actions
    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a") as out:
            out.write(f"valid={is_valid}\n")
            out.write(f"errors={json.dumps(errors)}\n")

    # Print summary for logs
    if errors:
        print("Validation failed with these issues:")
        for e in errors:
            print(f"- {e}")
    else:
        print("Validation passed with no issues.")

if __name__ == "__main__":
    main()
