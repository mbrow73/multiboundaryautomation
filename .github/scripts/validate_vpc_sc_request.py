#!/usr/bin/env python3
"""
validate_vpc_sc_request.py

Uses the handler's parser to read the issue, then validates:
  * Perimeter names exist in router.yml
  * Project IDs are 10-digit numbers
  * IP addresses are CIDR x.x.x.x/xx and require a TLM-ID for ingress rules
  * User-specified methods and permissions exist in SUPPORTED_METHODS/PERMISSIONS
Outputs:
  - valid: 'true' or 'false'
  - errors: JSON array of validation errors
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, Any, List

import yaml  # type: ignore

# Use the same parser as the handler
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from vpc_sc_request_handler import parse_issue_body  # type: ignore

# Fill these dictionaries with the strings from Google's supported method restrictions
SUPPORTED_METHODS: Dict[str, set[str]] = {
    "bigquery.googleapis.com": {
        # e.g. "BigQueryJobs.Get", "BigQueryJobs.List", "BigQueryStorage.CreateReadSession", "*"
    },
    "logging.googleapis.com": {
        # e.g. "WriteLogEntries", "ListLogEntries", "*"
    },
    # Add other services here...
}

SUPPORTED_PERMISSIONS: Dict[str, set[str]] = {
    "bigquery.googleapis.com": {
        # e.g. "bigquery.tables.get", "bigquery.jobs.create", "bigquery.jobs.get"
    },
    # Add other services here...
}

def validate_rules(rules: List[Dict[str, Any]], router: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    router_perims = set(router.get("perimeters", {}).keys())
    ip_cidr_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

    for rule in rules:
        direction = rule.get("direction", "").upper()
        # Perimeter existence
        for p in rule.get("perimeters", []):
            if p not in router_perims:
                errors.append(f"Perimeter '{p}' does not exist in router.yml.")
        # Project ID format
        for res in rule.get("sources", []) + rule.get("destinations", []):
            if res.startswith("projects/"):
                proj_id = res.split("/", 1)[-1]
                if not re.fullmatch(r"\d{10}", proj_id):
                    errors.append(
                        f"Resource '{res}' must be of form projects/<10-digit ID>."
                    )
        # IP/TLM validation
        tlm_id = rule.get("tlm_id", "").strip()
        for src in rule.get("sources", []):
            # Only treat entries with dots as IPs; ignore project and resource references
            if "." in src and not src.startswith("projects/"):
                if not ip_cidr_re.fullmatch(src):
                    errors.append(f"IP '{src}' is not in CIDR format (x.x.x.x/xx).")
                if direction == "INGRESS" and not tlm_id:
                    errors.append(
                        "TLM-ID is required when specifying IP subnets in an INGRESS rule."
                    )
        # Service method validation
        svc_methods: Dict[str, List[str]] = rule.get("service_methods", {})
        for svc, mlist in svc_methods.items():
            # Skip empty or wildcard lists ("*" means all methods)
            if not mlist or mlist == ["*"]:
                continue
            allowed = SUPPORTED_METHODS.get(svc, set())
            for m in mlist:
                if m not in allowed:
                    errors.append(f"Unsupported method '{m}' for service '{svc}'.")
        # Service permission validation
        svc_perms: Dict[str, List[str]] = rule.get("service_permissions", {})
        for svc, plist in svc_perms.items():
            if not plist or plist == ["*"]:
                continue
            allowed = SUPPORTED_PERMISSIONS.get(svc, set())
            for p in plist:
                if p not in allowed:
                    errors.append(f"Unsupported permission '{p}' for service '{svc}'.")
    return errors

def main() -> None:
    parser = argparse.ArgumentParser(description="Validate VPC SC request using handler parser")
    parser.add_argument("--issue-file", required=True, help="Path to issue_body.md")
    parser.add_argument("--router-file", required=True, help="Path to router.yml")
    args = parser.parse_args()

    with open(args.issue_file, encoding="utf-8") as f:
        issue_text = f.read()
    with open(args.router_file, encoding="utf-8") as f:
        router = yaml.safe_load(f) or {}

    parsed = parse_issue_body(issue_text)
    # Each rule inherits tlm_id for the IP/TLM check
    enriched_rules = []
    for rule in parsed.get("rules", []):
        rule_copy = dict(rule)
        rule_copy["tlm_id"] = parsed.get("tlm_id", "")
        enriched_rules.append(rule_copy)

    errors = validate_rules(enriched_rules, router)
    valid = "true" if not errors else "false"

    # Emit outputs for GitHub Actions
    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a") as out:
            out.write(f"valid={valid}\n")
            out.write(f"errors={json.dumps(errors)}\n")

    # Print summary
    if errors:
        print("Validation failed:")
        for err in errors:
            print(f"- {err}")
    else:
        print("Validation passed.")

if __name__ == "__main__":
    main()
