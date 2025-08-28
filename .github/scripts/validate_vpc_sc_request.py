#!/usr/bin/env python3
"""
validate_vpc_sc_request.py

This validator imports the same parse_issue_body() function used by
vpc_sc_request_handler.py, so it relies on exactly the same parsing logic.
It checks:
  * Each perimeter referenced exists in router.yml
  * Project IDs use 10-digit numeric IDs in 'projects/<id>' format
  * IP subnets are in CIDR notation x.x.x.x/xx and, for INGRESS rules,
    require a TLM-ID
Outputs:
  - valid: 'true' or 'false'
  - errors: JSON array of validation errors
"""

import argparse
import json
import os
import re
import sys
import yaml  # type: ignore

# Import the parser from your handler
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from vpc_sc_request_handler import parse_issue_body  # type: ignore

def validate_rules(rules, router) -> list[str]:
    errors: list[str] = []
    router_perims = set(router.get("perimeters", {}).keys())
    ip_cidr_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

    for rule in rules:
        reqid = rule.get("reqid", "REQ")
        direction = rule.get("direction", "").upper()
        # Perimeters
        for perim in rule.get("perimeters", []):
            if perim not in router_perims:
                errors.append(
                    f"Perimeter '{perim}' does not exist in router.yml."
                )
        # Project ID length
        for res in rule.get("sources", []) + rule.get("destinations", []):
            if res.startswith("projects/"):
                proj_id = res.split("/", 1)[-1]
                if not re.fullmatch(r"\d{10}", proj_id):
                    errors.append(
                        f"Resource '{res}' must be of form projects/<10-digit ID>."
                    )
        # IP/TLM check
        tlm_id = rule.get("tlm_id", "")
        for src in rule.get("sources", []):
            if "." in src and not src.startswith("projects/"):
                if not ip_cidr_re.fullmatch(src):
                    errors.append(f"IP '{src}' is not in CIDR format (x.x.x.x/xx).")
                if direction == "INGRESS" and not tlm_id:
                    errors.append(
                        "TLM-ID is required when specifying IP subnets in an INGRESS rule."
                    )
    return errors

def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a VPC SC request using the handler's parser")
    parser.add_argument("--issue-file", required=True, help="Path to issue_body.md")
    parser.add_argument("--router-file", required=True, help="Path to router.yml")
    args = parser.parse_args()

    # Read issue text
    with open(args.issue_file, encoding="utf-8") as f:
        issue_text = f.read()
    # Read router definition
    with open(args.router_file, encoding="utf-8") as f:
        router = yaml.safe_load(f) or {}

    # Use the handler's parser to get rules
    parsed = parse_issue_body(issue_text)
    rules = []
    # Enrich rules with tlm_id for IP/TLM check
    for rule in parsed.get("rules", []):
        rule["tlm_id"] = parsed.get("tlm_id", "")
        rules.append(rule)

    errors = validate_rules(rules, router)
    valid = "true" if not errors else "false"

    # Write outputs for GitHub Actions
    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a") as out:
            out.write(f"valid={valid}\n")
            out.write(f"errors={json.dumps(errors)}\n")

    # Show summary in logs
    if errors:
        print("Validation failed:")
        for err in errors:
            print(f"- {err}")
    else:
        print("Validation passed.")

if __name__ == "__main__":
    main()
