#!/usr/bin/env python3
"""
firewall_issue_builder.py

This unified helper script converts a JSON payload into a Markdown
issue body according to the requested operation: create new rules,
update existing rules, or remove rules.  It is intended to be used
from the GitHub Actions workflow that processes repository dispatch
events.  Pass `--mode` to select the type of request.

Supported modes:
    request  – build a new firewall request issue
    update   – build an update firewall request issue
    remove   – build a removal firewall request issue

Examples:
    python3 firewall_issue_builder.py --mode request --payload payload.json --output issue_body.md
    python3 firewall_issue_builder.py --mode update --payload payload.json --output issue_body.md
    python3 firewall_issue_builder.py --mode remove --payload payload.json --output issue_body.md

The payload formats correspond to those expected by the GitHub API
workflow:

* New request:
    {
      "reqid": "REQ1234567",
      "carid": "123456789",
      "tlmid": "",          # optional
      "rules": [
        {
          "src": "10.0.0.1/32,10.0.0.2/32",
          "dst": "10.1.0.0/24",
          "ports": "443,8443",
          "protocol": "tcp",
          "justification": "Example",
          "direction": "INGRESS"   # optional
        },
        ...
      ]
    }

* Update request:
    {
      "new_reqid": "REQ1234567",
      "tlmid": "",  # optional
      "rules": [
        {
          "current_name": "existing-rule-name",
          "new_src": "optional new source list",
          "new_dst": "optional new destination list",
          "new_ports": "optional new ports list",
          "new_protocol": "optional new protocol",
          "new_carid": "optional new CARID",
          "new_justification": "optional new justification"
        },
        ...
      ]
    }

* Removal request:
    {
      "reqid": "REQ1234567",
      "rules": ["rule1", "rule2", ...]
    }

If validation fails, the script prints error messages to stderr and
exits with status 1.  On success it writes the generated Markdown
body to the specified output file.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def validate_request_top(payload: dict) -> list[str]:
    """Validate the top-level fields for a new request."""
    errors: list[str] = []
    reqid = (payload.get("reqid") or "").strip()
    carid = (payload.get("carid") or "").strip()
    if not re.fullmatch(r"REQ\d{7,8}", reqid):
        errors.append("'reqid' must match REQ followed by 7 or 8 digits")
    if not re.fullmatch(r"\d{9}", carid):
        errors.append("'carid' must be exactly 9 digits")
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("'rules' must be a non‑empty list of rule definitions")
    return errors


def build_request_body(payload: dict) -> str:
    """Build the Markdown issue body for a new firewall request."""
    reqid = (payload.get("reqid") or "").strip()
    carid = (payload.get("carid") or "").strip()
    tlmid = (payload.get("tlmid") or "").strip()
    rules = payload.get("rules") or []
    lines: list[str] = []
    lines.extend([
        "---",
        'name: "Firewall Rule Request"',
        'about: "Request new or updated GCP firewall rules"',
        'labels: ["firewall-request"]',
        '---',
        "",
        f"### Request ID (REQID): {reqid}",
        f"### CARID: {carid}",
        f"### Third Party ID (TLM ID) (required for third-party VPC access): {tlmid}",
        "",
    ])
    for idx, rule in enumerate(rules, 1):
        src = (rule.get("src") or "").strip()
        dst = (rule.get("dst") or "").strip()
        ports = (rule.get("ports") or "").strip()
        proto = (rule.get("protocol") or "").strip().lower()
        just = (rule.get("justification") or "").strip()
        dire = (rule.get("direction") or "").strip()
        if not all([src, dst, ports, proto, just]):
            raise ValueError(
                f"Rule {idx} is missing required fields (src, dst, ports, protocol, justification)"
            )
        lines.append(f"#### Rule {idx}")
        lines.append(f"🔹 New Source IP(s) or CIDR(s): {src}  ")
        lines.append(f"🔹 New Destination IP(s) or CIDR(s): {dst}  ")
        lines.append(f"🔹 New Port(s): {ports}  ")
        lines.append(f"🔹 New Protocol: {proto}  ")
        if dire:
            lines.append(f"🔹 New Direction: {dire}  ")
        lines.append(f"🔹 New Business Justification: {just}")
        lines.append("")
    return "\n".join(lines)


def validate_update_top(payload: dict) -> list[str]:
    """Validate the top-level fields for an update request."""
    errors: list[str] = []
    reqid = (payload.get("new_reqid") or "").strip()
    if not re.fullmatch(r"REQ\d{7,8}", reqid):
        errors.append("'new_reqid' must match REQ followed by 7 or 8 digits")
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("'rules' must be a non‑empty list")
    return errors


def build_update_body(payload: dict) -> str:
    reqid = (payload.get("new_reqid") or "").strip()
    tlmid = (payload.get("tlmid") or "").strip()
    rules = payload.get("rules") or []
    lines: list[str] = []
    lines.extend([
        "---",
        'name: "Update Firewall Rule(s)"',
        'about: "Request updates to one or more existing GCP firewall rules"',
        'labels: ["firewall-update-request"]',
        '---',
        "",
        f"### New Request ID (REQID): {reqid}",
        f"### New Third Party ID (required for third‑party VPC access): {tlmid}",
        "",
    ])
    for idx, r in enumerate(rules, 1):
        cur = (r.get("current_name") or "").strip()
        if not cur:
            raise ValueError(f"Rule {idx} is missing 'current_name'")
        lines.append(f"#### Rule {idx}")
        lines.append(f"**Current Rule Name**: {cur}")
        if r.get("new_src"):
            lines.append(f"**New Source IP(s) or CIDR(s)**: {r['new_src']}")
        if r.get("new_dst"):
            lines.append(f"**New Destination IP(s) or CIDR(s)**: {r['new_dst']}")
        if r.get("new_ports"):
            lines.append(f"**New Port(s)**: {r['new_ports']}")
        if r.get("new_protocol"):
            lines.append(f"**New Protocol**: {r['new_protocol']}")
        if r.get("new_carid"):
            lines.append(f"**New CARID**: {r['new_carid']}")
        if r.get("new_justification"):
            lines.append(f"**New Business Justification**: {r['new_justification']}")
        lines.append("")
    return "\n".join(lines)


def validate_remove_top(payload: dict) -> list[str]:
    errors: list[str] = []
    reqid = (payload.get("reqid") or "").strip()
    if not re.fullmatch(r"REQ\d{7,8}", reqid):
        errors.append("'reqid' must match REQ followed by 7 or 8 digits")
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("'rules' must be a non‑empty list of rule names to remove")
    return errors


def build_remove_body(payload: dict) -> str:
    reqid = (payload.get("reqid") or "").strip()
    rules = payload.get("rules") or []
    lines: list[str] = []
    lines.extend([
        "---",
        'name: "Firewall Rule Removal Request"',
        'about: "Request removal of existing GCP firewall rules"',
        'labels: ["firewall-remove-request"]',
        '---',
        "",
        f"### Request ID (REQID) for this removal: {reqid}",
        "",
        "<!-- For each rule you want to remove, copy/paste the block below -->",
        "",
    ])
    for idx, rule_name in enumerate(rules, 1):
        rule_name = str(rule_name).strip()
        lines.append(f"#### Rule {idx}")
        lines.append(f"**Current Rule Name**: {rule_name}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a firewall issue body from JSON payload")
    parser.add_argument("--mode", choices=["request", "update", "remove"], required=True,
                        help="Operation type: request (new rules), update (modify existing), or remove")
    parser.add_argument("--payload", default="payload.json", help="Path to the JSON payload file")
    parser.add_argument("--output", default="issue_body.md", help="Path to write the generated issue body")
    args = parser.parse_args()
    # Load payload
    try:
        payload = json.load(open(args.payload, "r", encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read payload file {args.payload}: {exc}", file=sys.stderr)
        sys.exit(1)
    # Build based on mode
    if args.mode == "request":
        errs = validate_request_top(payload)
        if errs:
            for e in errs:
                print(e, file=sys.stderr)
            sys.exit(1)
        body = build_request_body(payload)
    elif args.mode == "update":
        errs = validate_update_top(payload)
        if errs:
            for e in errs:
                print(e, file=sys.stderr)
            sys.exit(1)
        try:
            body = build_update_body(payload)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:  # remove
        errs = validate_remove_top(payload)
        if errs:
            for e in errs:
                print(e, file=sys.stderr)
            sys.exit(1)
        body = build_remove_body(payload)
    # Write output
    Path(args.output).write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()