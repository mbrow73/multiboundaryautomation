#!/usr/bin/env python3
"""
payload_to_markdown.py

Reads a JSON request from the environment variable CLIENT_PAYLOAD and converts it
into the Markdown format expected by vpc_sc_request_handler.py. This allows
repository_dispatch events carrying a JSON payload to be processed without
modifying the existing parsing logic.

Usage (within a GitHub Actions step):
  env:
    CLIENT_PAYLOAD: ${{ toJSON(github.event.client_payload) }}
  run: python3 payload_to_markdown.py > issue_body.md

The script writes the formatted Markdown to standard output.
"""

import json
import os
import sys

def main() -> None:
    payload = os.environ.get("CLIENT_PAYLOAD", "{}")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        # If payload isn't valid JSON, just print nothing.
        return
    # If the payload contains a raw issue body, emit it directly.
    issue_body = data.get("issue_body")
    if isinstance(issue_body, str) and issue_body.strip():
        sys.stdout.write(issue_body)
        return
    lines: list[str] = []
    # Request ID
    reqid = data.get("reqid") or ""
    if reqid:
        lines.append(f"Request ID: {reqid}")
    # Perimeter names
    perimeters = data.get("perimeters") or []
    if perimeters:
        lines.append("")
        lines.append("Perimeter Name(s)")
        for p in perimeters:
            lines.append(str(p))
    # Direction
    direction = (data.get("direction") or "").upper()
    if direction:
        lines.append("")
        lines.append("Direction")
        lines.append(direction)
    # Determine which policies list to use based on direction
    policies = []
    if direction == "EGRESS":
        policies = data.get("egress_policies") or []
    elif direction == "INGRESS":
        policies = data.get("ingress_policies") or []
    # Process each policy
    for policy in policies:
        services: list[str] = []
        methods: list[str] = []
        perms: list[str] = []
        # Operations are under 'to' for egress, 'from' for ingress
        ops = {}
        if direction == "EGRESS":
            ops = policy.get("to", {}).get("operations", {})
        else:
            ops = policy.get("from", {}).get("operations", {})
        for svc, op in ops.items():
            services.append(svc)
            if op.get("methods"):
                methods.append(f"{svc}: " + ", ".join(op["methods"]))
            if op.get("permissions"):
                perms.append(f"{svc}: " + ", ".join(op["permissions"]))
        if services:
            lines.append("")
            lines.append("Services")
            lines.append(", ".join(services))
        if methods:
            lines.append("")
            lines.append("Methods")
            lines.extend(methods)
        if perms:
            lines.append("")
            lines.append("Permissions")
            lines.extend(perms)
        # Identities: from for egress, to for ingress
        identities: list[str] = []
        who = policy.get("from", {}) if direction == "EGRESS" else policy.get("to", {})
        ids = who.get("identities") or []
        if isinstance(ids, list):
            identities.extend(str(i) for i in ids)
        if identities:
            lines.append("")
            lines.append("Identities")
            lines.append(", ".join(identities))
        # Resources/destinations
        if direction == "EGRESS":
            resources = policy.get("to", {}).get("resources", [])
            label = "Destination / To"
        else:
            resources = policy.get("from", {}).get("resources", [])
            label = "Source / From"
        if resources:
            lines.append("")
            lines.append(label)
            for r in resources:
                lines.append(str(r))
    # Output the assembled lines
    sys.stdout.write("\n".join(lines))

if __name__ == "__main__":
    main()