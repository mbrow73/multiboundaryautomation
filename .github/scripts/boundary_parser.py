#!/usr/bin/env python3
"""
boundary_parser.py

Parse firewall request issues and generate auto TFVars files for Terraform.

This script is intended to be run inside a GitHub Action. It consumes the
GitHub event JSON (pointed to by the first argument) and reads the issue
body to extract firewall rule requests. It uses `boundary_map.json` in the
repository root to determine which logical boundary each source and
destination IP belongs to. A default boundary of "inet" is applied when
an IP does not match any CIDR in the map.

For each rule in the request, the parser emits a single entry in the
``auto_firewall_rules`` list. More advanced logic (e.g. duplicating rules
for on-prem flows) can be added as needed. The resulting JSON is written
to ``firewall-requests/<REQID>.auto.tfvars.json`` relative to the
repository root.
"""

import ipaddress
import json
import os
import re
import sys
from pathlib import Path

from firewall_request_validator import normalise_key, parse_rules  # reuse helper functions

def load_event(event_path: str) -> dict:
    with open(event_path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_boundary_map(root_dir: Path) -> dict:
    map_path = root_dir / "boundary_map.json"
    with open(map_path, "r", encoding="utf-8") as f:
        return json.load(f)

def ip_to_boundary(ip_str: str, boundary_map: dict) -> str:
    """Return the boundary name for the given IP using the CIDR map."""
    ip_obj = ipaddress.ip_address(ip_str)
    for boundary, cidrs in boundary_map.items():
        for cidr in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return boundary
            except ValueError:
                continue
    return "inet"  # default boundary for public/internet addresses

def parse_reqid_and_carid(body: str) -> tuple[str, str]:
    """Extract REQID and CARID from the issue body."""
    reqid_match = re.search(r"REQID\):\s*(\S+)", body, re.IGNORECASE)
    carid_match = re.search(r"CARID\):\s*(\S+)", body, re.IGNORECASE)
    reqid = reqid_match.group(1) if reqid_match else "UNKNOWN"
    carid = carid_match.group(1) if carid_match else "UNKNOWN"
    return reqid, carid

def main(event_path: str) -> None:
    event = load_event(event_path)
    body = event.get("issue", {}).get("body", "")
    repo_root = Path(__file__).resolve().parent.parent.parent
    boundary_map = load_boundary_map(repo_root)
    reqid, carid = parse_reqid_and_carid(body)
    rules = parse_rules(body)
    auto_rules = []
    for rule in rules:
        # Normalise keys to simplify lookups
        canon = {normalise_key(k): v for k, v in rule.items()}
        srcs = [s.strip() for s in canon.get("new source ip", "").split(',') if s.strip()]
        dests = [d.strip() for d in canon.get("new destination ip", "").split(',') if d.strip()]
        if not srcs or not dests:
            continue
        # Determine boundaries using the first IP in each list
        src_boundary = ip_to_boundary(srcs[0], boundary_map)
        dest_boundary = ip_to_boundary(dests[0], boundary_map)
        direction = canon.get("new direction", "").upper() or "INGRESS"
        protocol = canon.get("new protocol", "tcp").lower()
        ports = canon.get("new port(s)", "").replace(" ", "")
        justification = canon.get("new business justification", "")
        # Determine action: apply security profile on cross-boundary egress flows
        action = "allow"
        if direction == "EGRESS" and src_boundary != dest_boundary:
            action = "apply_security_profile_group"
        auto_rules.append({
            "src_ip_ranges": srcs,
            "dest_ip_ranges": dests,
            "protocol": protocol,
            "ports": ports,
            "direction": direction,
            "justification": justification,
            "src_boundary": src_boundary,
            "dest_boundary": dest_boundary,
            "action": action,
        })
    if not auto_rules:
        print(f"No valid rules found in request {reqid}; nothing to do.")
        return
    # Ensure output directory exists
    out_dir = repo_root / "firewall-requests"
    out_dir.mkdir(exist_ok=True)
    output = {"auto_firewall_rules": auto_rules}
    out_path = out_dir / f"{reqid}.auto.tfvars.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"Generated {out_path} with {len(auto_rules)} rule(s).")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: boundary_parser.py <path_to_event_json>",
            file=sys.stderr,
        )
        sys.exit(2)
    main(sys.argv[1])