#!/usr/bin/env python3
"""
boundary_mapper.py
===================

This script assigns `src_vpc` and `dest_vpc` values to each rule in a
`*.auto.tfvars.json` file based on a CIDR→boundary map and also infers
the firewall rule’s `direction` for certain well‑known public ranges.

It takes three arguments:

    --map-file       Path to a JSON file mapping boundary names to lists of
                     CIDR strings.  Lines beginning with `//` and block
                     comments are ignored.
    --json-file      The `.auto.tfvars.json` file to update in place.
    --default-boundary  (optional) Boundary to use for IPs not found in
                     the map; if omitted, unmapped IPs cause an error.

For each rule it determines which boundary each source and destination
IP belongs to (picking the most specific matching CIDR).  All source
ranges must resolve to the same boundary; the same applies to all
destination ranges.  It then writes those boundaries into the rule.

If the rule’s `direction` field is empty (or missing), the script also
performs a simple classification:

* If **all** source ranges fall within the health‑check CIDRs
  (`35.191.0.0/16` or `130.211.0.0/22`), the rule is marked as
  `INGRESS`.  This means only inbound health‑check traffic is allowed.

* Else if **all** destination ranges fall within the restricted API
  CIDRs (`199.36.153.4/30`), the rule is marked as `EGRESS`.  This
  allows outbound calls to `restricted.googleapis.com` without a
  matching ingress.

Otherwise the `direction` field is left unchanged.  After updating
boundaries and direction the file is rewritten atomically.
"""

import argparse
import json
import ipaddress
import sys
import os
from typing import Dict, List, Tuple, Optional

# Health‑check ranges.  When all source IPs of a rule fall within
# these CIDRs, the rule is treated as inbound only (INGRESS).
HEALTH_CHECK_RANGES: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
]

# Restricted API ranges.  When all destination IPs of a rule fall
# within these CIDRs, the rule is treated as outbound only (EGRESS).
RESTRICTED_API_RANGES: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("199.36.153.4/30"),
]

def load_boundary_map(path: str) -> Dict[str, List[str]]:
    """Load boundary_map.json, stripping out // comments and /* */ blocks."""
    with open(path) as f:
        lines = f.readlines()
    json_lines: List[str] = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("/*"):
            in_block = True
            continue
        if in_block:
            if stripped.endswith("*/"):
                in_block = False
            continue
        if '//' in line:
            idx = line.find('//')
            prefix = line[:idx]
            # Remove line comment outside of strings
            if prefix.count('"') % 2 == 0:
                line = prefix + "\n"
        json_lines.append(line)
    return json.loads("".join(json_lines))

def build_network_index(boundary_map: Dict[str, List[str]]) -> List[Tuple[ipaddress.IPv4Network, str]]:
    """Return a list of (network, boundary) sorted by prefix length (descending)."""
    nets: List[Tuple[ipaddress.IPv4Network, str]] = []
    for boundary, cidrs in boundary_map.items():
        for cidr in cidrs:
            nets.append((ipaddress.ip_network(cidr, strict=False), boundary))
    nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return nets

def determine_boundary(ip_list: List[str], index: List[Tuple[ipaddress.IPv4Network, str]], default_boundary: Optional[str]) -> str:
    """Map each CIDR in ip_list to a boundary.  All must map to the same.

    If default_boundary is provided and a CIDR maps to none, the default is used.
    """
    boundaries: set = set()
    for ip_str in ip_list:
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        net = ipaddress.ip_network(ip_str, strict=False)
        found = None
        for candidate, boundary in index:
            if net.subnet_of(candidate):
                found = boundary
                break
        if found is None:
            if default_boundary is not None:
                found = default_boundary
            else:
                raise ValueError(f"No boundary mapping found for {ip_str}")
        boundaries.add(found)
    if len(boundaries) != 1:
        raise ValueError(f"Ambiguous boundaries {boundaries} for IP ranges {ip_list}")
    return next(iter(boundaries))

def ranges_in_list(ranges: List[str], allowed: List[ipaddress.IPv4Network]) -> bool:
    """Return True if every CIDR in `ranges` is a subnet of some CIDR in `allowed`."""
    for ip_str in ranges:
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        net = ipaddress.ip_network(ip_str, strict=False)
        if not any(net.subnet_of(a) for a in allowed):
            return False
    return True

def update_tfvars_file(json_path: str, boundary_index: List[Tuple[ipaddress.IPv4Network, str]], default_boundary: Optional[str] = None) -> None:
    """Update src_vpc, dest_vpc and direction fields in a .auto.tfvars.json file."""
    data = json.load(open(json_path))
    if "auto_firewall_rules" not in data or not isinstance(data["auto_firewall_rules"], list):
        raise ValueError(f"Unexpected format: {json_path} does not contain 'auto_firewall_rules'")
    for rule in data["auto_firewall_rules"]:
        src_ranges = rule.get("src_ip_ranges", [])
        dst_ranges = rule.get("dest_ip_ranges", [])
        # Determine boundaries
        src_boundary = determine_boundary(src_ranges, boundary_index, default_boundary)
        dst_boundary = determine_boundary(dst_ranges, boundary_index, default_boundary)
        rule["src_vpc"] = src_boundary
        rule["dest_vpc"] = dst_boundary
        # Infer direction only if it's empty/missing
        direction = (rule.get("direction") or "").strip()
        if not direction:
            # Health‑check: all source ranges within health check → INGRESS
            if src_ranges and ranges_in_list(src_ranges, HEALTH_CHECK_RANGES):
                rule["direction"] = "INGRESS"
            # Restricted API: all dest ranges within restricted → EGRESS
            elif dst_ranges and ranges_in_list(dst_ranges, RESTRICTED_API_RANGES):
                rule["direction"] = "EGRESS"
    # Write back atomically
    tmp_path = json_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp_path, json_path)

def main() -> None:
    parser = argparse.ArgumentParser(description="Assign src_vpc/dest_vpc and infer direction based on CIDRs.")
    parser.add_argument("--map-file", required=True, help="Boundary map JSON file (comments allowed)")
    parser.add_argument("--json-file", required=True, help="TFVars JSON file to update")
    parser.add_argument("--default-boundary", default=None, help="Fallback boundary for unmapped CIDRs")
    args = parser.parse_args()
    try:
        boundary_map = load_boundary_map(args.map_file)
    except Exception as exc:
        print(f"Failed to load boundary map {args.map_file}: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        boundary_index = build_network_index(boundary_map)
    except Exception as exc:
        print(f"Invalid boundary map: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        update_tfvars_file(args.json_file, boundary_index, args.default_boundary)
    except Exception as exc:
        print(f"Error updating {args.json_file}: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Updated {args.json_file} with boundaries and directions.")

if __name__ == "__main__":
    main()