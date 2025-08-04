# .github/scripts/boundary_mapper.py
#!/usr/bin/env python3
"""
Assign src_vpc, dest_vpc, and infer direction for each rule,
then tag actions for cross-boundary inspection.
"""
import argparse
import json
import ipaddress
import sys
import os
from typing import Dict, List, Tuple, Optional

def load_boundary_map(path: str) -> Dict[str, List[str]]:
    with open(path) as f:
        lines = f.readlines()
    # strip comments
    json_lines = []
    in_block = False
    for line in lines:
        s = line.strip()
        if s.startswith("/*"):
            in_block = True
            continue
        if in_block:
            if s.endswith("*/"):
                in_block = False
            continue
        if '//' in line:
            idx = line.find('//')
            prefix = line[:idx]
            if prefix.count('"') % 2 == 0:
                line = prefix + "\n"
        json_lines.append(line)
    return json.loads("".join(json_lines))

def build_network_index(bmap: Dict[str, List[str]]) -> List[Tuple[ipaddress.IPv4Network, str]]:
    nets = []
    for b, cidrs in bmap.items():
        for cidr in cidrs:
            nets.append((ipaddress.ip_network(cidr, strict=False), b))
    nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return nets

def find_boundary_for_network(net: ipaddress.IPv4Network, index):
    for cand, b in index:
        if net.subnet_of(cand):
            return b
    return None

def determine_boundary(ip_list, index, default=None):
    found = set()
    for ip in ip_list:
        if not ip.strip(): continue
        net = ipaddress.ip_network(ip.strip(), strict=False)
        b = find_boundary_for_network(net, index)
        if not b:
            if default:
                b = default
            else:
                raise ValueError(f"No boundary for {ip}")
        found.add(b)
    if len(found)>1:
        raise ValueError(f"Ambiguous boundaries {found}")
    if not found:
        raise ValueError("No IPs provided")
    return next(iter(found))

def update_tfvars_file(path, index, default=None):
    data = json.load(open(path))
    rules = data.get("auto_firewall_rules", [])
    for rule in rules:
        src = rule.get("src_ip_ranges", [])
        dst = rule.get("dest_ip_ranges", [])
        src_b = determine_boundary(src, index, default)
        dst_b = determine_boundary(dst, index, default)
        rule["src_vpc"]  = src_b
        rule["dest_vpc"] = dst_b
        # infer direction
        rule["direction"] = "EGRESS" if src_b != dst_b else "INGRESS"
        # cross-boundary inspection flags
        if src_b != dst_b:
            rule["action_egress"]  = "apply_security_profile_group"
            rule["action_ingress"] = "allow"
            if dst_b == "onprem" and src_b != "intranet":
                rule["special_onprem_routing"] = True
        else:
            rule["action_egress"]  = "allow"
            rule["action_ingress"] = "allow"
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--map-file", required=True)
    p.add_argument("--json-file", required=True)
    p.add_argument("--default-boundary", default=None)
    args = p.parse_args()
    try:
        bmap = load_boundary_map(args.map_file)
        idx  = build_network_index(bmap)
        update_tfvars_file(args.json_file, idx, args.default_boundary)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Updated {args.json_file}")

if __name__=="__main__":
    main()
