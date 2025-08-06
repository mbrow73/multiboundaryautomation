#!/usr/bin/env python3
import re
import sys
import ipaddress
import glob
import json
from typing import Dict, List

# Allowed public ranges for oversized CIDRs (/24 or larger)
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
    ipaddress.ip_network("199.36.153.4/30"),
]

HEALTH_CHECK_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
]
RESTRICTED_API_RANGES = [
    ipaddress.ip_network("199.36.153.4/30"),
]

# THIRD-PARTY CIDRs – replace with your real ranges
THIRD_PARTY_PEERING_RANGES = [
    ipaddress.ip_network("10.150.1.0/24"),
]

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def validate_reqid(reqid: str) -> bool:
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid or ""))

def validate_carid(carid: str) -> bool:
    return bool(re.fullmatch(r"\d{9}", carid or ""))

def validate_port(port: str) -> bool:
    if re.fullmatch(r"\d{1,5}", port or ""):
        n = int(port); return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port or ""):
        a, b = map(int, port.split('-')); return 1 <= a <= b <= 65535
    return False

def parse_existing_rules() -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            data = json.load(open(path))
        except Exception:
            continue
        for r in data.get("auto_firewall_rules", []):
            rules.append({
                "src": ",".join(r.get("src_ip_ranges", [])),
                "dst": ",".join(r.get("dest_ip_ranges", [])),
                "ports": ",".join(r.get("ports", [])),
                "proto": r.get("protocol"),
                "direction": r.get("direction"),
            })
    return rules

def rule_exact_match(rule: Dict[str, str], rulelist: List[Dict[str, str]]) -> bool:
    for r in rulelist:
        if rule["src"] == r["src"] and rule["dst"] == r["dst"] \
           and rule["ports"] == r["ports"] and rule["proto"] == r["proto"] \
           and rule["direction"] == r["direction"]:
            return True
    return False

def rule_is_redundant(rule: Dict[str, str], rulelist: List[Dict[str, str]]) -> bool:
    def subset(child: str, parent: str) -> bool:
        try: return ipaddress.ip_network(child, strict=False).subnet_of(ipaddress.ip_network(parent, strict=False))
        except Exception: return False
    for r in rulelist:
        if rule["direction"] != r["direction"] or rule["proto"] != r["proto"]: continue
        srcs_child  = [c.strip() for c in rule["src"].split(",")]
        srcs_parent = [p.strip() for p in r["src"].split(",")]
        dsts_child  = [c.strip() for c in rule["dst"].split(",")]
        dsts_parent = [p.strip() for p in r["dst"].split(",")]
        ports_child = set(int(p) for p in rule["ports"].split(","))
        ports_parent= set(int(p) for p in r["ports"].split(","))
        if all(any(subset(c,p) for p in srcs_parent) for c in srcs_child) and \
           all(any(subset(c,p) for p in dsts_parent) for c in dsts_child) and \
           ports_child.issubset(ports_parent):
            return True
    return False

def parse_rule_block(block: str) -> Dict[str, str]:
    def extract(label: str) -> str:
        m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
        return m.group(1).strip() if m else ""
    return {
        "src": extract("New Source IP") or extract("New Source"),
        "dst": extract("New Destination IP") or extract("New Destination"),
        "ports": extract("New Port"),
        "proto": extract("New Protocol"),
        "direction": extract("New Direction"),  # optional
        "just": extract("New Business Justification"),
    }

def main() -> None:
    issue = open(sys.argv[1]).read()
    errors: List[str] = []

    # REQID and CARID
    m = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m.group(1).strip() if m else None
    if not validate_reqid(reqid): errors.append(f"❌ REQID must be 'REQ' followed by 7–8 digits. Found: '{reqid}'")
    m = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m.group(1).strip() if m else None
    if not validate_carid(carid): errors.append(f"❌ CARID must be exactly 9 digits. Found: '{carid}'")

    # TLM ID (robust extraction; matches "Third Party ID:" even with parentheses)
    m = re.search(r"Third Party ID\b.*?:\s*(.*)", issue, re.IGNORECASE)
    tlm_id = m.group(1).strip() if m else ""

    # Each Rule
    blocks = re.split(r"#### Rule", issue, flags=re.IGNORECASE)[1:]
    seen: set = set()
    for idx, blk in enumerate(blocks, 1):
        r = parse_rule_block(blk)
        src, dst, ports, proto, direction, just = r["src"], r["dst"], r["ports"], r["proto"], r["direction"], r["just"]

        # Required fields
        if not all([src, dst, ports, proto, just]):
            errors.append(f"❌ Rule {idx}: All fields (source, destination, port, protocol, justification) must be present.")
            continue
        if proto != proto.lower() or proto not in {"tcp","udp","icmp","sctp"}:
            errors.append(f"❌ Rule {idx}: Protocol must be one of tcp, udp, icmp, sctp (lowercase).")

        uses_third_party = False
        for label, val in [("source", src), ("destination", dst)]:
            for ip_str in val.split(","):
                ip_str = ip_str.strip()
                if not ip_str: continue
                if "/" not in ip_str:
                    errors.append(f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' must include a CIDR mask (e.g. /32).")
                    continue
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                except Exception:
                    errors.append(f"❌ Rule {idx}: Invalid {label} IP/CIDR '{ip_str}'.")
                    continue
                if net == ipaddress.ip_network("0.0.0.0/0"):
                    errors.append(f"❌ Rule {idx}: {label.capitalize()} may not be 0.0.0.0/0.")
                    continue
                # Oversized prefix: must be within allowed GCP ranges
                if net.prefixlen < 24:
                    if not any(net.subnet_of(rng) for rng in ALLOWED_PUBLIC_RANGES):
                        errors.append(f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range.")
                    # still detect third‑party on oversized net
                    if any(net.subnet_of(rng) for rng in THIRD_PARTY_PEERING_RANGES):
                        uses_third_party = True
                    continue
                # Public addresses must be within allowed ranges
                if not any(net.subnet_of(rng) for rng in PRIVATE_RANGES):
                    if not any(net.subnet_of(rng) for rng in ALLOWED_PUBLIC_RANGES):
                        errors.append(f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' is public and not in allowed GCP ranges.")
                    # detect third party too
                    if any(net.subnet_of(rng) for rng in THIRD_PARTY_PEERING_RANGES):
                        uses_third_party = True
                    continue
                # Private net – check third‑party
                if any(net.subnet_of(rng) for rng in THIRD_PARTY_PEERING_RANGES):
                    uses_third_party = True

        # Enforce TLM ID when third‑party range used
        if uses_third_party and not tlm_id:
            errors.append(f"❌ Rule {idx}: A Third Party ID (TLM ID) must be specified when using the third‑party‑peering boundary.")

        # Port and duplicate checks
        for p in ports.split(","):
            p = p.strip()
            if not validate_port(p):
                errors.append(f"❌ Rule {idx}: Invalid port or range: '{p}'.")
        key = (src, dst, ports, proto, direction)
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule in request.")
        seen.add(key)

    # Existing rules duplicate/redundancy check
    existing = parse_existing_rules()
    for idx, blk in enumerate(blocks, 1):
        r = parse_rule_block(blk)
        if not all([r["src"], r["dst"], r["ports"], r["proto"]]): continue
        if rule_exact_match(r, existing):
            errors.append(f"❌ Rule {idx}: Exact duplicate of existing rule.")
        elif rule_is_redundant(r, existing):
            errors.append(f"❌ Rule {idx}: Redundant—already covered by an existing broader rule.")

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors: print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
