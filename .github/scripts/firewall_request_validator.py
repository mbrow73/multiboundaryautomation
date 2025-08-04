#!/usr/bin/env python3
import re
import sys
import ipaddress
import glob
import json
from collections import defaultdict

def validate_reqid(reqid):
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid))

def validate_carid(carid):
    return bool(re.fullmatch(r"\d{9}", carid))

def validate_ip(ip):
    # Fail if no CIDR mask present
    if "/" not in ip:
        return False
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except:
        return False

def validate_port(port):
    if re.fullmatch(r"\d{1,5}", port):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port):
        a, b = map(int, port.split('-'))
        return 1 <= a <= b <= 65535
    return False

def parse_rule_block(block):
    """Extract fields from a rule block in the issue body.

    The firewall request template now includes additional boundary fields (Source VPC/Destination VPC). To avoid
    accidentally capturing the VPC names as IP/CIDR values, we look for specific labels. If the newer labels
    are absent, we fall back to the older generic patterns for backward compatibility.
    """
    def extract(label):
        m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    # Prefer explicit IP/CIDR labels; fall back to generic "New Source"/"New Destination" for older issues
    src_ip = extract("New Source IP") or extract("New Source")
    dst_ip = extract("New Destination IP") or extract("New Destination")
    src_vpc = extract("New Source VPC")
    dst_vpc = extract("New Destination VPC")
    ports = extract("New Port")
    proto = extract("New Protocol")
    direction = extract("New Direction")
    just = extract("New Business Justification")

    return {
        "src": src_ip,
        "dst": dst_ip,
        "ports": ports,
        "proto": proto,
        "direction": direction,
        "just": just,
        "src_vpc": src_vpc,
        "dst_vpc": dst_vpc,
    }

def parse_existing_rules():
    """Load all existing auto firewall rules from JSON files into a list of summary dicts.

    Each dict contains IP/CIDR, ports, protocol, direction and (if present) boundary names.  Boundaries are
    optional in the original implementation; missing boundaries default to empty strings for comparison.
    """
    rules = []
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            data = json.load(open(path))
            for r in data.get("auto_firewall_rules", []):
                rules.append({
                    "src":       ",".join(r.get("src_ip_ranges", [])),
                    "dst":       ",".join(r.get("dest_ip_ranges", [])),
                    "ports":     ",".join(r.get("ports", [])),
                    "proto":     r.get("protocol"),
                    "direction": r.get("direction"),
                    "src_vpc":   r.get("src_vpc", ""),
                    "dst_vpc":   r.get("dest_vpc", ""),
                })
        except Exception:
            continue
    return rules

def rule_exact_match(rule, rulelist):
    """Check if a rule exactly matches an existing rule.

    Two rules are considered the same only if their IP ranges, ports, protocol, direction and boundaries all match.
    Boundaries are optional (empty string) and only compared when both rules specify them.
    """
    for r in rulelist:
        if (
            rule["src"] == r["src"]
            and rule["dst"] == r["dst"]
            and rule["ports"] == r["ports"]
            and rule["proto"] == r["proto"]
            and rule["direction"] == r["direction"]
        ):
            # if either rule has boundary names, require exact match as well
            if (rule.get("src_vpc") or r.get("src_vpc")):
                if rule.get("src_vpc", "") != r.get("src_vpc", ""):
                    continue
            if (rule.get("dst_vpc") or r.get("dst_vpc")):
                if rule.get("dst_vpc", "") != r.get("dst_vpc", ""):
                    continue
            return True
    return False

def rule_is_redundant(rule, rulelist):
    def subset(child, parent):
        try:
            return ipaddress.ip_network(child, strict=False).subnet_of(
                   ipaddress.ip_network(parent, strict=False))
        except:
            return False

    for r in rulelist:
        # Direction and protocol must match
        if rule["direction"] != r["direction"]:
            continue
        if rule["proto"] != r["proto"]:
            continue
        # If either rule specifies boundaries, only compare redundancy within the same boundaries
        if rule.get("src_vpc") or r.get("src_vpc"):
            if rule.get("src_vpc", "") != r.get("src_vpc", ""):
                continue
        if rule.get("dst_vpc") or r.get("dst_vpc"):
            if rule.get("dst_vpc", "") != r.get("dst_vpc", ""):
                continue

        srcs_child  = [c.strip() for c in rule["src"].split(",")]
        srcs_parent = [p.strip() for p in r["src"].split(",")]
        dsts_child  = [c.strip() for c in rule["dst"].split(",")]
        dsts_parent = [p.strip() for p in r["dst"].split(",")]
        ports_child = set(int(p) for p in rule["ports"].split(","))
        ports_parent = set(int(p) for p in r["ports"].split(","))

        if (
            all(any(subset(c, p) for p in srcs_parent) for c in srcs_child)
            and all(any(subset(c, p) for p in dsts_parent) for c in dsts_child)
            and ports_child.issubset(ports_parent)
        ):
            return True
    return False

def print_errors(errs):
    print("VALIDATION_ERRORS_START")
    for e in errs:
        print(e)
    print("VALIDATION_ERRORS_END")
    sys.exit(1)

def main():
    issue = open(sys.argv[1]).read()
    errors = []

    # REQID
    m = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m.group(1).strip() if m else None
    if not reqid or not validate_reqid(reqid):
        errors.append(f"❌ REQID must be 'REQ' followed by 7–8 digits. Found: '{reqid}'")

    # CARID
    m = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m.group(1).strip() if m else None
    if not carid or not validate_carid(carid):
        errors.append(f"❌ CARID must be exactly 9 digits. Found: '{carid}'")

    # Rule blocks
    blocks = re.split(r"#### Rule", issue, flags=re.IGNORECASE)[1:]
    seen = set()
    for idx, blk in enumerate(blocks, 1):
        r = parse_rule_block(blk)
        src, dst, ports, proto, direction, just = (
            r["src"], r["dst"], r["ports"], r["proto"], r["direction"], r["just"]
        )

        # all fields present?
        if not all([src, dst, ports, proto, direction, just]):
            errors.append(f"❌ Rule {idx}: All fields must be present.")
            continue

        # Protocol
        if proto != proto.lower() or proto not in {"tcp","udp","icmp","sctp"}:
            errors.append(f"❌ Rule {idx}: Protocol must be one of tcp, udp, icmp, sctp (lowercase).")

        # IP/CIDR checks (require slash mask)
        for label, val in [("source", src), ("destination", dst)]:
            for ip in val.split(","):
                ip = ip.strip()
                if "/" not in ip:
                    errors.append(f"❌ Rule {idx}: {label.capitalize()} '{ip}' must include a CIDR mask (e.g. /32).")
                    continue
                try:
                    net = ipaddress.ip_network(ip, strict=False)
                except:
                    errors.append(f"❌ Rule {idx}: Invalid {label} IP/CIDR '{ip}'.")
                    continue

        # Port checks
        for p in ports.split(","):
            p = p.strip()
            if not validate_port(p):
                errors.append(f"❌ Rule {idx}: Invalid port or range: '{p}'.")

        # Duplicate within request
        key = (src, dst, ports, proto, direction)
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule in request.")
        seen.add(key)

    # Global duplicates/redundancy
    existing = parse_existing_rules()
    for idx, blk in enumerate(blocks, 1):
        r = parse_rule_block(blk)
        if not all([r["src"], r["dst"], r["ports"], r["proto"], r["direction"]]):
            continue
        if rule_exact_match(r, existing):
            errors.append(f"❌ Rule {idx}: Exact duplicate of existing rule.")
        elif rule_is_redundant(r, existing):
            errors.append(f"❌ Rule {idx}: Redundant—already covered by an existing broader rule.")

    if errors:
        print_errors(errors)

if __name__ == "__main__":
    main()
