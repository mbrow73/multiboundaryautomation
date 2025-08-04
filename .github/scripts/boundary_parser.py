#!/usr/bin/env python3
"""
Parse a firewall request issue body and emit one or more network firewall
policy rules aware of logical network boundaries.  The parser looks up
boundaries based on a CIDR→boundary map defined in `boundary_map.json` and
expands certain flows into multiple rules when required:

  * Cross‑boundary flows emit a single rule tagged with src_boundary and
    dest_boundary; the action will default to apply_security_profile_group.
  * Flows destined to the on‑prem boundary emit two EGRESS rules: one in the
    source boundary and a second in the intranet boundary.
  * Flows originating from on‑prem emit one or two INGRESS rules depending on
    whether the destination boundary is the intranet (one rule) or something
    else (two rules: one targeting the intranet, one targeting the actual
    destination boundary).
  * Intra‑on‑prem flows are treated as intra‑intranet flows (on‑prem has no
    policy) and therefore generate a single rule in the intranet boundary.

The script writes the generated rules into `firewall-requests/<REQID>.auto.tfvars.json`.
It also writes a human‑readable summary of the rule flows to
`rules_summary.txt` which can be used in pull request descriptions.

Exit status is non‑zero and validation errors are printed between
VALIDATION_ERRORS_START and VALIDATION_ERRORS_END markers if any validation
errors are encountered.
"""

import sys
import os
import re
import json
import glob
import ipaddress

from typing import Dict, List, Tuple


def load_boundary_map(path: str) -> Dict[str, List[str]]:
    with open(path) as f:
        return json.load(f)


def ip_to_boundary(ip: str, boundary_map: Dict[str, List[str]]) -> str:
    """Return the boundary name in which the given IP/CIDR falls.
    Defaults to "inet" when no explicit match is found."""
    try:
        net = ipaddress.ip_network(ip, strict=False)
    except Exception:
        return "inet"
    for boundary, cidrs in boundary_map.items():
        for cidr in cidrs:
            try:
                if net.subnet_of(ipaddress.ip_network(cidr, strict=False)):
                    return boundary
            except Exception:
                continue
    return "inet"


def parse_blocks(issue_body: str) -> List[str]:
    # Split the body into rule blocks on headings like "#### Rule N"
    blocks = re.split(r"(?:^|\n)#{2,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]


def extract_field(block: str, label: str) -> str:
    m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def validate_reqid(reqid: str) -> bool:
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid))


def validate_carid(carid: str) -> bool:
    return bool(re.fullmatch(r"\d{9}", carid))


def validate_ip(ip: str) -> bool:
    if "/" not in ip:
        return False
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except Exception:
        return False


def validate_port(port: str) -> bool:
    if re.fullmatch(r"\d{1,5}", port):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port):
        a, b = map(int, port.split('-'))
        return 1 <= a <= b <= 65535
    return False


def get_max_priority() -> int:
    max_p = 999
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            data = json.load(open(path))
            for r in data.get("auto_firewall_rules", []):
                p = r.get("priority")
                if isinstance(p, int) and p > max_p:
                    max_p = p
        except Exception:
            continue
    return max_p


def main():
    # Read the issue body from stdin or argument
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()

    errors: List[str] = []

    # Load boundary map
    boundary_map_path = os.environ.get("BOUNDARY_MAP", "boundary_map.json")
    try:
        boundary_map = load_boundary_map(boundary_map_path)
    except Exception as e:
        print(f"VALIDATION_ERRORS_START\nFailed to load boundary map: {e}\nVALIDATION_ERRORS_END")
        sys.exit(1)

    # Extract REQID and CARID
    m_reqid = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    reqid = m_reqid.group(1).strip() if m_reqid else None
    if not reqid or not validate_reqid(reqid):
        errors.append(f"REQID must be 'REQ' followed by 7–8 digits. Found: '{reqid}'.")

    m_carid = re.search(r"CARID.*?:\s*(\d+)", issue_body, re.IGNORECASE)
    carid = m_carid.group(1).strip() if m_carid else None
    if not carid or not validate_carid(carid):
        errors.append(f"CARID must be exactly 9 digits. Found: '{carid}'.")

    # Parse the rule blocks
    blocks = parse_blocks(issue_body)
    if not blocks:
        errors.append("No rule blocks found in request.")

    # To detect duplicates within the request
    seen_rules = set()
    parsed_rules: List[Tuple[str, str, List[str], List[str], List[str], str, str]] = []
    # Each entry: (src, dst, ports_list, proto, direction, justification)
    for idx, block in enumerate(blocks, 1):
        src = extract_field(block, "New Source IP")
        dst = extract_field(block, "New Destination IP")
        ports = extract_field(block, "New Port")
        proto = extract_field(block, "New Protocol")
        direction = extract_field(block, "New Direction")
        just = extract_field(block, "New Business Justification")

        # Basic presence validation
        if not all([src, dst, ports, proto, direction, just]):
            errors.append(f"Rule {idx}: All fields must be present.")
            continue

        # Protocol validation
        if proto != proto.lower() or proto not in {"tcp", "udp", "icmp", "sctp"}:
            errors.append(f"Rule {idx}: Protocol must be one of tcp, udp, icmp, sctp (lowercase). Found: '{proto}'.")

        # Direction validation
        if direction.upper() not in {"INGRESS", "EGRESS"}:
            errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS. Found: '{direction}'.")

        # IP validations
        for label, val in [("source", src), ("destination", dst)]:
            for ip in [p.strip() for p in val.split(",") if p.strip()]:
                if not validate_ip(ip):
                    errors.append(f"Rule {idx}: Invalid {label} IP/CIDR '{ip}'.")

        # Port validations
        for p in [p.strip() for p in ports.split(",") if p.strip()]:
            if not validate_port(p):
                errors.append(f"Rule {idx}: Invalid port or range: '{p}'.")

        # Duplicate within request
        key = (src, dst, ports, proto, direction)
        if key in seen_rules:
            errors.append(f"Rule {idx}: Duplicate rule in request.")
        seen_rules.add(key)

        parsed_rules.append((src, dst, [p.strip() for p in ports.split(",") if p.strip()], proto.lower(), direction.upper(), just))

    # If any validation error occurred, print them and exit
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    # Determine the maximum existing priority for auto‑generated rules
    max_priority = get_max_priority()

    all_emitted_rules = []  # List of rule dicts to write into JSON
    summary_lines = []  # Lines for the PR summary
    rule_index = 0

    for src, dst, ports_list, proto, direction, just in parsed_rules:
        # Determine boundaries for the first IP in each list
        src_ips = [ip.strip() for ip in src.split(",") if ip.strip()]
        dst_ips = [ip.strip() for ip in dst.split(",") if ip.strip()]
        src_boundary = ip_to_boundary(src_ips[0], boundary_map)
        dest_boundary = ip_to_boundary(dst_ips[0], boundary_map)

        # Determine how to expand the rule into one or more boundary‑specific rules
        cases: List[Tuple[str, str]] = []  # list of (src_b, dest_b) pairs
        if src_boundary != "on_prem" and dest_boundary != "on_prem":
            # Normal boundary→boundary
            cases.append((src_boundary, dest_boundary))
        elif dest_boundary == "on_prem" and src_boundary != "on_prem":
            # Flows to on_prem: one in source boundary, one in intranet
            cases.append((src_boundary, dest_boundary))
            cases.append(("intranet", dest_boundary))
        elif src_boundary == "on_prem" and dest_boundary == "intranet":
            # From on_prem to intranet: single ingress in intranet
            cases.append((src_boundary, dest_boundary))
        elif src_boundary == "on_prem" and dest_boundary != "intranet" and dest_boundary != "on_prem":
            # From on_prem to a non‑intranet boundary: ingress in intranet and ingress in dest_boundary
            cases.append((src_boundary, "intranet"))
            cases.append((src_boundary, dest_boundary))
        else:
            # Intra on‑prem (src and dest both on_prem).  Treat as intranet→intranet.
            cases.append(("intranet", "intranet"))

        for case_src_boundary, case_dest_boundary in cases:
            rule_index += 1
            name = f"AUTO-{reqid}-{carid}-{proto.upper()}-{','.join(ports_list)}-{rule_index}"
            description = f"{name} | {just}"
            action = "apply_security_profile_group" if case_src_boundary != case_dest_boundary else "allow"
            rule = {
                "name": name,
                "description": description,
                "direction": direction,
                "src_ip_ranges": src_ips,
                "dest_ip_ranges": dst_ips,
                "ports": ports_list,
                "protocol": proto,
                "priority": max_priority + rule_index,
                "action": action,
                "enable_logging": True,
                "src_boundary": case_src_boundary,
                "dest_boundary": case_dest_boundary,
            }
            all_emitted_rules.append(rule)

            # Build a human‑readable summary line
            summary_lines.append(
                f"- **Rule {rule_index}:** {src} → {dst} on {proto}/{','.join(ports_list)} _(Direction: {direction})_\n    Justification: {just}"
            )

    # Write the auto.tfvars.json file
    os.makedirs("firewall-requests", exist_ok=True)
    out_path = os.path.join("firewall-requests", f"{reqid}.auto.tfvars.json")
    with open(out_path, "w") as f:
        json.dump({"auto_firewall_rules": all_emitted_rules}, f, indent=2)

    # Write the summary file
    with open("rules_summary.txt", "w") as f:
        for line in summary_lines:
            f.write(line + "\n")


if __name__ == "__main__":
    main()