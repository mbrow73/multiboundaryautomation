#!/usr/bin/env python3
import re
import sys
import ipaddress
import glob
import json

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

# Replace this with your real third‑party peering CIDRs
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
        a,b = map(int, port.split('-')); return 1 <= a <= b <= 65535
    return False

def main():
    issue = open(sys.argv[1]).read()
    errors = []

    # Extract REQID and CARID
    m = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m.group(1).strip() if m else None
    if not validate_reqid(reqid):
        errors.append(f"❌ REQID must be 'REQ' followed by 7–8 digits. Found: '{reqid}'")
    m = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m.group(1).strip() if m else None
    if not validate_carid(carid):
        errors.append(f"❌ CARID must be exactly 9 digits. Found: '{carid}'")

    # Extract TLM ID: match line that begins with "Third Party ID" but ignore parentheses text
    m = re.search(r"Third Party ID\b.*?:\s*(.*)", issue, re.IGNORECASE)
    tlm_id = m.group(1).strip() if m else ""

    # Split into rule blocks
    blocks = re.split(r"#### Rule", issue, flags=re.IGNORECASE)[1:]
    seen = set()

    for idx, block in enumerate(blocks, 1):
        # Parse fields (keep direction optional)
        def extract(label):
            m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
            return m.group(1).strip() if m else ""
        src = extract("New Source IP") or extract("New Source")
        dst = extract("New Destination IP") or extract("New Destination")
        ports = extract("New Port")
        proto = extract("New Protocol")
        just = extract("New Business Justification")
        direction = extract("New Direction")

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

                # Check third‑party range first, regardless of prefix length
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    uses_third_party = True

                # Oversized prefix handling
                if net.prefixlen < 24:
                    if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                        errors.append(f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range.")
                    continue

                # Public range check
                if not any(net.subnet_of(r) for r in PRIVATE_RANGES):
                    if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                        errors.append(f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' is public and not in allowed GCP ranges.")
                    continue

        # Require TLM ID when needed
        if uses_third_party and not tlm_id:
            errors.append(f"❌ Rule {idx}: A Third Party ID (TLM ID) must be provided when using the third‑party‑peering boundary.")

        # Validate ports
        for p in ports.split(","):
            if not validate_port(p.strip()):
                errors.append(f"❌ Rule {idx}: Invalid port or range: '{p.strip()}'")

        # Duplicate rule detection within the issue
        key = (src, dst, ports, proto, direction)
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule in request.")
        seen.add(key)

    # Print and exit on errors
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors: print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
