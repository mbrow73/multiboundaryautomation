#!/usr/bin/env python3
"""
Firewall Request Validator

This script validates new firewall rule **addition** requests.  It is
invoked by the GitHub Actions workflow before a new `.auto.tfvars.json`
file is generated.  The validator ensures that:

* A request ID (REQID) and CARID are present and correctly formatted.
* Each `#### Rule` block includes all required fields (source IPs,
  destination IPs, ports, protocol, and business justification).
* IP/CIDR values are syntactically valid, include a mask, are not 0.0.0.0/0,
  and are not overly broad (/24 or larger) unless they fall within specific
  GCP health‑check ranges.  Public IP ranges outside these exceptions are rejected.
* Third‑party‑peering boundary detection: if a source or destination IP
  falls within the defined third‑party ranges, a TLM ID must be supplied.
* Ports are valid integers or ranges within 1–65535.
* Protocols are one of tcp, udp, icmp, sctp (lowercase).
* Duplicate rule definitions within a single request are flagged.
* Rules are not exact duplicates or subsets of existing rules.

If any errors are found, the validator prints them between
`VALIDATION_ERRORS_START` and `VALIDATION_ERRORS_END` and exits non‑zero.
Otherwise it exits silently.
"""

import re
import sys
import ipaddress
import glob
import json
from typing import Dict, List

# Allowed public ranges for oversized CIDRs (/24 or larger).
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),    # GCP health‑check
    ipaddress.ip_network("130.211.0.0/22"),   # GCP health‑check
    ipaddress.ip_network("199.36.153.4/30"),  # restricted googleapis
]

# Explicit lists for special ranges
HEALTH_CHECK_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
]
RESTRICTED_API_RANGES = [
    ipaddress.ip_network("199.36.153.4/30"),
]

# Define your third‑party‑peering boundary CIDRs here.
THIRD_PARTY_PEERING_RANGES = [
    ipaddress.ip_network("203.0.113.0/24"),  # example – replace with actual range(s)
    # Add additional ranges as needed
]

# Define private ranges explicitly (RFC1918).
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# ... existing helper functions: validate_reqid, validate_carid, validate_port, etc. ...

def parse_rule_block(block: str) -> Dict[str, str]:
    """Extract fields from a rule block in the issue body."""
    def extract(label: str) -> str:
        m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
        return m.group(1).strip() if m else ""
    src_ip = extract("New Source IP") or extract("New Source")
    dst_ip = extract("New Destination IP") or extract("New Destination")
    ports   = extract("New Port")
    proto   = extract("New Protocol")
    direction = extract("New Direction")
    just    = extract("New Business Justification")
    return {
        "src": src_ip,
        "dst": dst_ip,
        "ports": ports,
        "proto": proto,
        "direction": direction,
        "just": just,
    }

def main() -> None:
    issue = open(sys.argv[1]).read()
    errors: List[str] = []

    # Extract REQID and CARID
    m = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m.group(1).strip() if m else None
    if not reqid or not re.fullmatch(r"REQ\d{7,8}", reqid):
        errors.append(f"❌ REQID must be 'REQ' followed by 7–8 digits. Found: '{reqid}'")
    m = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m.group(1).strip() if m else None
    if not carid or not re.fullmatch(r"\d{9}", carid):
        errors.append(f"❌ CARID must be exactly 9 digits. Found: '{carid}'")

    # Extract the TLM ID (Third Party ID) from the issue (optional)
    m = re.search(r"Third Party ID.*?:\s*(.+)", issue, re.IGNORECASE)
    tlm_id = m.group(1).strip() if m else ""

    # Split into rule blocks
    blocks = re.split(r"#### Rule", issue, flags=re.IGNORECASE)[1:]
    seen: set = set()
    for idx, blk in enumerate(blocks, 1):
        r = parse_rule_block(blk)
        src, dst, ports, proto, direction, just = (
            r["src"], r["dst"], r["ports"], r["proto"], r["direction"], r["just"]
        )

        # Required fields
        if not all([src, dst, ports, proto, just]):
            errors.append(f"❌ Rule {idx}: All fields (source, destination, port, protocol, justification) must be present.")
            continue
        if proto != proto.lower() or proto not in {"tcp", "udp", "icmp", "sctp"}:
            errors.append(f"❌ Rule {idx}: Protocol must be one of tcp, udp, icmp, sctp (lowercase).")

        # Flags for third‑party range usage
        uses_third_party = False
        # Validate IP fields
        for label, val in [("source", src), ("destination", dst)]:
            for ip_str in val.split(","):
                ip_str = ip_str.strip()
                if not ip_str:
                    continue
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

                # Oversized CIDR check
                if net.prefixlen < 24:
                    if not any(net.subnet_of(rng) for rng in ALLOWED_PUBLIC_RANGES):
                        errors.append(
                            f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range."
                        )
                    # Track special ranges on oversized CIDRs
                    continue

                # Determine if IP is public (not RFC1918)
                in_private = any(net.subnet_of(rng) for rng in PRIVATE_RANGES)
                if not in_private:
                    # Reject any public IP not in allowed ranges
                    if not any(net.subnet_of(rng) for rng in ALLOWED_PUBLIC_RANGES):
                        errors.append(
                            f"❌ Rule {idx}: {label.capitalize()} '{ip_str}' is public and not in allowed GCP ranges."
                        )
                        continue

                # Detect if this IP is in the third‑party boundary
                if any(net.subnet_of(rng) for rng in THIRD_PARTY_PEERING_RANGES):
                    uses_third_party = True

        # If the rule uses the third‑party boundary but no TLM ID was provided
        if uses_third_party and not tlm_id:
            errors.append(f"❌ Rule {idx}: A Third Party ID (TLM ID) must be specified when using the third‑party‑peering boundary.")

        # Port checks
        for p in ports.split(","):
            p = p.strip()
            if not validate_port(p):
                errors.append(f"❌ Rule {idx}: Invalid port or range: '{p}'.")

        # Duplicate detection
        key = (src, dst, ports, proto, direction)
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule in request.")
        seen.add(key)

    # Check duplicates against existing rules (unchanged)
    existing = parse_existing_rules()
    for idx, blk in enumerate(blocks, 1):
        r = parse_rule_block(blk)
        if not all([r["src"], r["dst"], r["ports"], r["proto"]]):
            continue
        if rule_exact_match(r, existing):
            errors.append(f"❌ Rule {idx}: Exact duplicate of existing rule.")
        elif rule_is_redundant(r, existing):
            errors.append(f"❌ Rule {idx}: Redundant—already covered by an existing broader rule.")

    # Output and exit if errors
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
