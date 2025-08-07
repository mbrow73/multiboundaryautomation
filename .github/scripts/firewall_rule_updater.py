#!/usr/bin/env python3
"""
Firewall request validator.

This script validates firewall rule requests submitted via GitHub Issues. It enforces
proper formatting for REQID and CARID values, checks that IP addresses and
prefixes are well‑formed, and ensures ports and protocols are within
acceptable ranges. It also applies special handling for Google health check
ranges and restricted API ranges.

When a rule involves a third‑party VPC (for example, a peering connection to an
external partner), the requesting engineer must supply a Third‑Party ID (also
called a TLM ID) in the issue body. To discover which IP ranges represent
third‑party networks, this script reads the repository's ``boundary_map.json``
file. Any entry whose key contains the substring ``"third"`` (case
insensitive) is treated as a third‑party boundary. All CIDRs under such
entries are collected into ``THIRD_PARTY_PEERING_RANGES``. If the boundary map
is missing or unreadable, the validator falls back to a default set of CIDRs
so that it can still run.
"""

import re
import sys
import ipaddress
import glob
import json
import os

# Allowed public ranges for Google services.
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
    ipaddress.ip_network("199.36.153.4/30"),
]

# Subset of public ranges reserved for GCP health checks.
HEALTH_CHECK_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
]

# Restricted API ranges that may only appear on the destination side of a rule.
RESTRICTED_API_RANGES = [
    ipaddress.ip_network("199.36.153.4/30"),
]

# Dynamically load third‑party peering ranges from boundary_map.json.  The map
# lives at the repository root.  We locate it relative to this file (two
# directories up) so the script can be executed from anywhere within the
# project.  If reading the map fails or yields no ranges, we fall back to a
# sensible default.
try:
    boundary_map_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "boundary_map.json")
    )
    with open(boundary_map_path, "r", encoding="utf-8") as f:
        _boundary_map = json.load(f)
    THIRD_PARTY_PEERING_RANGES = [
        ipaddress.ip_network(cidr)
        for name, cidrs in _boundary_map.items()
        if "third" in name.lower()
        for cidr in cidrs
    ]
    if not THIRD_PARTY_PEERING_RANGES:
        # Provide a default when no third‑party boundaries are defined.
        THIRD_PARTY_PEERING_RANGES = [ipaddress.ip_network("10.150.1.0/24")]
except Exception:
    # Fallback to the original default if loading fails.
    THIRD_PARTY_PEERING_RANGES = [ipaddress.ip_network("10.150.1.0/24")]

# Private address space used for on‑premises and intranet networks.
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def validate_reqid(reqid: str) -> bool:
    """Validate that the REQID follows the pattern REQ followed by 7–8 digits."""
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid or ""))

def validate_carid(carid: str) -> bool:
    """Validate that the CARID is exactly 9 digits."""
    return bool(re.fullmatch(r"\d{9}", carid or ""))

def validate_port(port: str) -> bool:
    """Validate that a port or port range is within 1–65535."""
    if re.fullmatch(r"\d{1,5}", port or ""):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port or ""):
        a, b = map(int, port.split('-'))
        return 1 <= a <= b <= 65535
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
    # Extract TLM ID on the same line as the "Third Party ID" label.  We match only
    # spaces or tabs after the colon to ensure we stop at a newline; without this
    # restriction, a blank TLM field followed by a heading (e.g. "#### Rule 1")
    # could be captured as the TLM ID.  If nothing is provided on that line,
    # ``tlm_id`` will be an empty string.
    m = re.search(r"Third Party ID\b.*?:[ \t]*([^\n\r]*)", issue, re.IGNORECASE)
    tlm_id = m.group(1).strip() if m else ""

    # Split into rule blocks.  Accept headings with any number of '#' characters (including none)
    # so that both "#### Rule 1" and plain "Rule 1" are handled.  We split on patterns
    # like "Rule 1", "## Rule 2", etc., and drop the first element (the text before the first rule).
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue, flags=re.IGNORECASE)
    blocks = [b for b in blocks[1:] if b.strip()]
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
        if proto != proto.lower() or proto not in {"tcp", "udp", "icmp", "sctp"}:
            errors.append(f"❌ Rule {idx}: Protocol must be one of tcp, udp, icmp, sctp (lowercase).")

        uses_third_party = False
        # Track whether the source and destination sides individually fall within
        # a third‑party boundary.  If both sides are third‑party, the rule is
        # effectively peering a third‑party VPC to another third‑party VPC,
        # which is not permitted.  We'll flag this as an error below.
        third_party_src = False
        third_party_dst = False

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

                # Check third‑party range first, regardless of prefix length
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    uses_third_party = True
                    # Record which side of the rule is third‑party.
                    if label == "source":
                        third_party_src = True
                    else:
                        third_party_dst = True

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

        # Disallow rules that have both the source and destination in a
        # third‑party VPC.  Such third‑party‑to‑third‑party traffic should
        # instead be handled via peering or internal networking constructs.
        if third_party_src and third_party_dst:
            errors.append(f"❌ Rule {idx}: Third‑party to third‑party traffic is not allowed; please do not peer two third‑party VPCs directly.")
        # Require a TLM ID when exactly one side of the rule is third‑party.
        # If both sides are third‑party, the above check covers that case and
        # takes precedence over this requirement.
        if uses_third_party and not tlm_id and not (third_party_src and third_party_dst):
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
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()