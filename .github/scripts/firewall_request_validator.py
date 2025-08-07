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

This version includes additional checks to ensure that health‑check ranges
(``35.191.0.0/16``, ``130.211.0.0/22``) may only appear on the source side of a rule
and that restricted Google API ranges (``199.36.153.4/30``) may only appear on
the destination side. It also strips leading punctuation/emoji from lines
before extracting fields to better handle templates that prefix labels with
icons.
"""

import re
import sys
import ipaddress
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

# Dynamically load third‑party peering ranges from boundary_map.json.
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
        THIRD_PARTY_PEERING_RANGES = [ipaddress.ip_network("10.150.1.0/24")]
except Exception:
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
        a, b = map(int, port.split("-"))
        return 1 <= a <= b <= 65535
    return False


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: firewall_request_validator.py <issue_body_file>")
        sys.exit(1)
    issue = open(sys.argv[1]).read()
    errors: list[str] = []

    # Extract REQID and CARID
    m = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue, re.IGNORECASE)
    reqid = m.group(1).strip() if m else None
    if not validate_reqid(reqid):
        errors.append(f"❌ REQID must be 'REQ' followed by 7–8 digits. Found: '{reqid}'")
    m = re.search(r"CARID.*?:\s*(\d+)", issue, re.IGNORECASE)
    carid = m.group(1).strip() if m else None
    if not validate_carid(carid):
        errors.append(f"❌ CARID must be exactly 9 digits. Found: '{carid}'")

    # Extract TLM ID on the same line as the "Third Party ID" label
    m = re.search(r"Third Party ID\b.*?:[ \t]*([^\n\r]*)", issue, re.IGNORECASE)
    tlm_id = m.group(1).strip() if m else ""

    # Split into rule blocks. Accept headings with any number of '#'
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue, flags=re.IGNORECASE)
    blocks = [b for b in blocks[1:] if b.strip()]
    seen: set[tuple[str, str, str, str, str]] = set()

    for idx, block in enumerate(blocks, 1):
        # Helper to extract fields. Strip leading punctuation/emoji and Markdown formatting.
        def extract(label: str) -> str:
            for line in block.splitlines():
                # Remove Markdown emphasis characters
                clean = re.sub(r"[*_`~]+", "", line)
                # Remove leading non‑alphanumeric characters (e.g. bullets or emoji)
                clean = re.sub(r"^[^A-Za-z0-9]*", "", clean)
                m2 = re.match(rf"\s*{re.escape(label)}.*?:\s*(.*)", clean, re.IGNORECASE)
                if m2:
                    return m2.group(1).strip()
            return ""

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
        third_party_src = False
        third_party_dst = False

        # Validate IP/CIDR lists and classify third‑party usage
        for label_name, val in [("source", src), ("destination", dst)]:
            for ip_str in val.split(","):
                ip_str = ip_str.strip()
                if not ip_str:
                    continue
                if "/" not in ip_str:
                    errors.append(f"❌ Rule {idx}: {label_name.capitalize()} '{ip_str}' must include a CIDR mask (e.g. /32).")
                    continue
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                except Exception:
                    errors.append(f"❌ Rule {idx}: Invalid {label_name} IP/CIDR '{ip_str}'.")
                    continue
                if net == ipaddress.ip_network("0.0.0.0/0"):
                    errors.append(f"❌ Rule {idx}: {label_name.capitalize()} may not be 0.0.0.0/0.")
                    continue
                # Check third‑party regardless of prefix len
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    uses_third_party = True
                    if label_name == "source":
                        third_party_src = True
                    else:
                        third_party_dst = True
                # Oversized prefix handling (< /24)
                if net.prefixlen < 24:
                    if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                        errors.append(
                            f"❌ Rule {idx}: {label_name.capitalize()} '{ip_str}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range."
                        )
                    continue
                # Public range check (prefix >= /24)
                if not any(net.subnet_of(r) for r in PRIVATE_RANGES):
                    if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                        errors.append(
                            f"❌ Rule {idx}: {label_name.capitalize()} '{ip_str}' is public and not in allowed GCP ranges."
                        )
                    continue

        # Require a TLM ID only for cross‑boundary rules (one side third‑party and the other internal)
        if uses_third_party and not tlm_id and not (third_party_src and third_party_dst):
            errors.append(
                f"❌ Rule {idx}: A Third Party ID (TLM ID) must be provided when using the third‑party‑peering boundary."
            )

        # Validate ports
        for p in ports.split(","):
            p = p.strip()
            if not validate_port(p):
                errors.append(f"❌ Rule {idx}: Invalid port or range: '{p}'")

        # Enforce restricted‑API and health‑check placement
        for ip_str in src.split(","):
            ip_str = ip_str.strip()
            if ip_str:
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                except Exception:
                    continue
                if any(net.subnet_of(r) for r in RESTRICTED_API_RANGES):
                    errors.append(
                        f"❌ Rule {idx}: Restricted Google APIs ranges (199.36.153.4/30) may only appear on the destination side."
                    )
        for ip_str in dst.split(","):
            ip_str = ip_str.strip()
            if ip_str:
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                except Exception:
                    continue
                if any(net.subnet_of(r) for r in HEALTH_CHECK_RANGES):
                    errors.append(
                        f"❌ Rule {idx}: Health‑check ranges (35.191.0.0/16, 130.211.0.0/22) may only appear on the source side."
                    )

        # Duplicate detection within the issue (source, destination, ports, protocol, direction)
        key = (src.strip(), dst.strip(), ports.strip(), proto.strip(), direction.strip())
        if key in seen:
            errors.append(f"❌ Rule {idx}: Duplicate rule in request.")
        seen.add(key)

    # Print errors and exit non‑zero if any
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)


if __name__ == "__main__":
    main()