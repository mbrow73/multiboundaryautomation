#!/usr/bin/env python3
"""
boundary_mapper.py
===================

This script reads a firewall request `.auto.tfvars.json` file and automatically
assigns the appropriate `src_vpc` and `dest_vpc` values for each rule based on
the IP ranges provided.  It uses a separate boundary map file (typically
`boundary_map.json`) which defines which IP ranges belong to which logical
boundary (VPC).

The mapping logic works as follows:

* The boundary map is a JSON object where each key is a boundary name and
  each value is a list of CIDR blocks.  Comments beginning with `//` or
  enclosed in `/* ... */` are ignored when parsing the file.
* For each CIDR in the map, the script builds an `ip_network` instance.  When
  determining which boundary an IP or network belongs to, it chooses the
  *most specific* matching CIDR (i.e. the one with the longest prefix length).
* All IP ranges within a single rule must resolve to the *same* boundary;
  otherwise the script will raise an error.  This restriction avoids
  ambiguous rule placement.

Usage:

```
python3 boundary_mapper.py --map-file boundary_map.json --json-file firewall-requests/REQ123.auto.tfvars.json
```

Upon successful completion the `.auto.tfvars.json` file will be updated in
place with the computed `src_vpc` and `dest_vpc` values.  If a source or
destination IP range does not map to any boundary, or maps to multiple
boundaries, the script will exit with an error.
"""

import argparse
import json
import ipaddress
import sys
import os
from typing import Dict, List, Tuple, Optional


def load_boundary_map(path: str) -> Dict[str, List[str]]:
    """Load a boundary map file, stripping out C-style and C++-style comments.

    The JSON loader in Python doesn't support comments, so this helper
    removes lines beginning with `//` and block comments enclosed in
    `/* ... */` before parsing the content as JSON.

    Args:
        path: Path to the boundary map JSON file.

    Returns:
        A dictionary mapping boundary names to lists of CIDR strings.

    Raises:
        json.JSONDecodeError: If the resulting JSON is invalid.
        FileNotFoundError: If the file cannot be opened.
    """
    with open(path) as f:
        lines = f.readlines()

    json_lines: List[str] = []
    in_block_comment = False
    for line in lines:
        stripped = line.strip()
        # Skip block comment start
        if stripped.startswith("/*"):
            in_block_comment = True
            continue
        # End block comment
        if in_block_comment:
            if stripped.endswith("*/"):
                in_block_comment = False
            continue
        # Remove single-line comments (// ...), but allow // inside strings
        if '//' in line:
            # naive removal: everything after // on the line
            idx = line.find('//')
            # Only strip if // is not inside a string (between quotes).  We
            # perform a simple check: count quotes before //.  If odd, assume
            # inside a string and leave untouched.  This is a heuristic and
            # assumes no escaped quotes.
            prefix = line[:idx]
            if prefix.count('"') % 2 == 0:
                line = prefix + "\n"
        json_lines.append(line)

    json_str = "".join(json_lines)
    return json.loads(json_str)


def build_network_index(boundary_map: Dict[str, List[str]]) -> List[Tuple[ipaddress.IPv4Network, str]]:
    """Create a list of (network, boundary) tuples for efficient lookup.

    Args:
        boundary_map: A dict mapping boundary names to lists of CIDR strings.

    Returns:
        A list of tuples where each element is (IPv4Network, boundary_name).

    Any invalid CIDR in the map will raise a ValueError.
    """
    nets: List[Tuple[ipaddress.IPv4Network, str]] = []
    for boundary, cidr_list in boundary_map.items():
        for cidr in cidr_list:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception as exc:
                raise ValueError(f"Invalid CIDR '{cidr}' in boundary '{boundary}': {exc}") from exc
            nets.append((net, boundary))
    # Sort by prefix length descending so that the most specific networks
    # appear first.  This aids in selecting the longest match.
    nets.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
    return nets


def find_boundary_for_network(net: ipaddress.IPv4Network, index: List[Tuple[ipaddress.IPv4Network, str]]) -> Optional[str]:
    """Find the boundary for a given IPv4Network.

    Args:
        net: The network to look up.
        index: A pre-built list of (network, boundary) tuples sorted by prefix length.

    Returns:
        The boundary name if a match is found, otherwise None.  If multiple
        matches exist, the first (most specific) match is returned.
    """
    for candidate_net, boundary in index:
        # Check if the candidate network completely covers the given net
        if net.subnet_of(candidate_net):
            return boundary
    return None


def determine_boundary(
    ip_list: List[str],
    index: List[Tuple[ipaddress.IPv4Network, str]],
    default_boundary: Optional[str] = None,
) -> str:
    """Determine a unique boundary for a list of IP range strings.

    Args:
        ip_list: List of IP or CIDR strings.
        index: The boundary index produced by `build_network_index`.
        default_boundary: Optional fallback boundary name to assign if a range
            does not match any configured boundary.  If None, the function
            raises an error when a range cannot be mapped.

    Returns:
        The boundary name that all provided IP ranges belong to, or the
        `default_boundary` if specified and needed.

    Raises:
        ValueError: If no boundary is found for a range (and no default
        specified), or if ranges map to multiple different boundaries.
    """
    found_boundaries = set()
    for ip_str in ip_list:
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        try:
            net = ipaddress.ip_network(ip_str, strict=False)
        except Exception as exc:
            raise ValueError(f"Invalid IP/CIDR '{ip_str}': {exc}") from exc
        boundary = find_boundary_for_network(net, index)
        if boundary is None:
            if default_boundary is not None:
                boundary = default_boundary
            else:
                raise ValueError(f"No boundary mapping found for {ip_str}")
        found_boundaries.add(boundary)
    if not found_boundaries:
        raise ValueError("No IP ranges provided for boundary determination")
    if len(found_boundaries) > 1:
        raise ValueError(f"Ambiguous boundaries {found_boundaries} for IP ranges {ip_list}")
    return next(iter(found_boundaries))


def update_tfvars_file(
    json_path: str,
    boundary_index: List[Tuple[ipaddress.IPv4Network, str]],
    default_boundary: Optional[str] = None,
) -> None:
    """Update the `.auto.tfvars.json` file in place with computed boundaries.

    Args:
        json_path: Path to the JSON file generated by the workflow.
        boundary_index: The network index for boundary lookup.
        default_boundary: Optional fallback boundary name to assign when
            an IP range does not match any configured boundary.  If None,
            the function raises an error for unmapped ranges.

    Raises:
        ValueError: If a rule cannot be mapped to a boundary and no default
            boundary is specified.
    """
    with open(json_path) as f:
        data = json.load(f)

    if "auto_firewall_rules" not in data or not isinstance(data["auto_firewall_rules"], list):
        raise ValueError(f"Unexpected format: {json_path} does not contain 'auto_firewall_rules' list")

    for rule in data["auto_firewall_rules"]:
        src_ranges = rule.get("src_ip_ranges", [])
        dst_ranges = rule.get("dest_ip_ranges", [])
        # Determine boundaries
        src_boundary = determine_boundary(src_ranges, boundary_index, default_boundary)
        dst_boundary = determine_boundary(dst_ranges, boundary_index, default_boundary)
        rule["src_vpc"] = src_boundary
        rule["dest_vpc"] = dst_boundary

    # Write back the updated JSON
    tmp_path = json_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp_path, json_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assign src_vpc/dest_vpc based on IP ranges and a boundary map",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--map-file",
        required=True,
        help="Path to boundary_map.json (can include // or /* */ comments)",
    )
    parser.add_argument(
        "--json-file",
        required=True,
        help="Path to .auto.tfvars.json to update",
    )
    parser.add_argument(
        "--default-boundary",
        default=None,
        help=(
            "Fallback boundary name for IP ranges that do not match any configured "
            "CIDR in the boundary map.  If omitted, unmapped ranges cause an error."
        ),
    )
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

    print(f"Updated {args.json_file} with src_vpc and dest_vpc boundaries.")


if __name__ == "__main__":
    main()
