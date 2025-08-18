#!/usr/bin/env python3
"""
pa_rule_merger.py

This script reads firewall rule CSVs exported from Panorama (similar to
``convert_pa_rules_v7.py``) and aggregates rules that share the same
service definition.  The goal is to reduce the total number of rule
attributes consumed in Google Cloud Platform by collapsing duplicate
source/destination ranges and grouping rules with identical protocol/port
definitions into a single rule.

File formats
------------
The CSV inputs are expected to have the following headers (case-insensitive):

* **Rules CSV**
  - ``Name``: descriptive name for the rule (ignored for grouping)
  - ``Source Address``: semicolon- or comma-separated list of objects or
    literal IPs/CIDRs.  ``any`` will be ignored and results in an empty list.
  - ``Destination Address``: semicolon- or comma-separated list of objects
    or literal IPs/CIDRs.
  - ``Service``: either a name referencing a row in the service objects CSV
    or a comma/semicolon‑separated list of ports (protocol defaults to TCP).

* **Address Objects CSV**
  - ``Name``: the object name referenced in rules
  - ``Address``: literal IP/CIDR
  - ``Tags``: optional semicolon‑separated list of tags used by dynamic groups

* **Address Groups CSV**
  - ``Name``
  - ``Addresses``: string containing ``Filter: tag1;tag2`` to match tags

* **Service Objects CSV**
  - ``Name``: service name referenced in rules
  - ``Protocol``: e.g. ``tcp``, ``udp``
  - ``Destination Port``: comma/semicolon‑separated list or ranges (e.g. ``80``, ``53-53``)

Behavior
--------
* Address objects and dynamic address groups are expanded to lists of IP
  addresses/CIDRs.
* Literal IPs without a prefix are treated as ``/32`` during summarisation.
* The summarisation logic uses ``ipaddress.collapse_addresses`` to merge
  adjacent networks only when mathematically exact.  This preserves
  semantics and prevents over‑aggregation.
* Rules are grouped by the tuple

    ``(protocol, tuple(sorted(ports_list)))``

  where ``ports_list`` is the list of string representations of ports or
  port ranges for the service.  Only rules with identical protocol and
  sorted port lists are merged.
* For each group, the source and destination IP lists from all rules are
  concatenated, de‑duplicated while preserving order, and summarised.
* The resulting merged rules are printed as markdown under headings
  ``#### Merged Rule n``.

Examples
--------
See the bottom of this file (``__main__`` section) for an example of how
to call this script on sample CSVs.  Running the script with ``--help``
will show available options.
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
from typing import Dict, Iterable, List, Tuple


# ----------------------------- Normalisation helpers -----------------------------

def _norm(s: str) -> str:
    """Normalise tokens: strip quotes/space, lower, drop trailing ``$``."""
    if s is None:
        return ""
    s = str(s).strip().strip('"').strip("'").lower()
    return s[:-1] if s.endswith("$") else s


def _split_tags(s: str) -> List[str]:
    """Split semicolon‑separated tags and normalise."""
    if not s:
        return []
    return [_norm(t) for t in str(s).split(";") if t.strip()]


def _split_list_cell(s: str) -> List[str]:
    """Split a cell that may use semicolons or commas as internal separators.

    ``NO MATCH`` placeholders (any case, possibly suffixed) are ignored.
    """
    if not s:
        return []
    parts: List[str] = []
    for p in str(s).replace(";", ",").split(","):
        p = p.strip().strip('"')
        if p:
            # Drop Panorama placeholder artifacts like "NO MATCH..." (any case)
            if _norm(p).startswith("no match"):
                continue
            parts.append(p)
    return parts


def _extract_filter_criteria(addresses_field: str) -> List[str]:
    """
    Extract tag filters from a dynamic address group definition.

    Example: ``"Dynamic Address Group: foo;Filter: tag1;tag2"`` → ``["tag1", "tag2"]``.
    Supports comma/semicolon separated lists and ``and``/``or`` separators.
    """
    if not addresses_field:
        return []
    m = re.search(r"filter\s*:\s*(.+)$", str(addresses_field), flags=re.IGNORECASE)
    if not m:
        return []
    raw = m.group(1)
    parts = re.split(r"[;,]|(?:\s+and\s+)|(?:\s+or\s+)", raw, flags=re.IGNORECASE)
    return [_norm(p) for p in parts if p.strip()]


def _tag_matches(tag: str, crit: str) -> bool:
    """Return True if ``tag`` equals ``crit`` or ends with ``crit``."""
    return tag == crit or tag.endswith(crit)


def _dedup_preserve(seq: Iterable[str]) -> List[str]:
    """Deduplicate while preserving order."""
    seen = set()
    out: List[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ----------------------------- CSV readers -----------------------------

def _dictreader_trimmed(path: str):
    """Yield lines from a CSV after skipping leading blank lines; supports UTF‑8 BOM."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        for line in f:
            if line.strip():
                yield line


def load_address_objects(path: str, verbose: bool = False) -> Dict[str, Dict]:
    """Read address objects from CSV.  Returns mapping from name → {value, tags}."""
    objs: Dict[str, Dict] = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return objs
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_addr = H.get("address")
    h_tags = H.get("tags")
    for row in rows:
        name = (row.get(h_name) or "").strip().strip('"')
        addr = (row.get(h_addr) or "").strip().strip('"')
        tags = _split_tags(row.get(h_tags) or "")
        if name and addr:
            objs[name] = {"value": addr, "tags": tags}
    if verbose:
        print(f"[info] loaded {len(objs)} address objects from {path}", file=sys.stderr)
    return objs


def load_address_groups(path: str, verbose: bool = False) -> Dict[str, Dict]:
    """Read dynamic address groups from CSV.  Returns mapping from name → {type, criteria}."""
    groups: Dict[str, Dict] = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return groups
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_addr = H.get("addresses")
    for row in rows:
        name = (row.get(h_name) or "").strip().strip('"')
        criteria = _extract_filter_criteria(row.get(h_addr) or "")
        if name:
            groups[name] = {"type": "dynamic", "criteria": criteria}
    if verbose:
        print(f"[info] loaded {len(groups)} address groups from {path}", file=sys.stderr)
    return groups


def load_service_objects(path: str, verbose: bool = False) -> Dict[str, Dict]:
    """Read service objects from CSV.  Returns mapping from normalised name → {protocol, ports}."""
    services: Dict[str, Dict] = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return services
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_proto = H.get("protocol")
    h_ports = H.get("destination port")
    for row in rows:
        name_raw = (row.get(h_name) or "")
        name = _norm(name_raw)
        proto = _norm(row.get(h_proto) or "tcp")
        ports = _split_list_cell(row.get(h_ports) or "")
        if name and proto and ports:
            services[name] = {"protocol": proto, "ports": ports}
    if verbose:
        print(f"[info] loaded {len(services)} service objects from {path}", file=sys.stderr)
    return services


def parse_rules(path: str, verbose: bool = False) -> List[Dict]:
    """Read the rules CSV.  Returns a list of raw rule dicts."""
    rules: List[Dict] = []
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return rules
    H = {h.lower(): h for h in rows.fieldnames}
    hn = H.get("name")
    hs = H.get("source address")
    hd = H.get("destination address")
    hv = H.get("service")
    for row in rows:
        name = (row.get(hn) or "").strip().strip('"')
        src = _split_list_cell(row.get(hs) or "")
        dst = _split_list_cell(row.get(hd) or "")
        svc = (row.get(hv) or "").strip().strip('"')
        if name and (src or dst) and svc:
            rules.append({"name": name, "source": src, "destination": dst, "service": svc})
    if verbose:
        print(f"[info] parsed {len(rules)} rules from {path}", file=sys.stderr)
    return rules


# ----------------------------- Expansion & summarisation -----------------------------

def expand_entity(name: str, objs: Dict[str, Dict], groups: Dict[str, Dict]) -> List[str]:
    """
    Expand an address object or dynamic group to a list of CIDR strings.

    ``unknown`` or unmatched entities return an empty list.  ``any`` also
    returns an empty list (to be filtered out by callers).
    """
    raw = name.strip().strip('"')
    if _norm(raw) == "any":
        return []

    obj = objs.get(raw)
    if obj:
        return [obj["value"]]

    grp = groups.get(raw)
    if grp and grp.get("type") == "dynamic":
        criteria = grp.get("criteria", [])
        if not criteria:
            return []
        ips: List[str] = []
        for o in objs.values():
            for c in criteria:
                if any(_tag_matches(tag, c) for tag in o["tags"]):
                    ips.append(o["value"])
                    break
        return ips

    return []


def summarize_cidrs(cidrs: List[str], keep_host_prefix: bool = True) -> List[str]:
    """Safely summarise a list of IPs/CIDRs using ``ipaddress.collapse_addresses``.

    Adds ``/32`` to bare IPs.  Only merges when exact; never over‑aggregates.
    If ``keep_host_prefix`` is True, host entries are shown as ``a.b.c.d/32``.
    """
    nets: List[ipaddress._BaseNetwork] = []
    for s in cidrs:
        s = s.strip()
        if not s:
            continue
        try:
            if "/" not in s:
                s = f"{s}/32"
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    collapsed = ipaddress.collapse_addresses(nets)
    out: List[str] = []
    for n in collapsed:
        # Keep host prefix on IPv4 /32s unless told otherwise
        if isinstance(n, ipaddress.IPv4Network) and n.prefixlen == 32 and keep_host_prefix:
            out.append(f"{n.network_address}/32")
        else:
            out.append(str(n))
    return out


# ----------------------------- Grouping & merging logic -----------------------------

def normalise_service(rule: Dict, services: Dict[str, Dict]) -> Tuple[str, Tuple[str, ...]]:
    """
    Normalise a rule's service into a canonical form suitable for grouping.

    Returns a tuple (protocol, sorted_ports) where ``protocol`` is a
    lowercase string and ``sorted_ports`` is a tuple of strings.  If the
    service name exists in ``services``, the corresponding protocol and
    port list are used.  Otherwise the rule's ``service`` field is
    interpreted as a comma/semicolon‑separated list of ports and defaults
    to protocol ``tcp``.
    """
    svc_key = _norm(rule["service"])
    if svc_key in services:
        proto = services[svc_key]["protocol"]
        ports = services[svc_key]["ports"]
    else:
        proto = "tcp"
        ports = _split_list_cell(rule["service"])
    # Sort ports to ensure consistent grouping irrespective of order
    sorted_ports = tuple(sorted(ports))
    return proto, sorted_ports


def aggregate_rules(rules: List[Dict], objs: Dict[str, Dict], groups: Dict[str, Dict], services: Dict[str, Dict], summarise: bool = True, verbose: bool = False) -> List[Dict]:
    """
    Expand and summarise rule IPs, then group rules by service and merge
    their source/destination lists.

    Returns a list of merged rule dictionaries with keys:
    ``protocol``, ``ports``, ``source``, ``destination``, and ``original_names``.
    ``original_names`` contains the names of the individual rules merged into
    this aggregated rule for traceability.
    """
    # Intermediate expansion structure: list of expanded rules with service
    expanded_rules = []
    for r in rules:
        src_ips: List[str] = []
        for s in r["source"]:
            src_ips.extend(expand_entity(s, objs, groups))
        dst_ips: List[str] = []
        for d in r["destination"]:
            dst_ips.extend(expand_entity(d, objs, groups))

        # Deduplicate while preserving order
        src_ips = _dedup_preserve(src_ips)
        dst_ips = _dedup_preserve(dst_ips)

        # Skip if either side empty
        if not src_ips or not dst_ips:
            if verbose:
                print(f"[skip] rule '{r['name']}' empty side after expansion", file=sys.stderr)
            continue

        # Optionally summarise IPs
        if summarise:
            src_ips = summarize_cidrs(src_ips, keep_host_prefix=True)
            dst_ips = summarize_cidrs(dst_ips, keep_host_prefix=True)

        proto, sorted_ports = normalise_service(r, services)
        expanded_rules.append({
            "name": r["name"],
            "protocol": proto,
            "ports": sorted_ports,
            "source": src_ips,
            "destination": dst_ips,
        })

    # Group by (protocol, ports)
    groups_map: Dict[Tuple[str, Tuple[str, ...]], Dict[str, List[str]]] = {}
    names_map: Dict[Tuple[str, Tuple[str, ...]], List[str]] = {}
    for er in expanded_rules:
        key = (er["protocol"], er["ports"])
        # If group not present, initialise
        if key not in groups_map:
            groups_map[key] = {"source": [], "destination": []}
            names_map[key] = []
        # Extend source/destination lists for this group
        groups_map[key]["source"].extend(er["source"])
        groups_map[key]["destination"].extend(er["destination"])
        names_map[key].append(er["name"])

    # Deduplicate and summarise group lists
    merged_rules: List[Dict] = []
    for key, lists in groups_map.items():
        protocol, ports = key
        src = _dedup_preserve(lists["source"])
        dst = _dedup_preserve(lists["destination"])
        if summarise:
            src = summarize_cidrs(src, keep_host_prefix=True)
            dst = summarize_cidrs(dst, keep_host_prefix=True)
        merged_rules.append({
            "protocol": protocol,
            "ports": list(ports),
            "source": src,
            "destination": dst,
            "original_names": names_map[key],
        })
    return merged_rules


# ----------------------------- Markdown generation -----------------------------

def generate_merged_issue_md(
    rules_csv: str,
    objs_csv: str,
    groups_csv: str,
    services_csv: str,
    reqid: str | None = None,
    carid: str | None = None,
    tlmid: str | None = None,
    summarise: bool = True,
    verbose: bool = False,
) -> str:
    """
    Generate a GitHub issue markdown block representing merged firewall rules.

    This function merges rules by service definition and outputs markdown
    formatted according to a standard firewall request template.  The YAML
    front‑matter and header fields are included.  The ``reqid``, ``carid``
    and ``tlmid`` parameters allow callers to supply custom values; if
    ``None`` is provided, placeholder values are used.
    """
    objs = load_address_objects(objs_csv, verbose=verbose)
    grps = load_address_groups(groups_csv, verbose=verbose)
    srvs = load_service_objects(services_csv, verbose=verbose)
    rules = parse_rules(rules_csv, verbose=verbose)

    merged = aggregate_rules(rules, objs, grps, srvs, summarise=summarise, verbose=verbose)

    lines: List[str] = []
    lines.append('---')
    lines.append('name: "Firewall Rule Request"')
    lines.append('about: "Request new or updated GCP firewall rules"')
    lines.append('labels: ["firewall-request"]')
    lines.append('---\n')
    lines.append(f"### Request ID (REQID): {reqid or '<REQID>'}")
    lines.append(f"### CARID: {carid or '<CARID>'}")
    lines.append(f"### Third Party ID (TLM ID) (required for third‑party VPC access): {tlmid or ''}\n")

    if not merged:
        lines.append("> _No merged rules emitted. Check inputs._\n")
        return "\n".join(lines)

    for idx, m in enumerate(merged, start=1):
        lines.append(f"#### Rule {idx}")
        lines.append(f"🔹 New Source IP(s) or CIDR(s): {', '.join(m['source'])}  ")
        lines.append(f"🔹 New Destination IP(s) or CIDR(s): {', '.join(m['destination'])}  ")
        lines.append(f"🔹 New Port(s): {', '.join(m['ports'])}  ")
        lines.append(f"🔹 New Protocol: {m['protocol']}  ")
        # Business justification includes names of original rules for traceability
        justification = f"Aggregated rule derived from {', '.join(m['original_names'])}" if m['original_names'] else "Aggregated rule"
        lines.append(f"🔹 New Business Justification: {justification}\n")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Aggregate and merge firewall rules by service definition.")
    p.add_argument("--rules", required=True, help="Rules CSV file")
    p.add_argument("--objects", required=True, help="Address Objects CSV file")
    p.add_argument("--groups", required=True, help="Address Groups CSV file")
    p.add_argument("--services", required=True, help="Service Objects CSV file")
    p.add_argument("--reqid", default=None, help="Request ID to embed in the issue header")
    p.add_argument("--carid", default=None, help="CARID to embed in the issue header")
    p.add_argument("--tlmid", default=None, help="Third Party ID (TLM ID) to embed in the issue header")
    p.add_argument("--summarise", dest="summarise", action="store_true", default=True,
                   help="Enable IP summarisation (default)")
    p.add_argument("--no-summarise", dest="summarise", action="store_false",
                   help="Disable IP summarisation")
    p.add_argument("--verbose", action="store_true", help="Verbose logging to stderr")
    args = p.parse_args()

    md = generate_merged_issue_md(
        args.rules,
        args.objects,
        args.groups,
        args.services,
        reqid=args.reqid,
        carid=args.carid,
        tlmid=args.tlmid,
        summarise=args.summarise,
        verbose=args.verbose,
    )
    print(md)


if __name__ == "__main__":
    # Example usage when called as a script.  To test the merging logic
    # interactively, run:
    #
    #   python pa_rule_merger.py --rules sample_rules.csv \
    #     --objects sample_objects.csv --groups sample_groups.csv \
    #     --services sample_services.csv
    main()
