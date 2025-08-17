#!/usr/bin/env python3
"""
convert_pa_rules_v7.py

- Rules CSV headers (case-insensitive):   Name, Source Address, Destination Address, Service
- Address Objects CSV:                    Name, Address, Tags
- Address Groups CSV:                     Name, Addresses   (contains 'Filter: ...')
- Service Objects CSV:                    Name, Protocol, Destination Port
Extra columns are ignored. Quoted cells are OK.

Features
- Expands dynamic groups by matching 'Filter:' tag(s) to address-object Tags (semicolon-separated).
- Aggregates multiple ports into one rule (list of strings).
- Safely summarizes IPs/CIDRs (exact merges only) and KEEPS /32 suffixes.
- Skips rules if either side expands to empty (no 'any', no NO MATCH markers).
- Prints markdown to console and writes the SAME markdown to a file in the local directory.
- Shows absolute output path and byte size after writing.
- --verbose prints helpful counts and which rules got skipped.

Defaults (can be overridden with flags):
  --rules    pa_rules_garbage.csv
  --objects  pa_address_objects_garbage.csv
  --groups   pa_address_groups_garbage.csv
  --services pa_service_objects_garbage.csv
  --out      request.md   (always written to current working directory)
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
from typing import List, Dict, Iterable


# ----------------------------- Normalization helpers -----------------------------

def _norm(s: str) -> str:
    """Normalize tokens: strip quotes/space, lower, drop trailing $."""
    if s is None:
        return ""
    s = str(s).strip().strip('"').strip("'").lower()
    return s[:-1] if s.endswith("$") else s

def _split_tags(s: str) -> List[str]:
    """Address-object 'Tags' are semicolon-separated in real exports."""
    if not s:
        return []
    return [_norm(t) for t in str(s).split(";") if t.strip()]

def _split_list_cell(s: str) -> List[str]:
    """Split a cell that may use semicolons or commas as internal separators. Drop NO MATCH artifacts."""
    if not s:
        return []
    parts = []
    for p in str(s).replace(";", ",").split(","):
        p = p.strip().strip('"')
        if p:
            # Drop Panorama placeholder artifacts like "NO MATCH..." (any case, with possible suffix)
            if _norm(p).startswith("no match"):
                continue
            parts.append(p)
    return parts

def _extract_filter_criteria(addresses_field: str) -> List[str]:
    """
    'Addresses' cell looks like:
      Dynamic Address Group: NAME;Filter: TAG1;TAG2
    Extract what's after 'filter:' (case-insensitive). Allow multiple tags separated by ; , AND OR.
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
    """Match equality or suffix (e.g., tag endswith crit)."""
    return tag == crit or tag.endswith(crit)

def _dedup_preserve(seq: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ----------------------------- CSV readers (robust) -----------------------------

def _dictreader_trimmed(path: str):
    """Yield lines after skipping leading blank lines; supports UTF-8 BOM."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        for line in f:
            if line.strip():
                yield line

def load_address_objects(path: str, verbose=False) -> Dict[str, Dict]:
    """Headers: Name, Address, Tags (case-insensitive). Extra columns ignored."""
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

def load_address_groups(path: str, verbose=False) -> Dict[str, Dict]:
    """Headers: Name, Addresses (contains 'Filter: ...'). Extra columns ignored."""
    groups: Dict[str, Dict] = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return groups
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_addr = H.get("addresses")  # contains 'Filter: ...'
    for row in rows:
        name = (row.get(h_name) or "").strip().strip('"')
        criteria = _extract_filter_criteria(row.get(h_addr) or "")
        if name:
            groups[name] = {"type": "dynamic", "criteria": criteria}
    if verbose:
        print(f"[info] loaded {len(groups)} address groups from {path}", file=sys.stderr)
    return groups

def load_service_objects(path: str, verbose=False) -> Dict[str, Dict]:
    """Headers: Name, Protocol, Destination Port. Extra columns ignored."""
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

def parse_rules(path: str, verbose=False) -> List[Dict]:
    """Headers: Name, Source Address, Destination Address, Service. Extra columns ignored."""
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


# ----------------------------- Expansion & summarization -----------------------------

def expand_entity(name: str, objs: Dict, groups: Dict) -> List[str]:
    """
    Expand an object or dynamic group to a list of CIDRs/IPs.
    - Unknown or unmatched entities return [] (silent).
    - 'any' returns [] (guard).
    """
    raw = name.strip().strip('"')
    if _norm(raw) == "any":
        return []

    obj = objs.get(raw)  # direct object?
    if obj:
        return [obj["value"]]

    grp = groups.get(raw)  # dynamic group?
    if grp and grp["type"] == "dynamic":
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

    return []  # unknown name — skip silently

def summarize_cidrs(cidrs: List[str], keep_host_prefix: bool = True) -> List[str]:
    """
    Safely summarize a list of IPs/CIDRs using ipaddress.collapse_addresses.
    - Adds /32 to bare IPs.
    - Only merges when mathematically exact; never over-aggregates.
    - If keep_host_prefix is True, show host entries as a.b.c.d/32.
    """
    nets = []
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
    out = []
    for n in collapsed:
        if isinstance(n, ipaddress.IPv4Network) and n.prefixlen == 32 and keep_host_prefix:
            out.append(f"{n.network_address}/32")
        else:
            out.append(str(n))
    return out


# ----------------------------- Markdown generation -----------------------------

def generate_issue_md(rules_csv, objs_csv, groups_csv, services_csv,
                      reqid=None, carid=None, tlmid=None,
                      summarize=True, verbose=False) -> str:
    objs = load_address_objects(objs_csv, verbose=verbose)
    groups = load_address_groups(groups_csv, verbose=verbose)
    services = load_service_objects(services_csv, verbose=verbose)
    rules = parse_rules(rules_csv, verbose=verbose)

    lines = []
    lines.append('---')
    lines.append('name: "Firewall Rule Request"')
    lines.append('about: "Request new or updated GCP firewall rules"')
    lines.append('labels: ["firewall-request"]')
    lines.append('---\n')
    lines.append(f"### Request ID (REQID): {reqid or '<REQID>'}")
    lines.append(f"### CARID: {carid or '<CARID>'}")
    lines.append(f"### Third Party ID (TLM ID) (required for third-party VPC access): {tlmid or ''}\n")

    emitted = 0
    for r in rules:
        # Expand
        src_ips: List[str] = []
        for s in r["source"]:
            src_ips.extend(expand_entity(s, objs, groups))
        dst_ips: List[str] = []
        for d in r["destination"]:
            dst_ips.extend(expand_entity(d, objs, groups))

        # De-dup (preserve order)
        src_ips = _dedup_preserve(src_ips)
        dst_ips = _dedup_preserve(dst_ips)

        # Skip if either side empty after expansion
        if not src_ips or not dst_ips:
            if verbose:
                print(f"[skip] rule '{r['name']}' empty side after expansion", file=sys.stderr)
            continue

        # Optional safe summarization
        if summarize:
            src_ips = summarize_cidrs(src_ips, keep_host_prefix=True)
            dst_ips = summarize_cidrs(dst_ips, keep_host_prefix=True)

        # Service mapping (single list of ports per rule)
        svc_key = _norm(r["service"])
        if svc_key in services:
            protocol = services[svc_key]["protocol"]
            ports_list = services[svc_key]["ports"]
        else:
            protocol = "tcp"
            ports_list = _split_list_cell(r["service"])
        if not ports_list:
            if verbose:
                print(f"[skip] rule '{r['name']}' no ports resolved", file=sys.stderr)
            continue

        emitted += 1
        # Clean justification tokens of any lingering "NO MATCH" artifacts just in case
        just_src = [x for x in r['source'] if not _norm(x).startswith("no match")]
        just_dst = [x for x in r['destination'] if not _norm(x).startswith("no match")]
        lines.append(f"#### Rule {emitted}")
        lines.append(f"🔹 New Source IP(s) or CIDR(s): {', '.join(src_ips)}  ")
        lines.append(f"🔹 New Destination IP(s) or CIDR(s): {', '.join(dst_ips)}  ")
        lines.append(f"🔹 New Port(s): {', '.join(ports_list)}  ")
        lines.append(f"🔹 New Protocol: {protocol}  ")
        lines.append(f"🔹 New Business Justification: {', '.join(just_src)} to {', '.join(just_dst)} for netsec migration\n")

    if emitted == 0:
        lines.append("> _No rules emitted. Check header names, group names, and tag filters._\n")

    return "\n".join(lines)


# ----------------------------- CLI -----------------------------

def main():
    p = argparse.ArgumentParser(description="Convert Panorama CSVs to GitHub firewall-request issue markdown.")
    p.add_argument("--rules",    default="rules.csv", help="Rules CSV file")
    p.add_argument("--objects",  default="address_objects.csv", help="Address Objects CSV file")
    p.add_argument("--groups",   default="address_groups.csv", help="Address Groups CSV file")
    p.add_argument("--services", default="service_objects.csv", help="Service Objects CSV file")
    p.add_argument("--reqid",    default=None, help="Request ID to embed")
    p.add_argument("--carid",    default=None, help="CARID to embed")
    p.add_argument("--tlmid",    default=None, help="Third-party ID (TLM ID) to embed")
    p.add_argument("--out",      default="request.md", help="Output markdown filename (always written to current directory)")
    p.add_argument("--summarize", dest="summarize", action="store_true",  default=True, help="Enable summarization (default)")
    p.add_argument("--no-summarize", dest="summarize", action="store_false", help="Disable summarization")
    p.add_argument("--verbose",  action="store_true", help="Verbose logging to stderr")
    args = p.parse_args()

    md = generate_issue_md(args.rules, args.objects, args.groups, args.services,
                           reqid=args.reqid, carid=args.carid, tlmid=args.tlmid,
                           summarize=args.summarize, verbose=args.verbose)

    # Always write to local working directory as 'request.md' or provided basename
    out_basename = os.path.basename(args.out or "request.md")
    out_path = os.path.abspath(os.path.join(os.getcwd(), out_basename))
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(md)
        size = os.path.getsize(out_path)
        print(md, flush=True)
        print(f"\n[Wrote markdown to {out_path} ({size} bytes)]")
        if size == 0:
            print("[Warning] File size is 0 bytes; content was empty after processing.", file=sys.stderr)
    except Exception as e:
        print(f"[Error] Failed writing to {out_path}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
