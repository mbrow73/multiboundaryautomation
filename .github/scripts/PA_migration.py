#!/usr/bin/env python3
import csv
import re
import argparse
from collections import defaultdict

# ---------- helpers ----------

def _norm(s: str) -> str:
    """Normalize tokens: strip quotes/space, lower, drop trailing $."""
    if s is None:
        return ""
    s = str(s).strip().strip('"').strip("'").lower()
    return s[:-1] if s.endswith("$") else s

def _split_tags(s: str) -> list[str]:
    if not s:
        return []
    # address-object tags are semicolon-separated in your exports
    return [_norm(t) for t in str(s).split(";") if t.strip()]

def _split_ports(s: str) -> list[str]:
    if not s:
        return []
    # support ; or , inside a quoted CSV cell
    parts = []
    for p in str(s).replace(";", ",").split(","):
        p = p.strip()
        if p:
            parts.append(p)
    return parts

def _extract_filter_criteria(addresses_field: str) -> list[str]:
    """
    'Addresses' cell looks like:
      Dynamic Address Group: AUTHBLUE-E1-OUT-DST;Filter: AUTHBLUE-E1-OUT-DSTS
    We extract the string after 'filter:' (case-insensitive) and split on
    ';' ',' 'and' 'or' to allow simple compound filters.
    """
    if not addresses_field:
        return []
    m = re.search(r"filter\s*:\s*(.+)$", str(addresses_field), flags=re.IGNORECASE)
    if not m:
        return []
    raw = m.group(1)
    # split on ; , or words AND/OR
    parts = re.split(r"[;,]|(?:\s+and\s+)|(?:\s+or\s+)", raw, flags=re.IGNORECASE)
    return [_norm(p) for p in parts if p.strip()]

def _tag_matches(tag: str, crit: str) -> bool:
    """Treat a match as equality or suffix (prod vs ...-prod)."""
    return tag == crit or tag.endswith(crit)

# ---------- loaders ----------

def _dictreader_trimmed(path: str):
    # Skip leading blank lines, handle UTF-8 with BOM
    with open(path, encoding="utf-8-sig", newline="") as f:
        for line in f:
            if line.strip():
                yield line
        # if file is empty/only blanks, caller will see no rows

def load_address_objects(path: str) -> dict:
    """Expect headers like: Name, Location, Type, Address, Tags (quoted cells OK)."""
    objs = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return objs
    # map headers case-insensitively
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_addr = H.get("address")
    h_tags = H.get("tags")  # NOTE: real export uses 'Tags'
    for row in rows:
        name = row.get(h_name, "").strip().strip('"')
        addr = row.get(h_addr, "").strip().strip('"')
        tags = _split_tags(row.get(h_tags, ""))
        if name and addr:
            objs[name] = {"value": addr, "tags": tags}
    return objs

def load_address_groups(path: str) -> dict:
    """Expect headers like: Name, Location, Members Count, Addresses, Tags."""
    groups = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return groups
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_addr = H.get("addresses")  # contains 'Filter: ...'
    for row in rows:
        name = row.get(h_name, "").strip().strip('"')
        crits = _extract_filter_criteria(row.get(h_addr, ""))
        if name:
            groups[name] = {"type": "dynamic", "criteria": crits}
    return groups

def load_service_objects(path: str) -> dict:
    """Expect headers like: Name, Protocol, Destination Port (plus junk columns)."""
    services = {}
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return services
    H = {h.lower(): h for h in rows.fieldnames}
    h_name = H.get("name")
    h_proto = H.get("protocol")
    h_ports = H.get("destination port")
    for row in rows:
        name = row.get(h_name, "").strip().strip('"')
        proto = _norm(row.get(h_proto, "tcp"))
        ports = _split_ports(row.get(h_ports, ""))
        if name and proto and ports:
            services[_norm(name)] = {"protocol": proto, "ports": ports}
    return services

def parse_rules(path: str) -> list[dict]:
    """Expect headers like: Name, Source Address, Destination Address, Service."""
    rules = []
    rows = csv.DictReader(_dictreader_trimmed(path))
    if not rows.fieldnames:
        return rules
    H = {h.lower(): h for h in rows.fieldnames}
    hn = H.get("name")
    hs = H.get("source address")
    hd = H.get("destination address")
    hv = H.get("service")
    for row in rows:
        name = row.get(hn, "").strip().strip('"')
        src = [s.strip().strip('"') for s in str(row.get(hs, "")).split(";") if s.strip()]
        dst = [d.strip().strip('"') for d in str(row.get(hd, "")).split(";") if d.strip()]
        svc = row.get(hv, "").strip().strip('"')
        if name and (src or dst) and svc:
            rules.append({"name": name, "source": src, "destination": dst, "service": svc})
    return rules

# ---------- expansion ----------

def expand_entity(name: str, objs: dict, groups: dict) -> list[str]:
    """Expand object/group name to list of CIDRs/IPs. Surface unknowns clearly."""
    key = name.strip().strip('"')
    if _norm(key) == "any":
        # You said you won't have any 'any' rules, but keep the guard
        return []
    if key in objs:
        return [objs[key]["value"]]
    if key in groups and groups[key]["type"] == "dynamic":
        crits = groups[key]["criteria"] or []
        ips = []
        for obj in objs.values():
            for c in crits:
                # match if any object tag equals or suffix-matches a criterion
                if any(_tag_matches(tag, c) for tag in obj["tags"]):
                    ips.append(obj["value"])
                    break
        return ips if ips else [f"***NO MATCH: group={key} filter={','.join(crits)}***"]
    return [f"***UNKNOWN ENTITY: {key}***"]

# ---------- output ----------

def generate_issue(rules_csv, objs_csv, groups_csv, services_csv, reqid=None, carid=None, tlmid=None):
    objs = load_address_objects(objs_csv)
    groups = load_address_groups(groups_csv)
    services = load_service_objects(services_csv)
    rules = parse_rules(rules_csv)

    print('---')
    print('name: "Firewall Rule Request"')
    print('about: "Request new or updated GCP firewall rules"')
    print('labels: ["firewall-request"]')
    print('---\n')
    print(f"### Request ID (REQID): {reqid or '<REQID>'}")
    print(f"### CARID: {carid or '<CARID>'}")
    print(f"### Third Party ID (TLM ID) (required for third-party VPC access): {tlmid or ''}\n")

    for idx, r in enumerate(rules, start=1):
        src_ips = []
        for s in r["source"]:
            src_ips.extend(expand_entity(s, objs, groups))
        dst_ips = []
        for d in r["destination"]:
            dst_ips.extend(expand_entity(d, objs, groups))

        svc_key = _norm(r["service"])
        if svc_key not in services:
            # allow service objects to be referred by either raw name or friendly name
            svc = {"protocol": "tcp", "ports": _split_ports(r["service"])}
        else:
            svc = services[svc_key]

        # Aggregate ports into a single list for this rule (per your framework)
        ports_list = svc["ports"]
        protocol = svc["protocol"]

        print(f"#### Rule {idx}")
        print(f"🔹 New Source IP(s) or CIDR(s): {', '.join(src_ips) if src_ips else '***EMPTY***'}  ")
        print(f"🔹 New Destination IP(s) or CIDR(s): {', '.join(dst_ips) if dst_ips else '***EMPTY***'}  ")
        print(f"🔹 New Port(s): {', '.join(ports_list)}  ")
        print(f"🔹 New Protocol: {protocol}  ")
        print(f"🔹 New Business Justification: {', '.join(r['source'])} to {', '.join(r['destination'])} for netsec migration\n")

# ---------- CLI ----------

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Convert PA CSVs to your GitHub issue format.")
    p.add_argument("--rules", default="rules.csv")
    p.add_argument("--objects", default="address_objects.csv")
    p.add_argument("--groups", default="address_groups.csv")
    p.add_argument("--services", default="services.csv")
    p.add_argument("--reqid", default=None)
    p.add_argument("--carid", default=None)
    p.add_argument("--tlmid", default=None)
    A = p.parse_args()
    generate_issue(A.rules, A.objects, A.groups, A.services, reqid=A.reqid, carid=A.carid, tlmid=A.tlmid)
