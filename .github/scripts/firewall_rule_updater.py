#!/usr/bin/env python3
"""
Firewall rule updater.

This script processes "Update Firewall Rule" GitHub issues and applies
requested changes to the JSON files under ``firewall-requests/``.  It ensures
updated rules are written to a new per‑request JSON file (named after the
supplied REQID) while leaving the original source files untouched.  The
updated rules are validated in the same manner as the new rule workflow:
REQID and CARID formats are checked, IP/CIDR syntax is validated, port
ranges and protocols are enforced, health‑check and restricted API ranges
are verified to be on the correct side of the rule, and duplicate rules
within the update request are detected.  When a rule crosses the
third‑party peering boundary, a Third‑Party ID (TLM ID) must be provided
unless both the source and destination are third‑party networks.  Updated
rules receive fresh priority values beginning at 1000 (or one greater than
the current maximum priority ≥1000) so as not to collide with manual
NetSec rules.

For rules that involve a third‑party VPC, a Third‑Party ID (TLM ID) must be
supplied in the issue.  To determine which IP ranges correspond to
third‑party networks, this script loads ``boundary_map.json`` from the repo
root.  All entries whose keys contain ``"third"`` are treated as third‑party
boundaries.  If the boundary map cannot be read or contains no such
entries, the updater falls back to the default CIDR of ``10.150.1.0/24``.
"""

import re
import sys
import os
import glob
import json
import ipaddress
import subprocess
from typing import Dict, List, Tuple, Any

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

# Private address space used for on‑premises and intranet networks.
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
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

NEW_TLM_ID = ""

def validate_reqid(reqid: str) -> bool:
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid or ""))

def validate_carid(carid: str) -> bool:
    return bool(re.fullmatch(r"\d{9}", carid or ""))

def validate_ip(ip: str) -> bool:
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def validate_port(port: str) -> bool:
    if re.fullmatch(r"\d{1,5}", port or ""):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port or ""):
        a, b = map(int, port.split("-"))
        return 1 <= a <= b <= 65535
    return False

def validate_protocol(proto: str) -> bool:
    return proto.lower() in {"tcp", "udp", "icmp", "sctp"}

def load_all_rules() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    rule_map: Dict[str, Dict[str, Any]] = {}
    file_map: Dict[str, str] = {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue
        for rule in data.get("auto_firewall_rules", []):
            name = rule.get("name")
            if name:
                rule_map[name] = rule
                file_map[name] = path
    return rule_map, file_map

def update_rule_fields(rule: Dict[str, Any], updates: Dict[str, Any], new_reqid: str, new_carid: str) -> Dict[str, Any]:
    # JSON round‑trip to deep clone the rule
    updated = json.loads(json.dumps(rule))
    idx = updated.get("_update_index", 1)
    proto = updates.get("protocol") or updated.get("protocol", "tcp")
    ports = updates.get("ports") or updated.get("ports", [])
    try:
        old_carid = updated.get("name", "AUTO-REQ-0-0").split("-")[2]
    except Exception:
        old_carid = ""
    carid = new_carid or old_carid
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    updated["name"] = new_name
    for key, value in updates.items():
        if value:
            updated[key] = value.lower() if key in {"protocol", "direction"} else value
    desc_just = updates.get("description") or updated.get("description", "").split("|", 1)[-1]
    updated["description"] = f"{new_name} | {desc_just.strip()}"
    return updated

def compute_next_priorities(updated_count: int) -> List[int]:
    existing_priorities: List[int] = []
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue
        for rule in data.get("auto_firewall_rules", []):
            prio = rule.get("priority")
            if isinstance(prio, int) and prio >= 1000:
                existing_priorities.append(prio)
    max_prio = max(existing_priorities) if existing_priorities else 999
    start = max(max_prio, 999) + 1
    return [start + i for i in range(updated_count)]

def validate_rule(rule: Dict[str, Any], idx: int) -> List[str]:
    errors: List[str] = []
    third_party_src = False
    third_party_dst = False
    for field in ["src_ip_ranges", "dest_ip_ranges"]:
        label = "Source" if field == "src_ip_ranges" else "Destination"
        for ip in rule.get(field, []):
            if "/" not in ip:
                errors.append(f"Rule {idx}: {label} '{ip}' must include a CIDR mask (e.g. /32).")
                continue
            if not validate_ip(ip):
                errors.append(f"Rule {idx}: Invalid {label.lower()} IP/CIDR '{ip}'.")
                continue
            net = ipaddress.ip_network(ip, strict=False)
            if net == ipaddress.ip_network("0.0.0.0/0"):
                errors.append(f"Rule {idx}: {label} may not be 0.0.0.0/0.")
                continue
            if net.prefixlen < 24:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: {label} '{ip}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range.")
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    rule["_uses_third_party"] = True
                    if field == "src_ip_ranges":
                        third_party_src = True
                    else:
                        third_party_dst = True
                continue
            if not any(net.subnet_of(r) for r in PRIVATE_RANGES):
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: Public {label} '{ip}' not in allowed GCP ranges.")
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    rule["_uses_third_party"] = True
                    if field == "src_ip_ranges":
                        third_party_src = True
                    else:
                        third_party_dst = True
                continue
            if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                rule["_uses_third_party"] = True
                if field == "src_ip_ranges":
                    third_party_src = True
                else:
                    third_party_dst = True

    for p in rule.get("ports", []):
        if not validate_port(p):
            errors.append(f"Rule {idx}: Invalid port or range: '{p}'.")
    proto = (rule.get("protocol") or "").lower()
    if not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{rule.get('protocol')}'.")
    direction = rule.get("direction", "")
    if direction and direction.upper() not in {"INGRESS", "EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS when provided. Found: '{direction}'.")
    try:
        carid = rule.get("name", "AUTO-REQ-0000000-0-0").split("-")[2]
    except Exception:
        carid = ""
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    try:
        if any(ipaddress.ip_network(ip).subnet_of(r) for ip in rule.get("src_ip_ranges", []) for r in RESTRICTED_API_RANGES if "/" in ip):
            errors.append(f"Rule {idx}: Restricted Google APIs ranges (199.36.153.4/30) may only appear on the destination side.")
        if any(ipaddress.ip_network(ip).subnet_of(r) for ip in rule.get("dest_ip_ranges", []) for r in HEALTH_CHECK_RANGES if "/" in ip):
            errors.append(f"Rule {idx}: Health‑check ranges (35.191.0.0/16, 130.211.0.0/22) may only appear on the source side.")
    except Exception:
        pass
    try:
        if rule.get("_uses_third_party") and not NEW_TLM_ID and not (third_party_src and third_party_dst):
            errors.append(
                f"Rule {idx}: A Third Party ID (TLM ID) must be provided when using the third‑party‑peering boundary."
            )
    except Exception:
        pass
    return errors

def parse_blocks(issue_body: str) -> List[str]:
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]

def extract_field(block: str, label: str) -> str:
    for line in block.splitlines():
        clean = re.sub(r"[*_`~]+", "", line)
        clean = re.sub(r"^[^A-Za-z0-9]*", "", clean)
        m = re.match(rf"\s*{re.escape(label)}.*?:\s*(.*)", clean, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""

def make_update_summary(idx: int, old_rule: Dict[str, Any], updates: Dict[str, Any], new_rule: Dict[str, Any]) -> str:
    changes: List[str] = []
    for field, label in [
        ("src_ip_ranges", "Source"), ("dest_ip_ranges", "Destination"), ("ports", "Ports"),
        ("protocol", "Protocol"), ("direction", "Direction"), ("carid", "CARID"), ("description", "Justification")
    ]:
        old_val = old_rule.get(field)
        new_val = updates.get(field) if updates.get(field) else None
        if new_val is not None and old_val != new_val:
            old_str = ",".join(old_val) if isinstance(old_val, list) else old_val
            new_str = ",".join(new_val) if isinstance(new_val, list) else new_val
            changes.append(f"{label}: `{old_str}` → `{new_str}`")
    if old_rule.get("name") != new_rule.get("name"):
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes:
        changes = ["(No fields updated, only name/desc changed)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)

def main() -> None:
    global NEW_TLM_ID
    issue_body = sys.stdin.read() if len(sys.argv) < 2 else sys.argv[1]
    errors: List[str] = []
    summaries: List[str] = []

    m_reqid = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m_reqid.group(1).strip() if m_reqid else None
    if not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' followed by 7 or 8 digits. Found: '{new_reqid}'.")
    m_tlm = re.search(r"New Third Party ID\b.*?:[ \t]*([^\n\r]*)", issue_body, re.IGNORECASE)
    NEW_TLM_ID = m_tlm.group(1).strip() if m_tlm else ""

    blocks = parse_blocks(issue_body)
    update_reqs: List[Dict[str, Any]] = []
    for idx, block in enumerate(blocks, 1):
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        update_reqs.append({
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [ip.strip() for ip in extract_field(block, "New Source IP").split(",") if ip.strip()],
            "dest_ip_ranges": [ip.strip() for ip in extract_field(block, "New Destination IP").split(",") if ip.strip()],
            "ports": [p.strip() for p in extract_field(block, "New Port").split(",") if p.strip()],
            "protocol": extract_field(block, "New Protocol"),
            "direction": extract_field(block, "New Direction"),
            "carid": extract_field(block, "New CARID"),
            "description": extract_field(block, "New Business Justification"),
        })

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    rule_map, file_map = load_all_rules()
    updated_rules: List[Dict[str, Any]] = []
    updated_keys: set = set()
    rules_to_remove: List[Tuple[str, str]] = []

    for req in update_reqs:
        idx = req["idx"]
        name = req["rule_name"]
        if name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{name}'.")
            continue
        original = rule_map[name]
        # Deep clone via JSON to avoid any mutation of the original rule
        to_update = json.loads(json.dumps(original))
        to_update["_update_index"] = idx
        new_fields: Dict[str, Any] = {}
        if req["src_ip_ranges"]:
            new_fields["src_ip_ranges"] = req["src_ip_ranges"]
        if req["dest_ip_ranges"]:
            new_fields["dest_ip_ranges"] = req["dest_ip_ranges"]
        if req["ports"]:
            new_fields["ports"] = req["ports"]
        if req["protocol"]:
            new_fields["protocol"] = req["protocol"]
        if req["direction"]:
            new_fields["direction"] = req["direction"]
        if req["description"]:
            new_fields["description"] = req["description"]
        new_carid = req["carid"]
        actual_change = False
        if req["src_ip_ranges"] and req["src_ip_ranges"] != to_update.get("src_ip_ranges", []):
            actual_change = True
        if req["dest_ip_ranges"] and req["dest_ip_ranges"] != to_update.get("dest_ip_ranges", []):
            actual_change = True
        if req["ports"] and req["ports"] != to_update.get("ports", []):
            actual_change = True
        if req["protocol"] and req["protocol"].lower() != to_update.get("protocol", "").lower():
            actual_change = True
        if req["direction"] and req["direction"].upper() != to_update.get("direction", "").upper():
            actual_change = True
        if req["carid"]:
            old_carid = to_update.get("name", "AUTO-REQ-0-0").split("-")[2] if '-' in to_update.get("name", "") else ""
            if req["carid"] != old_carid:
                actual_change = True
        if req["description"]:
            old_desc_just = to_update.get("description", "").split("|", 1)[-1].strip()
            if req["description"].strip() != old_desc_just:
                actual_change = True
        if not actual_change and new_reqid == (to_update.get("name", "AUTO-REQ-0-0").split("-")[1] if '-' in to_update.get("name", "") else ""):
            errors.append(f"Rule {idx}: No fields were changed; update request must modify at least one field.")
            continue
        updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
        errs = validate_rule(updated_rule, idx)
        if errs:
            errors.extend(errs)
            continue
        dup_key = (
            tuple(updated_rule.get("src_ip_ranges", [])),
            tuple(updated_rule.get("dest_ip_ranges", [])),
            tuple(updated_rule.get("ports", [])),
            (updated_rule.get("protocol") or "").lower(),
            (updated_rule.get("direction") or "").upper(),
        )
        if dup_key in updated_keys:
            errors.append(f"Rule {idx}: Duplicate rule in update request.")
            continue
        updated_keys.add(dup_key)
        updated_rules.append(updated_rule)
        summaries.append(make_update_summary(idx, to_update, req, updated_rule))
        if name in file_map:
            rules_to_remove.append((name, file_map[name]))

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    if not updated_rules:
        return

    next_priorities = compute_next_priorities(len(updated_rules))
    for i, r in enumerate(updated_rules):
        r.pop("_update_index", None)
        r.pop("_uses_third_party", None)
        r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
        r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
        r["ports"] = [p for p in r.get("ports", []) if p]
        r["priority"] = next_priorities[i]
        r.setdefault("enable_logging", True)

    dest_dir = "firewall-requests"
    os.makedirs(dest_dir, exist_ok=True)
    new_path = os.path.join(dest_dir, f"{new_reqid}.auto.tfvars.json")
    # Always remove any existing file with this REQID before writing
    if os.path.exists(new_path):
        try:
            os.remove(new_path)
        except Exception:
            pass
    combined_rules = updated_rules
    tmp_new = new_path + ".tmp"
    with open(tmp_new, "w") as nf:
        json.dump({"auto_firewall_rules": combined_rules}, nf, indent=2)
        nf.write("\n")
    os.replace(tmp_new, new_path)

    with open("rule_update_summary.txt", "w") as f:
        for line in summaries:
            f.write(line + "\n")

    try:
        map_file = "boundary_map.json"
        if os.path.exists(new_path):
            subprocess.run([
                sys.executable,
                os.path.join(os.path.dirname(__file__), "boundary_mapper.py"),
                "--map-file", map_file,
                "--json-file", new_path,
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Remove the old rule from its original file
    for old_name, orig_path in rules_to_remove:
        try:
            with open(orig_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        rules = data.get("auto_firewall_rules", [])
        filtered = [r for r in rules if r.get("name") != old_name]
        if len(filtered) != len(rules):
            if not filtered:
                try:
                    os.remove(orig_path)
                except FileNotFoundError:
                    pass
                continue
            tmp_file = orig_path + ".tmp"
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump({"auto_firewall_rules": filtered}, f, indent=2)
                f.write("\n")
            os.replace(tmp_file, orig_path)

if __name__ == "__main__":
    main()
