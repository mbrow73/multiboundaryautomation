#!/usr/bin/env python3
import re
import sys
import os
import glob
import json
import ipaddress
from typing import Dict, List, Tuple, Any

# Allowed public ranges
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

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Third‑party CIDRs
THIRD_PARTY_PEERING_RANGES = [
    ipaddress.ip_network("10.150.1.0/24"),
]

NEW_TLM_ID = ""

def validate_reqid(reqid: str) -> bool:
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid or ""))

def validate_carid(carid: str) -> bool:
    return bool(re.fullmatch(r"\d{9}", carid or ""))

def validate_ip(ip: str) -> bool:
    try:
        if "/" in ip: ipaddress.ip_network(ip, strict=False)
        else: ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def validate_port(port: str) -> bool:
    if re.fullmatch(r"\d{1,5}", port or ""):
        n = int(port); return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port or ""):
        a, b = map(int, port.split("-")); return 1 <= a <= b <= 65535
    return False

def validate_protocol(proto: str) -> bool:
    return proto.lower() in {"tcp","udp","icmp","sctp"}

def load_all_rules() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    rule_map, file_map = {}, {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        with open(path) as f: data = json.load(f)
        for rule in data.get("auto_firewall_rules", []):
            name = rule.get("name")
            if name:
                rule_map[name] = rule
                file_map[name] = path
    return rule_map, file_map

def update_rule_fields(rule: Dict[str, Any], updates: Dict[str, Any], new_reqid: str, new_carid: str) -> Dict[str, Any]:
    updated = rule.copy()
    idx = updated.get("_update_index", 1)
    proto = updates.get("protocol") or updated.get("protocol", "tcp")
    ports = updates.get("ports") or updated.get("ports", [])
    carid = new_carid or updated.get("name", "AUTO-REQ-0-0").split("-")[2]
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    updated["name"] = new_name
    for key, value in updates.items():
        if value:
            updated[key] = value.lower() if key in {"protocol","direction"} else value
    desc_just = updates.get("description") or updated.get("description", "").split("|", 1)[-1]
    updated["description"] = f"{new_name} | {desc_just.strip()}"
    return updated

def validate_rule(rule: Dict[str, Any], idx: int) -> List[str]:
    errors = []
    for field in ["src_ip_ranges","dest_ip_ranges"]:
        label = "Source" if field=="src_ip_ranges" else "Destination"
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
                continue
            if not any(net.subnet_of(r) for r in PRIVATE_RANGES):
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: Public {label} '{ip}' not in allowed GCP ranges.")
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    rule["_uses_third_party"] = True
                continue
            if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                rule["_uses_third_party"] = True

    for p in rule.get("ports", []):
        if not validate_port(p):
            errors.append(f"Rule {idx}: Invalid port or range: '{p}'.")
    proto = rule.get("protocol","").lower()
    if not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{rule.get('protocol')}'.")
    direction = rule.get("direction","")
    if direction and direction.upper() not in {"INGRESS","EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS when provided. Found: '{direction}'.")
    try:
        carid = rule.get("name", "AUTO-REQ-0000000-0-0").split("-")[2]
    except Exception:
        carid = ""
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    try:
        if any(ipaddress.ip_network(ip).subnet_of(r) for ip in rule.get("src_ip_ranges",[]) for r in RESTRICTED_API_RANGES if "/" in ip):
            errors.append(f"Rule {idx}: Restricted Google APIs ranges (199.36.153.4/30) may only appear on the destination side.")
        if any(ipaddress.ip_network(ip).subnet_of(r) for ip in rule.get("dest_ip_ranges",[]) for r in HEALTH_CHECK_RANGES if "/" in ip):
            errors.append(f"Rule {idx}: Health‑check ranges (35.191.0.0/16, 130.211.0.0/22) may only appear on the source side.")
    except Exception:
        pass
    try:
        if rule.get("_uses_third_party") and not NEW_TLM_ID:
            errors.append(f"Rule {idx}: A Third Party ID (TLM ID) must be provided when using the third‑party‑peering boundary.")
    except Exception:
        pass
    return errors

def parse_blocks(issue_body: str) -> List[str]:
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]

def extract_field(block: str, label: str) -> str:
    m = re.search(rf"{re.escape(label)}.*?:\s*(.+)", block, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def make_update_summary(idx: int, old_rule: Dict[str, Any], updates: Dict[str, Any], new_rule: Dict[str, Any]) -> str:
    changes = []
    for field,label in [
        ("src_ip_ranges","Source"),("dest_ip_ranges","Destination"),("ports","Ports"),
        ("protocol","Protocol"),("direction","Direction"),("carid","CARID"),("description","Justification")]:
        old_val = old_rule.get(field)
        new_val = updates.get(field) if updates.get(field) else None
        if new_val is not None and old_val != new_val:
            old_str = ','.join(old_val) if isinstance(old_val,list) else old_val
            new_str = ','.join(new_val) if isinstance(new_val,list) else new_val
            changes.append(f"{label}: `{old_str}` → `{new_str}`")
    if old_rule.get("name") != new_rule.get("name"):
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes: changes = ["(No fields updated, only name/desc changed)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)

def main():
    global NEW_TLM_ID
    issue_body = sys.stdin.read() if len(sys.argv) < 2 else sys.argv[1]
    errors, summaries = [], []

    m_reqid = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m_reqid.group(1).strip() if m_reqid else None
    if not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' followed by 7 or 8 digits. Found: '{new_reqid}'.")
    m_tlm = re.search(r"New Third Party ID\b.*?:\s*(.*)", issue_body, re.IGNORECASE)
    NEW_TLM_ID = m_tlm.group(1).strip() if m_tlm else ""

    blocks = parse_blocks(issue_body)
    update_reqs = []
    for idx, block in enumerate(blocks, 1):
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        update_reqs.append({
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [ip.strip() for ip in extract_field(block,"New Source IP").split(",") if ip.strip()],
            "dest_ip_ranges": [ip.strip() for ip in extract_field(block,"New Destination IP").split(",") if ip.strip()],
            "ports": [p.strip() for p in extract_field(block,"New Port").split(",") if p.strip()],
            "protocol": extract_field(block,"New Protocol"),
            "direction": extract_field(block,"New Direction"),
            "carid": extract_field(block,"New CARID"),
            "description": extract_field(block,"New Business Justification"),
        })

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors: print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    rule_map, file_map = load_all_rules()
    files_to_update: Dict[str, Tuple[List[Dict[str, Any]], List[Tuple[str, Dict[str, Any]]]]] = {}
    for req in update_reqs:
        idx = req["idx"]
        name = req["rule_name"]
        if name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{name}'.")
            continue
        file = file_map[name]
        remaining, updated_list = files_to_update.get(file, ([], []))
        if not remaining and not updated_list:
            with open(file) as f: data = json.load(f)
            for r in data.get("auto_firewall_rules", []): remaining.append(r)
        to_update = rule_map[name].copy()
        try: idx_in_file = [r.get("name") for r in remaining].index(name) + 1
        except ValueError: idx_in_file = 1
        to_update["_update_index"] = idx_in_file

        new_fields: Dict[str, Any] = {}
        if req["src_ip_ranges"]: new_fields["src_ip_ranges"] = req["src_ip_ranges"]
        if req["dest_ip_ranges"]: new_fields["dest_ip_ranges"] = req["dest_ip_ranges"]
        if req["ports"]: new_fields["ports"] = req["ports"]
        if req["protocol"]: new_fields["protocol"] = req["protocol"]
        if req["direction"]: new_fields["direction"] = req["direction"]
        if req["description"]: new_fields["description"] = req["description"]
        new_carid = req["carid"]

        parts = to_update["name"].split("-")
        old_id = parts[1] if len(parts) > 1 else ""
        actual_change = False
        if req["src_ip_ranges"] and req["src_ip_ranges"] != to_update.get("src_ip_ranges", []): actual_change = True
        if req["dest_ip_ranges"] and req["dest_ip_ranges"] != to_update.get("dest_ip_ranges", []): actual_change = True
        if req["ports"] and req["ports"] != to_update.get("ports", []): actual_change = True
        if req["protocol"] and req["protocol"].lower() != to_update.get("protocol", "").lower(): actual_change = True
        if req["direction"] and req["direction"].upper() != to_update.get("direction", "").upper(): actual_change = True
        if req["carid"]:
            old_carid = to_update.get("name","AUTO-REQ-0-0").split("-")[2] if '-' in to_update.get("name","") else ""
            if req["carid"] != old_carid: actual_change = True
        if req["description"]:
            old_desc_just = to_update.get("description","").split("|",1)[-1].strip()
            if req["description"].strip() != old_desc_just: actual_change = True
        if not actual_change and new_reqid == old_id:
            errors.append(f"Rule {idx}: No fields were changed; update request must modify at least one field.")
            files_to_update[file] = (remaining, updated_list)
            continue

        updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
        errs = validate_rule(updated_rule, idx)
        if errs: errors.extend(errs)
        else:
            updated_list.append((old_id, updated_rule))
            summaries.append(make_update_summary(idx, to_update, req, updated_rule))
        files_to_update[file] = (remaining, updated_list)

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors: print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    changed_files = set()
    for file,(remaining_rules,updated_rules) in files_to_update.items():
        updated_names = {req["rule_name"] for req in update_reqs}
        orig_remaining = [r for r in remaining_rules if r.get("name") not in updated_names]
        in_place_updates, to_move_updates = [], []
        for old_id, upd_rule in updated_rules:
            r = upd_rule.copy()
            r.pop("_update_index", None)
            r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges",[]) if ip]
            r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges",[]) if ip]
            r["ports"] = [p for p in r.get("ports",[]) if p]
            (in_place_updates if old_id == new_reqid else to_move_updates).append(r)
        combined = [dict(rr, src_ip_ranges=[ip for ip in rr.get("src_ip_ranges",[]) if ip], dest_ip_ranges=[ip for ip in rr.get("dest_ip_ranges",[]) if ip], ports=[p for p in rr.get("ports",[]) if p]) for rr in orig_remaining]
        combined.extend(in_place_updates)
        if combined:
            tmp = file + ".tmp"
            with open(tmp,"w") as outf:
                json.dump({"auto_firewall_rules": combined},outf,indent=2); outf.write("\n")
            os.replace(tmp,file); changed_files.add(file)
        else:
            if os.path.exists(file): os.remove(file); changed_files.add(file)
        if to_move_updates:
            dirpath = os.path.dirname(file)
            new_name = f"{new_reqid}.auto.tfvars.json"
            new_path = os.path.join(dirpath,new_name)
            existing_rules = []
            if os.path.exists(new_path):
                with open(new_path) as nf:
                    try: existing_rules = json.load(nf).get("auto_firewall_rules",[])
                    except Exception: existing_rules = []
            existing_rules.extend(to_move_updates)
            tmp_new = new_path + ".tmp"
            with open(tmp_new,"w") as nf:
                json.dump({"auto_firewall_rules": existing_rules},nf,indent=2); nf.write("\n")
            os.replace(tmp_new,new_path); changed_files.add(new_path)

    with open("rule_update_summary.txt","w") as f:
        for line in summaries: f.write(line + "\n")

    if changed_files:
        try:
            import subprocess
            map_file = "boundary_map.json"
            for fp in changed_files:
                if os.path.exists(fp):
                    subprocess.run([sys.executable, os.path.join(".github","scripts","boundary_mapper.py"), "--map-file", map_file, "--json-file", fp], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

if __name__ == "__main__":
    main()
