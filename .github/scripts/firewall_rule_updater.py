#!/usr/bin/env python3
"""
Firewall Rule Updater
---------------------

This script processes firewall rule **update** requests.  It reads the
issue body, locates the existing rule(s) by name, applies user‑supplied
changes, and writes the updated rules back to their JSON file(s) under
`firewall-requests/`.  If the new Request ID (REQID) provided in the
issue differs from the original rule’s REQID, the script will remove
the updated rule from its current file and append it to a new
`firewall-requests/REQ<newid>.auto.tfvars.json`.  Otherwise, it updates
the rule in place.

Before writing anything to disk the script validates input values (IP
ranges, ports, protocol, direction, CARID).  If any requested change
would leave a rule exactly the same as before and the REQIDs match,
that update is rejected so that no–op requests do not result in
unnecessary pull requests.

After writing files the script runs `boundary_mapper.py` on each
changed file to recompute `src_vpc` and `dest_vpc` fields based on the
updated IP ranges.

Usage:
    python3 firewall_rule_updater.py "<issue body>"
    cat issue.txt | python3 firewall_rule_updater.py
"""

import re
import sys
import os
import glob
import json
import ipaddress
from typing import Dict, List, Tuple, Any

# Allowed oversized public ranges for /24 CIDR exceptions
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
    ipaddress.ip_network("199.36.153.4/30"),
]

# Ranges used to infer direction for certain GCP services.  When all
# source IPs fall within HEALTH_CHECK_RANGES, the rule should be
# treated as inbound only (INGRESS).  When all destination IPs fall
# within RESTRICTED_API_RANGES, the rule should be treated as
# outbound only (EGRESS).  These lists mirror those used in
# boundary_mapper.py and the request validator.
HEALTH_CHECK_RANGES: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
]
RESTRICTED_API_RANGES: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("199.36.153.4/30"),
]

def ranges_in_list(ranges: List[str], allowed: List[ipaddress.IPv4Network]) -> bool:
    """Return True if every CIDR in `ranges` is a subnet of some CIDR in `allowed`."""
    for ip_str in ranges:
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        net = ipaddress.ip_network(ip_str, strict=False)
        if not any(net.subnet_of(a) for a in allowed):
            return False
    return True

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
    """Load all rules from firewall-requests and return name->rule and name->file maps."""
    rule_map: Dict[str, Dict[str, Any]] = {}
    file_map: Dict[str, str] = {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            data = json.load(open(path))
        except Exception:
            continue
        for rule in data.get("auto_firewall_rules", []):
            name = rule.get("name")
            if name:
                rule_map[name] = rule
                file_map[name] = path
    return rule_map, file_map

def update_rule_fields(rule: Dict[str, Any], updates: Dict[str, Any], new_reqid: str, new_carid: str) -> Dict[str, Any]:
    """Apply user updates to the rule and regenerate its name/description."""
    updated = rule.copy()
    idx = updated.get("_update_index", 1)
    # Determine protocol and ports (fall back to existing)
    proto = updates.get("protocol") or updated.get("protocol", "tcp")
    ports = updates.get("ports") or updated.get("ports", [])
    # Determine CARID for name
    carid = new_carid or updated.get("name", "AUTO-REQ-0-0").split("-")[2]
    # Regenerate rule name
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    updated["name"] = new_name
    # Apply field updates
    for key, value in updates.items():
        if value:
            updated[key] = value.lower() if key in {"protocol", "direction"} else value
    # Update description using new name and provided justification or existing suffix
    desc_just = updates.get("description") or updated.get("description", "").split("|", 1)[-1]
    updated["description"] = f"{new_name} | {desc_just.strip()}"
    return updated

def validate_rule(rule: Dict[str, Any], idx: int) -> List[str]:
    """Validate a single firewall rule and return a list of error strings."""
    errors: List[str] = []
    # IP/CIDR validations
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
            # Disallow 0.0.0.0/0
            if net == ipaddress.ip_network("0.0.0.0/0"):
                errors.append(f"Rule {idx}: {label} may not be 0.0.0.0/0.")
                continue
            # Oversized CIDR must be in allowed ranges
            if net.prefixlen < 24:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: {label} '{ip}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range.")
                continue
            # Public ranges must be allowed
            if not net.is_private:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: Public {label} '{ip}' not in allowed GCP ranges.")
                continue
    # Ports
    for p in rule.get("ports", []):
        if not validate_port(p):
            errors.append(f"Rule {idx}: Invalid port or range: '{p}'.")
    # Protocol
    proto = rule.get("protocol", "").lower()
    if not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{rule.get('protocol')}'.")
    # Direction
    direction = rule.get("direction", "")
    if direction and direction.upper() not in {"INGRESS", "EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS when provided. Found: '{direction}'.")
    # CARID in name
    try:
        carid = rule.get("name", "AUTO-REQ-0000000-0-0").split("-")[2]
    except Exception:
        carid = ""
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    return errors

def parse_blocks(issue_body: str) -> List[str]:
    """Split the issue body into separate rule blocks."""
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]

def extract_field(block: str, label: str) -> str:
    m = re.search(rf"{re.escape(label)}.*?:\s*(.+)", block, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def make_update_summary(idx: int, old_rule: Dict[str, Any], updates: Dict[str, Any], new_rule: Dict[str, Any]) -> str:
    """Generate a human readable summary of changes for a single rule."""
    changes: List[str] = []
    fields = [
        ("src_ip_ranges", "Source"),
        ("dest_ip_ranges", "Destination"),
        ("ports", "Ports"),
        ("protocol", "Protocol"),
        ("direction", "Direction"),
        ("carid", "CARID"),
        ("description", "Justification"),
    ]
    for field, label in fields:
        old_val = old_rule.get(field)
        new_val = updates.get(field) if updates.get(field) else None
        if new_val is not None and old_val != new_val:
            old_str = ','.join(old_val) if isinstance(old_val, list) else old_val
            new_str = ','.join(new_val) if isinstance(new_val, list) else new_val
            changes.append(f"{label}: `{old_str}` → `{new_str}`")
    if old_rule.get("name") != new_rule.get("name"):
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes:
        changes = ["(No fields updated, only name/desc changed)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)

def main():
    # Read issue body from argument or stdin
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()
    errors: List[str] = []
    summaries: List[str] = []
    # Extract new REQID
    m_reqid = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m_reqid.group(1).strip() if m_reqid else None
    if not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' followed by 7 or 8 digits. Found: '{new_reqid}'.")
    # Split into rule blocks
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
    # If parse-level errors, report and exit
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)
    # Load existing rules
    rule_map, file_map = load_all_rules()
    # Stage updates per file
    files_to_update: Dict[str, Tuple[List[Dict[str, Any]], List[Tuple[str, Dict[str, Any]]]]] = {}
    for req in update_reqs:
        idx = req["idx"]
        name = req["rule_name"]
        if name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{name}'.")
            continue
        file = file_map[name]
        remaining, updated_list = files_to_update.get(file, ([], []))
        # Load file rules if not already loaded
        if not remaining and not updated_list:
            with open(file) as f:
                data = json.load(f)
            remaining.extend(data.get("auto_firewall_rules", []))
        # Copy original rule and mark its index in file for name regeneration
        to_update = rule_map[name].copy()
        try:
            idx_in_file = [r.get("name") for r in remaining].index(name) + 1
        except ValueError:
            idx_in_file = 1
        to_update["_update_index"] = idx_in_file
        # Build new_fields dict from non-empty values
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
        # Capture old request ID and CARID from the original rule name
        parts = to_update["name"].split("-")
        old_id = parts[1] if len(parts) > 1 else ""
        old_carid = parts[2] if len(parts) > 2 else ""
        # Determine if any actual field (other than REQID) changes
        fields_changed = False
        # Compare IP ranges
        if "src_ip_ranges" in new_fields and new_fields["src_ip_ranges"] != to_update.get("src_ip_ranges", []):
            fields_changed = True
        elif "dest_ip_ranges" in new_fields and new_fields["dest_ip_ranges"] != to_update.get("dest_ip_ranges", []):
            fields_changed = True
        elif "ports" in new_fields and new_fields["ports"] != to_update.get("ports", []):
            fields_changed = True
        elif "protocol" in new_fields and new_fields["protocol"].lower() != to_update.get("protocol", "").lower():
            fields_changed = True
        elif "direction" in new_fields and new_fields["direction"].upper() != to_update.get("direction", "").upper():
            fields_changed = True
        elif "description" in new_fields:
            # Compare justification by stripping description suffix
            existing_desc = to_update.get("description", "").split("|", 1)
            existing_just = existing_desc[1].strip() if len(existing_desc) > 1 else ""
            if new_fields["description"].strip() != existing_just:
                fields_changed = True
        # Also consider CARID change
        if new_carid and new_carid != old_carid:
            fields_changed = True
        # Reject no-op update when REQID does not change and no fields change
        if not fields_changed and new_reqid == old_id:
            errors.append(f"Rule {idx}: No fields were changed; update request must modify at least one field.")
            files_to_update[file] = (remaining, updated_list)
            continue
        # ---------------------------------------------------------------------
        # Infer direction for health‑check and restricted‑API ranges
        # If the user did not supply a new direction (req["direction"] is empty)
        # we may override direction based on the effective source/dest ranges.
        if not req.get("direction"):
            # Determine the effective src/dst ranges after applying updates.  If
            # new ranges were provided, use them; otherwise use the current
            # rule values from to_update.
            eff_src = new_fields.get("src_ip_ranges", to_update.get("src_ip_ranges", []))
            eff_dst = new_fields.get("dest_ip_ranges", to_update.get("dest_ip_ranges", []))
            # If all source ranges are in the health check ranges, mark as INGRESS
            if eff_src and ranges_in_list(eff_src, HEALTH_CHECK_RANGES):
                new_fields["direction"] = "INGRESS"
            # Else if all destination ranges are in the restricted API ranges, mark as EGRESS
            elif eff_dst and ranges_in_list(eff_dst, RESTRICTED_API_RANGES):
                new_fields["direction"] = "EGRESS"
        # Generate updated rule and validate
        updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
        errs = validate_rule(updated_rule, idx)
        if errs:
            errors.extend(errs)
        else:
            updated_list.append((old_id, updated_rule))
            summaries.append(make_update_summary(idx, to_update, req, updated_rule))
        files_to_update[file] = (remaining, updated_list)
    # Abort on validation errors
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)
    # Apply modifications per file
    changed_files: set = set()
    for file, (remaining_rules, updated_rules) in files_to_update.items():
        # Determine rules not updated
        updated_names = {req["rule_name"] for req in update_reqs}
        orig_remaining = [r for r in remaining_rules if r.get("name") not in updated_names]
        in_place_updates: List[Dict[str, Any]] = []
        to_move_updates: List[Dict[str, Any]] = []
        for old_id_val, upd_rule in updated_rules:
            # Clean helper and empty entries
            r = upd_rule.copy()
            r.pop("_update_index", None)
            r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
            r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
            r["ports"] = [p for p in r.get("ports", []) if p]
            if old_id_val == new_reqid:
                in_place_updates.append(r)
            else:
                to_move_updates.append(r)
        # Write back original file with remaining and in-place updates
        combined = []
        for r in orig_remaining:
            rr = r.copy()
            rr.pop("_update_index", None)
            rr["src_ip_ranges"] = [ip for ip in rr.get("src_ip_ranges", []) if ip]
            rr["dest_ip_ranges"] = [ip for ip in rr.get("dest_ip_ranges", []) if ip]
            rr["ports"] = [p for p in rr.get("ports", []) if p]
            combined.append(rr)
        combined.extend(in_place_updates)
        if combined:
            tmp_path = file + ".tmp"
            with open(tmp_path, "w") as outf:
                json.dump({"auto_firewall_rules": combined}, outf, indent=2)
                outf.write("\n")
            os.replace(tmp_path, file)
            changed_files.add(file)
        else:
            # Remove file if no rules remain
            if os.path.exists(file):
                os.remove(file)
                changed_files.add(file)
        # Write moved updates to new file if needed
        if to_move_updates:
            dirpath = os.path.dirname(file)
            new_filename = f"{new_reqid}.auto.tfvars.json"
            new_path = os.path.join(dirpath, new_filename)
            existing_rules: List[Dict[str, Any]] = []
            if os.path.exists(new_path):
                try:
                    existing_rules = json.load(open(new_path)).get("auto_firewall_rules", [])
                except Exception:
                    existing_rules = []
            existing_rules.extend(to_move_updates)
            tmp_new = new_path + ".tmp"
            with open(tmp_new, "w") as nf:
                json.dump({"auto_firewall_rules": existing_rules}, nf, indent=2)
                nf.write("\n")
            os.replace(tmp_new, new_path)
            changed_files.add(new_path)
    # Write summary file
    with open("rule_update_summary.txt", "w") as f:
        for line in summaries:
            f.write(line + "\n")
    # Invoke boundary mapper on changed files
    if changed_files:
        try:
            import subprocess
            map_file = "boundary_map.json"
            for fp in changed_files:
                if os.path.exists(fp):
                    subprocess.run([
                        sys.executable,
                        os.path.join(".github", "scripts", "boundary_mapper.py"),
                        "--map-file", map_file,
                        "--json-file", fp,
                    ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

if __name__ == "__main__":
    main()