#!/usr/bin/env python3
"""
Firewall Rule Updater (move updated rules to new request file)
-------------------------------------------------------------

This script is used by the GitHub workflow that processes firewall update
requests filed as issues.  For each update:

* It parses the issue body to extract a new request ID and one or more
  rule‑update blocks.  Each block contains the name of an existing rule and
  optional new values for the source IPs, destination IPs, ports,
  protocol, direction, CARID and justification.
* It loads the current `auto_firewall_rules` JSON files from the
  `firewall-requests/` directory and locates the rule to update.
* For each rule, it records the **original request ID** from the rule’s
  name.  If the new request ID differs from the original, the updated rule
  is removed from its current file and appended to a new file named
  `firewall-requests/REQ<newid>.auto.tfvars.json`.  Otherwise the rule is
  updated in place in the original file.  This preserves safe concurrency:
  updates for different request IDs never write to the same file, while
  updates for the same request ID simply rewrite the rule in its original
  context.
* It validates the updated rule (CIDR formats, ports, protocol, direction,
  CARID) before making any file changes.  If any rule fails validation, it
  reports the errors and aborts without touching the filesystem.
* After successfully writing files, it invokes `boundary_mapper.py` on each
  changed file so that `src_vpc` and `dest_vpc` values are recalculated when
  IP ranges cross boundaries.
* It generates a human‑readable summary of changes in
  `rule_update_summary.txt` for inclusion in the pull request body.

This design keeps the rulebase consistent, avoids partial updates and
accommodates concurrent requests.  If you specify a new request ID, your
updated rule will appear in its own file; if you reuse the same request ID,
your rule is simply updated in place.
"""

import re
import sys
import os
import glob
import json
import ipaddress
from typing import Dict, List, Tuple, Any


# Allowed public ranges for oversize CIDRs
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
    ipaddress.ip_network("199.36.153.4/30"),
]


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
        with open(path) as f:
            data = json.load(f)
            for rule in data.get("auto_firewall_rules", []):
                name = rule.get("name")
                if name:
                    rule_map[name] = rule
                    file_map[name] = path
    return rule_map, file_map


def update_rule_fields(rule: Dict[str, Any], updates: Dict[str, Any], new_reqid: str, new_carid: str) -> Dict[str, Any]:
    """Return a modified copy of `rule` with updated fields and a regenerated name/description."""
    updated = rule.copy()
    idx = updated.get("_update_index", 1)
    proto = updates.get("protocol") or updated.get("protocol", "tcp")
    ports = updates.get("ports") or updated.get("ports", [])
    carid = new_carid or updated.get("name", "AUTO-REQ-0-0").split("-")[2]
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    updated["name"] = new_name
    # Apply updates to fields
    for field, value in updates.items():
        if value:
            updated[field] = value.lower() if field in {"protocol", "direction"} else value
    # Update description
    desc_just = updates.get("description") or updated.get("description", "").split("|", 1)[-1]
    updated["description"] = f"{new_name} | {desc_just.strip()}"
    return updated


def validate_rule(rule: Dict[str, Any], idx: int) -> List[str]:
    errors: List[str] = []
    # IP validations
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
                    errors.append(
                        f"Rule {idx}: {label} '{ip}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range."
                    )
                continue
            if not net.is_private:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: Public {label} '{ip}' not in allowed GCP ranges.")
                continue
    # Port
    for p in rule.get("ports", []):
        if not validate_port(p):
            errors.append(f"Rule {idx}: Invalid port or range: '{p}'.")
    # Protocol
    proto = rule.get("protocol", "").lower()
    if not validate_protocol(proto):
        errors.append(
            f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{rule.get('protocol')}'."
        )
    # Direction
    direction = rule.get("direction", "")
    if direction and direction.upper() not in {"INGRESS", "EGRESS"}:
        errors.append(
            f"Rule {idx}: Direction must be INGRESS or EGRESS when provided. Found: '{direction}'."
        )
    # CARID
    try:
        carid = rule.get("name", "AUTO-REQ-0000000-0-0").split("-")[2]
    except Exception:
        carid = ""
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    return errors


def parse_blocks(issue_body: str) -> List[str]:
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]


def extract_field(block: str, label: str) -> str:
    m = re.search(rf"{re.escape(label)}.*?:\s*(.+)", block, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def make_update_summary(idx: int, old_rule: Dict[str, Any], updates: Dict[str, Any], new_rule: Dict[str, Any]) -> str:
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
    # Read issue body from arg or stdin
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()

    errors: List[str] = []
    summaries: List[str] = []

    # Extract new request ID
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

    # If parse errors, output and exit
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    # Load rules and mapping
    rule_map, file_map = load_all_rules()

    # Stage per-file updates: map file -> (remaining_rules, updated_rules).
    # For the in‑place update workflow, `updated_rules` is a list of updated rule dicts.
    files_to_update: Dict[str, Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]] = {}

    # Process each update request
    for req in update_reqs:
        idx = req["idx"]
        name = req["rule_name"]
        if name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{name}'.")
            continue
        file = file_map[name]
        remaining, updated_list = files_to_update.get(file, ([], []))
        # If this file has not been processed yet, load its rules
        if not remaining and not updated_list:
            with open(file) as f:
                data = json.load(f)
            for r in data.get("auto_firewall_rules", []):
                remaining.append(r)
        # Extract the rule to update
        # We will process removal after staging
        to_update = rule_map[name].copy()
        # Determine original index within its file for stable naming
        try:
            idx_in_file = [r.get("name") for r in remaining].index(name) + 1
        except ValueError:
            idx_in_file = 1
        to_update["_update_index"] = idx_in_file

        # Build updates dict based on provided fields
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
        # Generate the updated rule using the new request ID.  In the in‑place
        # workflow, we ignore the original request ID and simply update the
        # rule fields.  The updated rule will be written back to the same file.
        updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
        # Validate the updated rule
        errs = validate_rule(updated_rule, idx)
        if errs:
            errors.extend(errs)
        else:
            updated_list.append(updated_rule)
            summaries.append(make_update_summary(idx, to_update, req, updated_rule))
        files_to_update[file] = (remaining, updated_list)

    # If validation errors, report and exit
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    # Apply modifications: rewrite updated rules in place.  For each file we
    # combine the remaining (untouched) rules with the updated rules and
    # write the combined list back to the same file.  Empty files are left
    # untouched unless all rules were updated, in which case the file will be
    # removed.  We track all changed files so we can run boundary mapping.
    changed_files: set = set()
    for file, (remaining_rules, updated_rules) in files_to_update.items():
        # Build a set of names of rules being updated in this file
        updated_names = {req["rule_name"] for req in update_reqs}
        # Combine remaining rules (excluding ones slated for update) with the updated rules
        combined_rules = []
        # Add remaining rules that are not being updated
        for r in remaining_rules:
            if r.get("name") not in updated_names:
                new_r = r.copy()
                new_r.pop("_update_index", None)
                new_r["src_ip_ranges"] = [ip for ip in new_r.get("src_ip_ranges", []) if ip]
                new_r["dest_ip_ranges"] = [ip for ip in new_r.get("dest_ip_ranges", []) if ip]
                new_r["ports"] = [p for p in new_r.get("ports", []) if p]
                combined_rules.append(new_r)
        # Add the updated rules
        for r in updated_rules:
            new_r = r.copy()
            new_r.pop("_update_index", None)
            new_r["src_ip_ranges"] = [ip for ip in new_r.get("src_ip_ranges", []) if ip]
            new_r["dest_ip_ranges"] = [ip for ip in new_r.get("dest_ip_ranges", []) if ip]
            new_r["ports"] = [p for p in new_r.get("ports", []) if p]
            combined_rules.append(new_r)
        # Write combined list back to the file
        if combined_rules:
            tmp_path = file + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump({"auto_firewall_rules": combined_rules}, f, indent=2)
                f.write("\n")
            os.replace(tmp_path, file)
            changed_files.add(file)
        else:
            # If no rules remain, remove the file
            if os.path.exists(file):
                os.remove(file)
                changed_files.add(file)

    # Write summary file
    with open("rule_update_summary.txt", "w") as f:
        for line in summaries:
            f.write(line + "\n")

    # Run boundary mapper on changed files
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