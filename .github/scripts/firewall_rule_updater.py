#!/usr/bin/env python3
import re
import sys
import os
import glob
import json
import ipaddress

"""
This script is used by the GitHub workflow that processes firewall update
requests.  It reads issue input from stdin, parses the requested updates and
applies them to the existing `auto_firewall_rules` definitions in
`firewall-requests/` files.  The updated rules are written back out to a
new file prefixed with the new REQID.  Validation is performed on IP
formats, ports, protocol, and naming conventions.  Note: this updater only
modifies the rule fields provided by the user and preserves the existing
`src_vpc`/`dest_vpc` assignments.  After running this script you should run
`boundary_mapper.py` to recompute `src_vpc` and `dest_vpc` if any IP ranges
change boundaries.
"""

# Only these oversized public ranges are allowed
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),    # GCP health-check
    ipaddress.ip_network("130.211.0.0/22"),   # GCP health-check
    ipaddress.ip_network("199.36.153.4/30"),  # restricted googleapis
]


def validate_reqid(reqid):
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid))


def validate_carid(carid):
    return bool(re.fullmatch(r"\d{9}", carid))


def validate_ip(ip):
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except:
        return False


def validate_port(port):
    if re.fullmatch(r"\d{1,5}", port):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port):
        a, b = map(int, port.split('-'))
        return 1 <= a <= b <= 65535
    return False


def validate_protocol(proto):
    return proto in {"tcp", "udp", "icmp", "sctp"}


def load_all_rules():
    rule_map = {}
    file_map = {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        with open(path) as f:
            data = json.load(f)
            for rule in data.get("auto_firewall_rules", []):
                rule_map[rule["name"]] = rule
                file_map[rule["name"]] = path
    return rule_map, file_map


def update_rule_fields(rule, updates, new_reqid, new_carid):
    idx = rule.get("_update_index", 1)
    proto = updates.get("protocol") or rule["protocol"]
    ports = updates.get("ports") or rule["ports"]
    direction = updates.get("direction") or rule.get("direction", "")
    carid = new_carid or rule["name"].split("-")[2]

    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    rule["name"] = new_name

    for k, v in updates.items():
        if v:
            rule[k] = (v.lower() if k in ["protocol", "direction"] else v)

    desc_just = updates.get("description") or rule.get("description", "").split("|", 1)[-1]
    rule["description"] = f"{new_name} | {desc_just.strip()}"
    return rule


def validate_rule(rule, idx=1):
    errors = []
    # IP/CIDR validations — require a slash-mask first
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
            # Disallow CIDRs larger than /24 unless in allowed public ranges
            if net.prefixlen < 24:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(
                        f"Rule {idx}: {label} '{ip}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range."
                    )
                continue
            # Disallow other public ranges not in ALLOWED_PUBLIC_RANGES
            if not net.is_private:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: Public {label} '{ip}' not in allowed GCP ranges.")
                continue
    # Port validation
    for port in rule.get("ports", []):
        if not validate_port(port):
            errors.append(f"Rule {idx}: Invalid port or range: '{port}'.")
    # Protocol validation
    proto = rule.get("protocol", "")
    if proto != proto.lower() or not validate_protocol(proto):
        errors.append(
            f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{proto}'"
        )
    # Direction validation (optional)
    direction = rule.get("direction", "")
    if direction and direction.upper() not in {"INGRESS", "EGRESS"}:
        errors.append(
            f"Rule {idx}: Direction must be INGRESS or EGRESS when provided. Found: '{direction}'"
        )
    # CARID in name
    carid = rule["name"].split("-")[2]
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    return errors


def parse_blocks(issue_body):
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]


def make_update_summary(idx, rule_name, old_rule, updates, new_rule):
    changes = []
    labels = [
        ("src_ip_ranges", "Source"),
        ("dest_ip_ranges", "Destination"),
        ("ports", "Ports"),
        ("protocol", "Protocol"),
        ("direction", "Direction"),
        ("carid", "CARID"),
        ("description", "Justification"),
    ]
    for k, label in labels:
        old = old_rule.get(k)
        new = updates.get(k) if updates.get(k) else None
        if new is not None and old != new:
            old_val = ','.join(old) if isinstance(old, list) else old
            new_val = ','.join(new) if isinstance(new, list) else new
            changes.append(f"{label}: `{old_val}` → `{new_val}`")
    if old_rule["name"] != new_rule["name"]:
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes:
        changes = ["(No fields updated, only name/desc changed)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)


def main():
    # Read issue body either from argument or stdin
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()
    errors = []
    summaries = []
    # Parse new REQID
    m_reqid = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m_reqid.group(1).strip() if m_reqid else None
    if not new_reqid or not validate_reqid(new_reqid):
        errors.append(
            f"New REQID must be 'REQ' followed by 7 or 8 digits. Found: '{new_reqid}'."
        )
    # Parse rule blocks
    rule_blocks = parse_blocks(issue_body)
    updates = []
    for idx, block in enumerate(rule_blocks, 1):
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue

        def extract(label):
            m = re.search(rf"{label}.*?:\s*(.+)", block, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        updates.append({
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [ip.strip() for ip in extract("New Source IP").split(",") if ip.strip()],
            "dest_ip_ranges": [ip.strip() for ip in extract("New Destination IP").split(",") if ip.strip()],
            "ports": [p.strip() for p in extract("New Port").split(",") if p.strip()],
            "protocol": extract("New Protocol"),
            "direction": extract("New Direction"),
            "carid": extract("New CARID"),
            "description": extract("New Business Justification"),
        })
    # Load existing rules
    rule_map, file_map = load_all_rules()
    # Group updates by file path
    updates_by_file = {}
    for update in updates:
        rule_name = update["rule_name"]
        if rule_name not in file_map:
            errors.append(
                f"Rule {update['idx']}: No rule found in codebase with name '{rule_name}'."
            )
            continue
        file = file_map[rule_name]
        updates_by_file.setdefault(file, []).append(update)
    # Collect updated rules across all files.  We'll write them out to a single
    # new file named <new_reqid>.auto.tfvars.json after processing all inputs.
    updated_rules_global: list = []

    # Apply updates per file
    for file, update_list in updates_by_file.items():
        with open(file) as f:
            file_data = json.load(f)
        orig_rules = file_data.get("auto_firewall_rules", [])
        new_rules = []
        # Split rules into two buckets:
        # - remaining_rules stay in the original file
        # - updated_rules move to the global updated list
        remaining_rules: list = []
        file_updated_rules: list = []
        for idx, rule in enumerate(orig_rules, 1):
            if rule["name"] in {u["rule_name"] for u in update_list}:
                # Build the update definition for this rule
                update = next(u for u in update_list if u["rule_name"] == rule["name"])
                new_fields = {}
                if update["src_ip_ranges"]:
                    new_fields["src_ip_ranges"] = update["src_ip_ranges"]
                if update["dest_ip_ranges"]:
                    new_fields["dest_ip_ranges"] = update["dest_ip_ranges"]
                if update["ports"]:
                    new_fields["ports"] = update["ports"]
                if update["protocol"]:
                    new_fields["protocol"] = update["protocol"]
                if update["direction"]:
                    new_fields["direction"] = update["direction"]
                if update["description"]:
                    new_fields["description"] = update["description"]
                new_carid = update["carid"]
                to_update = rule.copy()
                to_update["_update_index"] = idx
                updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
                rule_errors = validate_rule(updated_rule, idx=update["idx"])
                if rule_errors:
                    errors.extend(rule_errors)
                file_updated_rules.append(updated_rule)
                summaries.append(
                    make_update_summary(
                        update["idx"], rule["name"], rule, update, updated_rule
                    )
                )
            else:
                remaining_rules.append(rule)
        # If there are no validation errors, write back the updated rules
        if not errors:
            # Clean helper fields and remove empty values
            def clean_rules(rules_list):
                cleaned_list = []
                for r in rules_list:
                    r.pop("_update_index", None)
                    r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
                    r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
                    r["ports"] = [p for p in r.get("ports", []) if p]
                    cleaned_list.append(r)
                return cleaned_list
            # Accumulate updated rules from this file into the global list
            updated_rules_global.extend(file_updated_rules)
            # 2. update or remove the original file
            if remaining_rules:
                tmp_orig = file + ".tmp"
                with open(tmp_orig, "w") as of:
                    json.dump({"auto_firewall_rules": clean_rules(remaining_rules)}, of, indent=2)
                    of.write("\n")
                os.replace(tmp_orig, file)
            else:
                # no remaining rules; remove original file
                if os.path.exists(file):
                    os.remove(file)
    # After processing all files, write the collected updated rules to a single
    # <new_reqid>.auto.tfvars.json file if any updates were made.  We do this
    # only when there are no validation errors.
    if not errors and updated_rules_global:
        # Clean helper fields and remove empty values
        def clean_global(rules_list):
            cleaned_list = []
            for r in rules_list:
                r.pop("_update_index", None)
                r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
                r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
                r["ports"] = [p for p in r.get("ports", []) if p]
                cleaned_list.append(r)
            return cleaned_list
        new_filename = f"{new_reqid}.auto.tfvars.json"
        new_path = os.path.join("firewall-requests", new_filename)
        tmp_path = new_path + ".tmp"
        with open(tmp_path, "w") as nf:
            json.dump({"auto_firewall_rules": clean_global(updated_rules_global)}, nf, indent=2)
            nf.write("\n")
        os.replace(tmp_path, new_path)

    # write summary file if no errors occurred
    if not errors:
        with open("rule_update_summary.txt", "w") as f:
            for line in summaries:
                f.write(line + "\n")
    # output validation errors if any
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)


if __name__ == "__main__":
    main()