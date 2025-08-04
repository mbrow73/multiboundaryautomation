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
    # Build proposed changes for each file.  Separate the rules into two
    # categories: those that will remain in the original file (remaining_rules)
    # and those that should be moved to a new file (updated_rules).  This
    # allows us to preserve safe concurrency: if the new request ID differs
    # from the existing file's request ID, we will move the updated rules
    # into a new file named REQ<new_reqid>.auto.tfvars.json.  If the new
    # request ID matches the existing ID, we simply update in place.
    files_to_update: dict[str, tuple[list, list]] = {}
    changed_files = set()
    for file, update_list in updates_by_file.items():
        with open(file) as f:
            file_data = json.load(f)
        orig_rules = file_data.get("auto_firewall_rules", [])
        remaining_rules: list = []
        # When we update a rule we need to remember the original request ID
        # (the ID embedded in the rule name before it is updated) so that
        # later we can decide whether to move the updated rule to a new
        # file.  updated_rules will hold tuples of (old_reqid, updated_rule).
        updated_rules: list[tuple[str, dict]] = []
        for idx, rule in enumerate(orig_rules, 1):
            # Determine if this rule is slated for update
            if rule["name"] in {u["rule_name"] for u in update_list}:
                # Build a mapping of new fields based on user input
                update = next(u for u in update_list if u["rule_name"] == rule["name"])
                new_fields: dict = {}
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
                # Copy the rule and mark its original index so update_rule_fields can
                # produce a stable name
                to_update = rule.copy()
                to_update["_update_index"] = idx
                # Apply updates to rule fields and regenerate its name
                # Capture the original request ID from the rule name before
                # updating.  Rule names follow the format
                # AUTO-<REQID>-<CARID>-<PROTOCOL>-<PORTS>-<INDEX>.
                original_name_parts = rule["name"].split("-")
                old_reqid = original_name_parts[1] if len(original_name_parts) > 1 else ""
                updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
                rule_errors = validate_rule(updated_rule, idx=update["idx"])
                if rule_errors:
                    errors.extend(rule_errors)
                # Store the old request ID alongside the updated rule
                updated_rules.append((old_reqid, updated_rule))
                summaries.append(
                    make_update_summary(update["idx"], rule["name"], rule, update, updated_rule)
                )
            else:
                remaining_rules.append(rule)
        files_to_update[file] = (remaining_rules, updated_rules)

    # After staging all changes and collecting errors, write out modifications
    # only if there were no validation errors.  We operate per-rule rather
    # than per-file to correctly handle scenarios where a single file may
    # contain rules belonging to multiple request IDs.  For each rule
    # slated for update we determine its original request ID based on the
    # rule name (the second dash‑separated token, e.g. 'REQ1234567' in
    # 'AUTO-REQ1234567-123456789-TCP-443-1').  If the new request ID
    # differs from the original, that rule will be removed from its
    # current file and appended to a new file named
    # `firewall-requests/REQ<new_reqid>.auto.tfvars.json`.  Otherwise the
    # rule is updated in place and left in the original file.  This logic
    # preserves concurrency (by ensuring updates with different request
    # IDs never write to the same file) while avoiding the issue where
    # rules disappear when IDs match.
    if not errors:
        # Collect per-file modifications for writing back.  We'll
        # accumulate remaining and updated rules here keyed by the file
        # path they should live in after the update.
        per_file_new_contents: dict[str, list] = {}
        # Also track which files have been touched so that we can run
        # boundary mapping on them later.
        changed_files = set()
        # The new file to which moved rules should be appended.  It's
        # always relative to the directory of the original files.
        for file, (remaining_rules, updated_rules) in files_to_update.items():
            # Start by copying over all remaining (untouched) rules
            # These rules remain in the original file regardless of the
            # request ID comparison.
            per_file_new_contents[file] = []
            for rule in remaining_rules:
                r = rule.copy()
                r.pop("_update_index", None)
                # Clean empty values from lists
                r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
                r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
                r["ports"] = [p for p in r.get("ports", []) if p]
                per_file_new_contents[file].append(r)
            # Process each updated rule individually.  Each entry in
            # updated_rules is a tuple (old_reqid, rule_dict).  We use
            # old_reqid (the request ID from the original rule name) to
            # determine whether the rule should be moved to a new file or
            # remain in the current file.  If old_reqid differs from
            # new_reqid, we move the rule; otherwise we update it in place.
            for old_reqid, rule in updated_rules:
                # Clean helper and empty fields
                r = rule.copy()
                r.pop("_update_index", None)
                r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
                r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
                r["ports"] = [p for p in r.get("ports", []) if p]
                if old_reqid and old_reqid != new_reqid:
                    # Move rule to a file dedicated to the new request ID
                    dirpath = os.path.dirname(file)
                    new_filename = f"{new_reqid}.auto.tfvars.json"
                    new_path = os.path.join(dirpath, new_filename)
                    per_file_new_contents.setdefault(new_path, [])
                    per_file_new_contents[new_path].append(r)
                    changed_files.add(new_path)
                else:
                    # Same request ID: update rule in place within the original file
                    per_file_new_contents[file].append(r)
                    changed_files.add(file)
        # Write out all modified files
        for fp, rules_list in per_file_new_contents.items():
            if rules_list:
                tmp_path = fp + ".tmp"
                with open(tmp_path, "w") as outf:
                    json.dump({"auto_firewall_rules": rules_list}, outf, indent=2)
                    outf.write("\n")
                # If the file already existed, replace it; otherwise just
                # move into place.  Using os.replace ensures atomic write.
                os.replace(tmp_path, fp)
            else:
                # If rules_list is empty and the file exists, remove it
                if os.path.exists(fp):
                    os.remove(fp)
                    changed_files.add(fp)

    # write summary file if no errors occurred
    if not errors:
        with open("rule_update_summary.txt", "w") as f:
            for line in summaries:
                f.write(line + "\n")

        # After writing all the rules out, recompute boundaries on any changed
        # files.  We call the existing boundary_mapper script on each file
        # individually so that src_vpc/dest_vpc fields are adjusted when IP
        # ranges cross boundaries.  If the boundary mapper script is not
        # available this step will no-op gracefully.
        if changed_files:
            try:
                import subprocess
                # Use a boundary map file if it exists; otherwise default to
                # boundary_map.json in the repository root.
                map_file = "boundary_map.json"
                for fp in changed_files:
                    # Only run for files that still exist (original files may have
                    # been removed).  Provide the relative JSON path.
                    if os.path.exists(fp):
                        # Attempt to call boundary mapper; ignore errors
                        # Suppress stdout/stderr from boundary mapper to avoid noise during updates
                        subprocess.run([
                            sys.executable,
                            os.path.join(".github", "scripts", "boundary_mapper.py"),
                            "--map-file", map_file,
                            "--json-file", fp,
                        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                # If subprocess or mapper is unavailable, silently skip boundary remap.
                pass
    # output validation errors if any
    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)


if __name__ == "__main__":
    main()