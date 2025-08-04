import re
import sys
import os
import glob
import json

def validate_reqid(reqid):
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid))

def parse_blocks(issue_body):
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]

def main():
    if len(sys.argv) == 2:
        issue_body = sys.argv[1]
    else:
        issue_body = sys.stdin.read()
    errors = []
    summaries = []

    # Parse REQID
    m_reqid = re.search(r"Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    reqid = m_reqid.group(1).strip() if m_reqid else None
    if not reqid or not validate_reqid(reqid):
        errors.append(f"REQID must be 'REQ' followed by 7 or 8 digits. Found: '{reqid}'.")

    # Parse rule blocks
    rule_blocks = parse_blocks(issue_body)
    rule_names = []
    for idx, block in enumerate(rule_blocks, 1):
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        rule_names.append((idx, rule_name))

    # Load all rules and file paths
    file_map = {}
    rule_found = set()
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        with open(path) as f:
            data = json.load(f)
            for rule in data.get("auto_firewall_rules", []):
                file_map[rule["name"]] = path

    # Group removals by file
    removals_by_file = {}
    for idx, rule_name in rule_names:
        if rule_name not in file_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{rule_name}'.")
            continue
        file = file_map[rule_name]
        removals_by_file.setdefault(file, []).append((idx, rule_name))
        rule_found.add(rule_name)

    # For each file, remove rules, and delete file if empty
    for file, removal_list in removals_by_file.items():
        with open(file) as f:
            file_data = json.load(f)
        orig_rules = file_data.get("auto_firewall_rules", [])
        new_rules = [r for r in orig_rules if r["name"] not in {rn for (_, rn) in removal_list}]
        for idx, rule_name in removal_list:
            summaries.append(f"- **Rule {idx}** (`{rule_name}`) will be **removed**.")

        if not errors:
            if not new_rules:
                os.remove(file)
            else:
                with open(file, "w") as f:
                    json.dump({"auto_firewall_rules": new_rules}, f, indent=2)

    if not errors:
        with open("rule_removal_summary.txt", "w") as f:
            for line in summaries:
                f.write(line + "\n")

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

if __name__ == "__main__":
    main()
