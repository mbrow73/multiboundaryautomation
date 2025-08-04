import glob
import json

BASE_PRIORITY = 1000
PRIORITY_STEP = 1

# Collect all rules, keep their file and original index
rules = []
for path in sorted(glob.glob("firewall-requests/*.auto.tfvars.json")):
    with open(path) as f:
        data = json.load(f)
        for idx, rule in enumerate(data.get("auto_firewall_rules", [])):
            rules.append({
                "rule": rule,
                "file": path,
                "idx": idx
            })

# Find duplicate priorities
priority_to_rules = {}
for i, entry in enumerate(rules):
    prio = entry["rule"].get("priority")
    if prio in priority_to_rules:
        priority_to_rules[prio].append(i)
    else:
        priority_to_rules[prio] = [i]

# If all priorities are unique, exit without rewriting files
has_dupes = any(len(idxs) > 1 for idxs in priority_to_rules.values())
if not has_dupes:
    print("No duplicate priorities detected. No normalization needed.")
    exit(0)

# If there are duplicates, reassign unique, gapless priorities across all rules (preserving order)
print("Duplicate priorities found! Normalizing...")
for i, entry in enumerate(rules):
    entry["rule"]["priority"] = BASE_PRIORITY + i * PRIORITY_STEP

# Write back updated rules to their respective files (preserving file and original order)
file_map = {}
for entry in rules:
    file_map.setdefault(entry["file"], []).append(entry["rule"])

for path, new_rules in file_map.items():
    with open(path, "r") as f:
        orig_rules = json.load(f).get("auto_firewall_rules", [])
    if orig_rules != new_rules:
        with open(path, "w") as f:
            json.dump({"auto_firewall_rules": new_rules}, f, indent=2)
        print(f"Updated: {path}")

