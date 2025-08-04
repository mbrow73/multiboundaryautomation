#!/usr/bin/env python3
"""
Post‑merge priority normalizer for firewall rules.

After multiple firewall rule changes are merged into the main branch the
priority values assigned at creation time may become sparse or disordered.
This utility scans all `*.auto.tfvars.json` files in the `firewall-requests`
directory, collects every rule, sorts them by their existing priority and
reassigns a fresh, evenly spaced priority starting at 1000.  The rules are
written back to their original files with updated priority values.  Rule
names are intentionally left unchanged; only the `priority` field is
modified.
"""

import json
import glob
import os

def main() -> None:
    # Gather all auto rule files
    files = glob.glob("firewall-requests/*.auto.tfvars.json")
    if not files:
        print("No auto.tfvars.json files found. Nothing to normalize.")
        return

    # Load all rules with their file references
    all_rules = []  # list of (file_path, rule)
    for path in files:
        try:
            data = json.load(open(path))
        except Exception:
            continue
        for rule in data.get("auto_firewall_rules", []):
            all_rules.append((path, rule))

    # Sort rules by their existing priority (ascending)
    all_rules.sort(key=lambda x: x[1].get("priority", 0))

    # Assign new priorities starting at 1000 with increments of 10
    new_priority_base = 1000
    for idx, (path, rule) in enumerate(all_rules):
        rule["priority"] = new_priority_base + idx * 10

    # Group rules back into their respective files and write them out
    grouped = {}
    for path, rule in all_rules:
        grouped.setdefault(path, []).append(rule)

    for path, rules in grouped.items():
        with open(path, "w") as f:
            json.dump({"auto_firewall_rules": rules}, f, indent=2)

    print(f"Normalized {len(all_rules)} firewall rule priorities across {len(grouped)} files.")

if __name__ == "__main__":
    main()