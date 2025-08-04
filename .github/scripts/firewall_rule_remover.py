#!/usr/bin/env python3
"""
firewall_rule_remover.py

Remove an existing firewall rule by deleting its auto.tfvars JSON file.
This script is triggered by a GitHub Action when a firewall removal
issue is created.  It reads the issue body to find the REQ ID and
removes the corresponding file from the `firewall-requests` directory.

Usage:
  python3 firewall_rule_remover.py /path/to/github_event.json
"""
import json
import os
import re
import sys

FIREWALL_REQUESTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'firewall-requests')

def load_event(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def parse_reqid(body: str) -> str:
    match = re.search(r'REQ\s*ID\s*: *([\w-]+)', body, re.IGNORECASE)
    return match.group(1).strip() if match else ''


def main(event_path: str) -> None:
    event = load_event(event_path)
    body = event.get('issue', {}).get('body', '')
    reqid = parse_reqid(body)
    if not reqid:
        print('REQ ID not found in issue body.', file=sys.stderr)
        sys.exit(1)
    target = os.path.join(FIREWALL_REQUESTS_DIR, f"{reqid}.auto.tfvars.json")
    if os.path.exists(target):
        os.remove(target)
        print(f"Removed {target}")
    else:
        print(f"File {target} does not exist.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: firewall_rule_remover.py <event path>', file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])