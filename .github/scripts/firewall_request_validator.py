#!/usr/bin/env python3
"""
firewall_request_validator.py

Minimal validation for firewall requests.  This script checks the
structure of the issue body for required fields and ensures that IP
addresses and CIDRs are valid, ports are numeric, protocols and
directions are recognised, and the request ID does not already
exist.  Duplicate rules and malformed input will cause the script
to exit with a non‑zero status.

Usage:
  python3 firewall_request_validator.py /path/to/github_event.json
"""
import json
import os
import re
import sys
import ipaddress

FIREWALL_REQUESTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'firewall-requests')


def load_event(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def parse_issue_body(body: str) -> dict:
    patterns = {
        'carid': r'CAR\s*ID\s*: *([\w-]+)',
        'reqid': r'REQ\s*ID\s*: *([\w-]+)',
        'source': r'New\s+Source\s+IP\s*: *([\d./:]+)',
        'destination': r'New\s+Destination\s+IP\s*: *([\d./:]+)',
        'ports': r'Ports\s*: *([\w,\-]+)',
        'protocol': r'Protocol\s*: *([\w]+)',
        'direction': r'Direction\s*: *([\w]+)',
    }
    result = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            result[key] = match.group(1).strip()
        else:
            result[key] = ''
    return result


def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False


def validate_ports(port_str: str) -> bool:
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            if not (start.isdigit() and end.isdigit() and int(start) <= int(end)):
                return False
        else:
            if not part.isdigit():
                return False
            num = int(part)
            if not (0 < num <= 65535):
                return False
    return True


def main(event_path: str) -> None:
    event = load_event(event_path)
    body = event.get('issue', {}).get('body', '')
    fields = parse_issue_body(body)
    errors = []
    if not fields['carid']:
        errors.append('CAR ID is missing.')
    if not fields['reqid']:
        errors.append('REQ ID is missing.')
    if not validate_ip(fields['source']):
        errors.append(f"Invalid source IP/CIDR: {fields['source']}")
    if not validate_ip(fields['destination']):
        errors.append(f"Invalid destination IP/CIDR: {fields['destination']}")
    if not validate_ports(fields['ports']):
        errors.append(f"Invalid ports: {fields['ports']}")
    if fields['protocol'].lower() not in ['tcp', 'udp', 'icmp']:
        errors.append(f"Unsupported protocol: {fields['protocol']}")
    if fields['direction'].upper() not in ['INGRESS', 'EGRESS']:
        errors.append(f"Unsupported direction: {fields['direction']}")
    # Ensure request ID is unique
    if fields['reqid']:
        existing_file = os.path.join(FIREWALL_REQUESTS_DIR, f"{fields['reqid']}.auto.tfvars.json")
        if os.path.exists(existing_file):
            errors.append(f"Request ID {fields['reqid']} already exists.")
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: firewall_request_validator.py <event path>', file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])