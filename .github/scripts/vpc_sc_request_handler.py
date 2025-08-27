#!/usr/bin/env python3
# ... (same header comments)

import argparse
import json
import re
import uuid
from typing import Any, Dict, List

import yaml  # type: ignore

def parse_issue_body(issue_text: str) -> Dict[str, Any]:
    """Parse the issue body for VPC Service Controls request fields."""
    clean_text = re.sub(r"[\*`]+", "", issue_text)
    reqid_match = re.search(r"Request ID.*?:\s*([A-Za-z0-9_-]+)", clean_text, re.IGNORECASE)
    reqid = reqid_match.group(1).strip() if reqid_match else f"REQ-{uuid.uuid4().hex[:8]}"
    perimeters: List[str] = []
    match_global_perimeter = re.search(r"^Perimeter Name\s*:?(.*)$", clean_text, re.IGNORECASE | re.MULTILINE)
    if match_global_perimeter:
        value = match_global_perimeter.group(1).strip()
        for part in re.split(r",", value):
            perim = part.strip()
            if perim and perim != "(s)":
                perimeters.append(perim)
    third_party_match = re.search(r"Third\s*-?Party\s*Name.*?:\s*(.+)", issue_text, re.IGNORECASE)
    third_party = third_party_match.group(1).strip() if third_party_match else ""
    # Capture only the first non-empty line after "Justification"
    justification = ""
    just_match = re.search(r"Justification\s*\n+([^\n]+)", issue_text, re.IGNORECASE)
    if just_match:
        justification = just_match.group(1).strip()

    rules: List[Dict[str, Any]] = []
    rule_pattern = re.compile(
        r"Perimeter Name\(s\)?[^\n]*\n.*?(?=(?:\n\s*Perimeter Name\(s\)?|\Z))",
        re.IGNORECASE | re.DOTALL,
    )
    for rule_match in rule_pattern.finditer(clean_text):
        block = rule_match.group(0)
        # Correctly pick the line below the heading to capture the direction
        dir_match = re.search(r"Direction[^\n]*\n\s*(INGRESS|EGRESS)", block, re.IGNORECASE)
        direction = dir_match.group(1).upper() if dir_match else ""

        headings = [
            "Perimeter Name", "Perimeter Name(s)", "Services", "Methods",
            "Permissions", "Source / From", "From", "Destination / To", "To",
            "Identities", "Direction", "Third-Party Name", "Third-Party Name (if applicable)", "Justification",
        ]
        non_data_headings = {"Direction", "Third-Party Name", "Third-Party Name (if applicable)", "Justification"}
        values: Dict[str, List[str]] = {h: [] for h in headings if h not in non_data_headings}
        current_heading: str | None = None
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            normalized = re.sub(r"[*`#]+", "", stripped).strip()
            matched_heading = None
            for h in headings:
                if re.match(rf"^{re.escape(h)}", normalized, re.IGNORECASE):
                    matched_heading = h
                    break
            if matched_heading:
                if matched_heading.lower() in {"direction", "third-party name",
                                               "third-party name (if applicable)", "justification"}:
                    current_heading = None
                else:
                    current_heading = matched_heading
                continue
            if current_heading:
                if stripped.startswith("-") or re.search(r"\bFor\b|\bExample\b", stripped, re.IGNORECASE):
                    continue
                values[current_heading].append(stripped)

        perim_vals: List[str] = []
        for key in ("Perimeter Name(s)", "Perimeter Name"):
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    part = part.strip()
                    if part:
                        perim_vals.append(part)
        if not perim_vals:
            perim_vals = perimeters.copy()

        services, methods, permissions = [], [], []
        for val in values.get("Services", []):
            for part in re.split(r",", val):
                if part.strip():
                    services.append(part.strip())
        for val in values.get("Methods", []):
            for part in re.split(r",", val):
                if part.strip():
                    methods.append(part.strip())
        for val in values.get("Permissions", []):
            for part in re.split(r",", val):
                if part.strip():
                    permissions.append(part.strip())

        sources, destinations = [], []
        for key in ("Source / From", "From"):
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    if part.strip():
                        sources.append(part.strip())
        for key in ("Destination / To", "To"):
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    if part.strip():
                        destinations.append(part.strip())

        identities: List[str] = []
        for val in values.get("Identities", []):
            for part in re.split(r",", val):
                part = part.strip()
                if part:
                    if ":" not in part:
                        lower = part.lower()
                        if lower.endswith(".iam.gserviceaccount.com") or lower.endswith(".gserviceaccount.com"):
                            part = f"serviceAccount:{part}"
                        elif "googlegroups.com" in lower or lower.startswith("group-"):
                            part = f"group:{part}"
                        elif "@" in part:
                            part = f"user:{part}"
                    identities.append(part)

        rules.append({
            "direction": direction,
            "services": services,
            "methods": methods,
            "permissions": permissions,
            "sources": sources,
            "destinations": destinations,
            "identities": identities,
            "perimeters": perim_vals,
        })

    return {
        "reqid": reqid,
        "perimeters": perimeters,
        "ttl": "",
        "third_party": third_party,
        "justification": justification,
        "rules": rules,
    }

# build_actions() remains the same except for justification handling and per-rule comments,
# which you have already incorporated.
