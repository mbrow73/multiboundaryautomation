#!/usr/bin/env python3
"""
Updated VPC Service Controls request handler.

This script processes VPC Service Controls requests submitted via GitHub Issues.
It supports multiple rules per request, additional metadata (TTL, justification,
third‑party name) and method selectors.  Each rule consists of a direction
(INGRESS/EGRESS), services, optional methods, sources/destinations and
identities.  The parser identifies rule sections based on the "Direction"
heading in the issue template.  The script generates ingress and egress
policy objects that can be consumed by Terraform and constructs access
level HCL snippets when IP-based sources are present.

The script produces a JSON summary consumed by the GitHub Actions workflow.
Each action describes which repository to update, the branch and PR details,
and the file changes to apply.
"""

import argparse
import json
import os
import re
import sys
import uuid
from typing import Any, Dict, List

import yaml  # type: ignore


def parse_issue_body(issue_text: str) -> Dict[str, Any]:
    """Parse the issue body for VPC Service Controls request fields.

    This parser attempts to support multiple rules per request and additional
    metadata such as TTL, justification and third‑party name.  Each rule
    consists of a direction (INGRESS/EGRESS), services, methods (optional),
    sources/destinations and identities.  Rules are delimited by the
    "Direction" heading in the issue template.  Everything after the last rule
    heading until the next "###" heading is considered part of the same rule.

    Returns a dictionary containing:
      - reqid: the request identifier (generated if absent)
      - perimeters: list of perimeter names mentioned in the issue
      - ttl: the time‑to‑live string (if provided)
      - third_party: the third‑party name (if provided)
      - justification: justification text (if provided)
      - rules: a list of rule dictionaries with keys direction, services,
        methods, sources, destinations and identities
    """
    # Preprocess to remove markdown bold/italic/backticks that may interfere with regex.
    clean_text = re.sub(r"[\*`]+", "", issue_text)

    # Generate or extract request id
    reqid_match = re.search(r"Request ID.*?:\s*([A-Za-z0-9_-]+)", clean_text, re.IGNORECASE)
    reqid = reqid_match.group(1).strip() if reqid_match else f"REQ-{uuid.uuid4().hex[:8]}"

    # Top‑level perimeter names are deprecated in favour of per-rule perimeters.
    # Extract any global perimeter names for backward compatibility.
    perimeters: List[str] = []
    perimeter_regex = re.compile(r"^Perimeter Name\s*:?(.*)$", re.IGNORECASE | re.MULTILINE)
    match_global_perimeter = perimeter_regex.search(clean_text)
    if match_global_perimeter:
        value = match_global_perimeter.group(1).strip()
        for part in re.split(r",", value):
            perim = part.strip()
            # Skip spurious values like "(s)" that arise from optional plural markers
            if perim and perim != "(s)":
                perimeters.append(perim)

    # TTL is no longer used.  Leave as empty string for backward compatibility.
    ttl = ""

    # Extract third‑party name
    third_party_match = re.search(r"Third\s*-?Party\s*Name.*?:\s*(.+)", issue_text, re.IGNORECASE)
    third_party = third_party_match.group(1).strip() if third_party_match else ""

    # Extract justification (capture everything after the Justification heading)
    justification = ""
    justification_match = re.search(r"Justification\s*\n+(.+?)\n\s*(?:###|\Z)", issue_text, re.IGNORECASE | re.DOTALL)
    if justification_match:
        justification = justification_match.group(1).strip()

    # Parse rules using a more robust line‑based approach.  Each rule starts
    # at a "Perimeter Name" heading and continues until the next such heading
    # (or end of file).  If the template omits the perimeter for a rule, it
    # will fall back to any global perimeters parsed earlier.
    rules: List[Dict[str, Any]] = []
    # Regular expression to find rule blocks starting at "Perimeter Name"
    rule_pattern = re.compile(
        r"Perimeter Name\(s\)?[^\n]*\n.*?(?=(?:\n\s*Perimeter Name\(s\)?|\Z))",
        re.IGNORECASE | re.DOTALL,
    )
    for rule_match in rule_pattern.finditer(clean_text):
        block = rule_match.group(0)
        # Determine direction
        dir_match = re.search(r"Direction.*?(INGRESS|EGRESS)", block, re.IGNORECASE)
        direction = dir_match.group(1).upper() if dir_match else ""
        # Candidate headings within a rule
        headings = [
            "Perimeter Name",
            "Perimeter Name(s)",
            "Services",
            "Methods",
            "Permissions",
            "Source / From",
            "From",
            "Destination / To",
            "To",
            "Identities",
            # Include Direction as a heading to prevent it from being captured as a value
            "Direction",
        ]
        # Initialise values for headings we intend to capture (exclude Direction)
        values: Dict[str, List[str]] = {h: [] for h in headings if h != "Direction"}
        current_heading: str | None = None
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            normalized = re.sub(r"[*`]+", "", stripped)
            matched_heading = None
            for h in headings:
                if re.match(rf"^{re.escape(h)}", normalized, re.IGNORECASE):
                    matched_heading = h
                    break
            if matched_heading:
                # If this is the Direction heading, do not set current_heading
                # so that the following line (e.g., "INGRESS") is not captured as a value.
                if matched_heading.lower().startswith("direction"):
                    current_heading = None
                else:
                    current_heading = matched_heading
                continue
            # Stop capturing when encountering Third‑Party or Justification headings
            if re.match(r"^Third", normalized, re.IGNORECASE) or re.match(r"^Justification", normalized, re.IGNORECASE):
                current_heading = None
                continue
            if current_heading:
                if stripped.startswith("-") or re.search(r"\bFor\b|\bExample\b", stripped, re.IGNORECASE):
                    continue
                values[current_heading].append(stripped)
        # Extract perimeters
        perim_vals: List[str] = []
        for key in ("Perimeter Name(s)", "Perimeter Name"):
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    part = part.strip()
                    if part:
                        perim_vals.append(part)
        if not perim_vals:
            perim_vals = perimeters.copy()
        # Extract services
        services: List[str] = []
        for val in values.get("Services", []):
            for part in re.split(r",", val):
                part = part.strip()
                if part:
                    services.append(part)
        # Extract methods
        methods: List[str] = []
        for val in values.get("Methods", []):
            for part in re.split(r",", val):
                part = part.strip()
                if part:
                    methods.append(part)
        # Extract permissions
        permissions: List[str] = []
        for val in values.get("Permissions", []):
            for part in re.split(r",", val):
                part = part.strip()
                if part:
                    permissions.append(part)
        # Extract sources
        sources: List[str] = []
        for key in ("Source / From", "From"):
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    part = part.strip()
                    if part:
                        sources.append(part)
        # Extract destinations
        destinations: List[str] = []
        for key in ("Destination / To", "To"):
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    part = part.strip()
                    if part:
                        destinations.append(part)
        # Extract identities
        identities: List[str] = []
        for val in values.get("Identities", []):
            for part in re.split(r",", val):
                part = part.strip()
                if part:
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
        # top‑level perimeters retained for backward compatibility
        "perimeters": perimeters,
        "ttl": ttl,
        "third_party": third_party,
        "justification": justification,
        "rules": rules,
    }


def build_actions(parsed: Dict[str, Any], router: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Construct actions based on the parsed request and router mapping.

    For each perimeter listed in the request, this function looks up the
    repository, tfvars and access level file paths from the router config and
    builds a branch name, commit message and pull request metadata.  It then
    generates the ingress and egress policy objects based on the parsed rules
    and assembles HCL snippets for access level definitions when needed.

    The resulting actions list is consumed by the GitHub Actions workflow to
    apply changes across repositories.
    """
    actions: List[Dict[str, Any]] = []
    reqid = parsed.get("reqid") or f"REQ-{uuid.uuid4().hex[:8]}"
    # TTL is ignored and no longer stored in tfvars or PR bodies
    ttl = ""
    third_party = parsed.get("third_party") or ""
    justification = parsed.get("justification") or ""
    rules: List[Dict[str, Any]] = parsed.get("rules", [])

    # Aggregate policies per perimeter
    perim_map: Dict[str, Dict[str, Any]] = {}
    # Helper to generate safe access level names
    def safe_name(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "-", s.lower())

    for idx, rule in enumerate(rules):
        direction = rule.get("direction", "").upper()
        services = rule.get("services", [])
        methods = rule.get("methods", [])
        permissions = rule.get("permissions", [])
        sources = rule.get("sources", [])
        destinations = rule.get("destinations", [])
        identities = rule.get("identities", [])
        rule_perims: List[str] = rule.get("perimeters", []) or parsed.get("perimeters", [])

        # Build operations mapping per service
        operations: Dict[str, Dict[str, Any]] = {}
        for svc in services:
            svc_dict: Dict[str, Any] = {}
            svc_dict["methods"] = methods.copy() if methods else []
            svc_dict["permissions"] = permissions.copy() if permissions else []
            operations[svc] = svc_dict

        for perim in rule_perims:
            perim_info = router.get("perimeters", {}).get(perim)
            if not perim_info:
                continue
            data = perim_map.setdefault(perim, {
                "ingress_policies": [],
                "egress_policies": [],
                "access_levels": [],
            })
            policy_id = perim_info.get("policy_id")
            if direction == "INGRESS":
                # Build ingress policy
                ingress_from: Dict[str, Any] = {"identity_type": ""}
                access_levels_list: List[str] = []
                resource_sources: List[str] = []
                ip_subnets: List[str] = []
                for src in sources:
                    if re.match(r"^\d+\.\d+\.\d+\.\d+(\/\d+)?$", src):
                        ip_subnets.append(src)
                    else:
                        resource_sources.append(src)
                if ip_subnets:
                    level_name = f"{safe_name(reqid)}-rule{idx+1}"
                    access_uri = f"accessPolicies/{policy_id}/accessLevels/{level_name}"
                    access_levels_list.append(access_uri)
                    # Build access level snippet
                    hcl_lines = [
                        f"resource \"google_access_context_manager_access_level\" \"{level_name}\" {{",
                        f"  name   = \"accessPolicies/{policy_id}/accessLevels/{level_name}\"",
                        f"  parent = \"accessPolicies/{policy_id}\"",
                        f"  title  = \"{level_name}\"",
                        "  basic {",
                        "    conditions {",
                        f"      ip_subnetworks = [" + ", ".join([f'\"{ip}\"' for ip in ip_subnets]) + "]",
                        (f"      members        = [" + ", ".join([f'\"{m}\"' for m in identities]) + "]" if identities else ""),
                        "    }",
                        "  }",
                        "}\n",
                    ]
                    hcl_lines = [line for line in hcl_lines if line]
                    data["access_levels"].append("\n".join(hcl_lines))
                sources_obj = {"resources": resource_sources, "access_levels": access_levels_list}
                ingress_from["sources"] = sources_obj
                if identities:
                    ingress_from["identities"] = identities
                ingress_to: Dict[str, Any] = {}
                if destinations:
                    ingress_to["resources"] = destinations
                if operations:
                    ingress_to["operations"] = operations
                data["ingress_policies"].append({"from": ingress_from, "to": ingress_to})
            elif direction == "EGRESS":
                egress_from: Dict[str, Any] = {"identity_type": ""}
                if identities:
                    egress_from["identities"] = identities
                egress_to: Dict[str, Any] = {}
                if destinations:
                    egress_to["resources"] = destinations
                if operations:
                    egress_to["operations"] = operations
                data["egress_policies"].append({"from": egress_from, "to": egress_to})
            else:
                continue

    # Build actions from aggregated data
    for perim, data in perim_map.items():
        perim_info = router.get("perimeters", {}).get(perim)
        if not perim_info:
            continue
        repo = perim_info.get("repo")
        tfvars_file = perim_info.get("tfvars_file")
        access_file = perim_info.get("accesslevel_file")
        branch = f"vpcsc/{reqid.lower()}-{perim}"
        commit_msg = f"[VPC-SC] Apply request {reqid}"
        pr_title = f"VPC SC request {reqid} for {perim}"
        pr_body_lines = [f"This pull request applies the VPC Service Controls request `{reqid}` to perimeter `{perim}`."]
        if third_party:
            pr_body_lines.append(f"**Third‑party:** {third_party}")
        if justification:
            pr_body_lines.append("\n**Justification:**\n" + justification)
        pr_body = "\n\n".join(pr_body_lines)
        policy_obj = {
            "ingress_policies": data["ingress_policies"],
            "egress_policies": data["egress_policies"],
        }
        tfvars_content_lines: List[str] = []
        if justification:
            for line in justification.split("\n"):
                tfvars_content_lines.append(f"# {line}")
        tfvars_content_lines.append(json.dumps(policy_obj, indent=2))
        tfvars_content = "\n".join(tfvars_content_lines) + "\n"
        access_content = "\n\n".join(data["access_levels"]) + ("\n" if data["access_levels"] else "")
        changes: List[Dict[str, Any]] = []
        if tfvars_file:
            changes.append({"file": tfvars_file, "content": tfvars_content})
        if access_file and access_content:
            changes.append({"file": access_file, "content": access_content})
        actions.append({
            "repo": repo,
            "branch": branch,
            "commit_message": commit_msg,
            "pr_title": pr_title,
            "pr_body": pr_body,
            "changes": changes,
        })
    return actions


def main() -> None:
    parser = argparse.ArgumentParser(description="Process a VPC Service Controls request issue")
    parser.add_argument("--issue-file", required=True, help="Path to the issue body file (markdown)")
    parser.add_argument("--router-file", required=True, help="Path to router.yml mapping perimeters to repos")
    parser.add_argument("--workdir", required=False, default=".", help="Working directory (unused)")
    parser.add_argument("--output", required=True, help="Path to write the JSON summary")
    args = parser.parse_args()

    with open(args.issue_file, "r", encoding="utf-8") as f:
        issue_text = f.read()
    try:
        with open(args.router_file, "r", encoding="utf-8") as f:
            router = yaml.safe_load(f)
    except Exception:
        router = {}

    parsed = parse_issue_body(issue_text)
    actions = build_actions(parsed, router)
    summary = {"reqid": parsed.get("reqid"), "actions": actions}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
