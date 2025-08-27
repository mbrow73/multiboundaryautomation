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
    # Generate or extract request id
    reqid_match = re.search(r"Request ID.*?:\s*([A-Za-z0-9_-]+)", issue_text, re.IGNORECASE)
    reqid = reqid_match.group(1).strip() if reqid_match else f"REQ-{uuid.uuid4().hex[:8]}"

    # Extract perimeter names.  Accept comma-separated list or one per line.
    perimeters: List[str] = []
    perimeter_regex = re.compile(r"Perimeter Name\s*:?\s*([A-Za-z0-9_-]+)", re.IGNORECASE)
    for match in perimeter_regex.finditer(issue_text):
        perim = match.group(1).strip()
        if perim:
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

    # Parse rules.  Split on Direction headings
    rules: List[Dict[str, Any]] = []
    pattern = re.compile(
        r"Direction\s*\([^\)]+\)\s*\n(.*?)(?=\n\s*Direction\s*\(|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    for rule_match in pattern.finditer(issue_text):
        rule_text = rule_match.group(0)
        # Determine direction (INGRESS or EGRESS)
        dir_match = re.search(r"Direction.*?(INGRESS|EGRESS)", rule_text, re.IGNORECASE)
        direction = dir_match.group(1).upper() if dir_match else ""

        # Helper to extract a section between a heading and the next blank line
        def extract_section(label: str, text: str) -> str:
            sec_match = re.search(
                rf"{label}\s*\n(.*?)(?:\n\s*\n|\Z)", text, re.IGNORECASE | re.DOTALL
            )
            return sec_match.group(1).strip() if sec_match else ""

        services_raw = extract_section("Services", rule_text)
        services: List[str] = []
        for s in re.split(r"[,\n]+", services_raw):
            s = s.strip()
            if s:
                services.append(s)

        methods_raw = extract_section("Methods", rule_text)
        methods: List[str] = []
        for m in re.split(r"[,\n]+", methods_raw):
            m = m.strip()
            if m:
                methods.append(m)

        sources_raw = extract_section("Source / From", rule_text)
        sources: List[str] = []
        for src in re.split(r"[,\n]+", sources_raw):
            src = src.strip()
            if src:
                sources.append(src)

        destinations_raw = extract_section("Destination / To", rule_text)
        destinations: List[str] = []
        for dst in re.split(r"[,\n]+", destinations_raw):
            dst = dst.strip()
            if dst:
                destinations.append(dst)

        identities_raw = extract_section("Identities", rule_text)
        identities: List[str] = []
        for idn in re.split(r"[,\n]+", identities_raw):
            idn = idn.strip()
            if idn:
                identities.append(idn)

        rules.append(
            {
                "direction": direction,
                "services": services,
                "methods": methods,
                "sources": sources,
                "destinations": destinations,
                "identities": identities,
            }
        )

    return {
        "reqid": reqid,
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

    for perim in parsed.get("perimeters", []):
        perim_info = router.get("perimeters", {}).get(perim)
        if not perim_info:
            continue  # Unknown perimeter
        repo = perim_info.get("repo")
        tfvars_file = perim_info.get("tfvars_file")
        access_file = perim_info.get("accesslevel_file")
        policy_id = perim_info.get("policy_id")

        branch = f"vpcsc/{reqid.lower()}-{perim}"
        commit_msg = f"[VPC-SC] Apply request {reqid}"
        pr_title = f"VPC SC request {reqid} for {perim}"
        pr_body_lines = [
            f"This pull request applies the VPC Service Controls request `{reqid}` to perimeter `{perim}`.",
        ]
        if third_party:
            pr_body_lines.append(f"**Third‑party:** {third_party}")
        if justification:
            pr_body_lines.append("\n**Justification:**\n" + justification)
        pr_body = "\n\n".join(pr_body_lines)

        ingress_policies: List[Dict[str, Any]] = []
        egress_policies: List[Dict[str, Any]] = []
        access_level_snippets: List[str] = []

        # Generate a simple name prefix for access levels
        def safe_name(s: str) -> str:
            return re.sub(r"[^A-Za-z0-9]", "-", s.lower())

        for idx, rule in enumerate(rules):
            direction = rule.get("direction", "").upper()
            services = rule.get("services", [])
            methods = rule.get("methods", [])
            sources = rule.get("sources", [])
            destinations = rule.get("destinations", [])
            identities = rule.get("identities", [])

            # Build operations block for ingress/egress
            operations: List[Dict[str, Any]] = []
            for svc in services:
                op: Dict[str, Any] = {"service_name": svc}
                if methods:
                    op["method_selectors"] = [{"method": m} for m in methods]
                operations.append(op)

            if direction == "INGRESS":
                # Build ingress policy object
                ingress_from: Dict[str, Any] = {}
                # Determine sources: IP ranges will require an access level
                src_access_levels: List[str] = []
                other_sources: List[Dict[str, Any]] = []
                ip_subnets: List[str] = []
                for src in sources:
                    if re.match(r"^\d+\.\d+\.\d+\.\d+(\/\d+)?$", src):
                        ip_subnets.append(src)
                    else:
                        # Could be a project/resource
                        other_sources.append({"resource": src})
                # Create access level if ip_subnets found
                if ip_subnets:
                    level_name = f"{safe_name(reqid)}-rule{idx+1}"
                    access_uri = f"accessPolicies/{policy_id}/accessLevels/{level_name}"
                    src_access_levels.append(access_uri)
                    # Build HCL snippet for the access level
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
                    # Filter out empty strings
                    hcl_lines = [line for line in hcl_lines if line]
                    access_level_snippets.append("\n".join(hcl_lines))

                if src_access_levels:
                    ingress_from["access_levels"] = src_access_levels
                if other_sources:
                    ingress_from.setdefault("sources", []).extend(other_sources)
                if identities:
                    ingress_from.setdefault("identities", []).extend(identities)

                ingress_to: Dict[str, Any] = {}
                if destinations:
                    ingress_to["resources"] = destinations
                if operations:
                    ingress_to["operations"] = operations

                ingress_policies.append({
                    "ingress_from": ingress_from,
                    "ingress_to": ingress_to,
                })

            elif direction == "EGRESS":
                # Build egress policy object
                egress_from: Dict[str, Any] = {}
                if identities:
                    egress_from["identities"] = identities
                if sources:
                    # Egress sources can specify resources or access levels; treat as resources
                    egress_from["sources"] = [ {"resource": s} for s in sources ]

                egress_to: Dict[str, Any] = {}
                if destinations:
                    egress_to["resources"] = destinations
                if operations:
                    egress_to["operations"] = operations

                egress_policies.append({
                    "egress_from": egress_from,
                    "egress_to": egress_to,
                })
            else:
                # Unknown or unsupported direction; skip
                continue

        # Construct tfvars content.  Embed TTL and justification as comments.
        policy_obj = {
            "ingress_policies": ingress_policies,
            "egress_policies": egress_policies,
        }
        tfvars_content_lines = []
        if justification:
            for line in justification.split("\n"):
                tfvars_content_lines.append(f"# {line}")
        tfvars_content_lines.append(json.dumps(policy_obj, indent=2))
        tfvars_content = "\n".join(tfvars_content_lines) + "\n"

        # Combine access level snippets
        access_content = "\n\n".join(access_level_snippets) + ("\n" if access_level_snippets else "")

        changes: List[Dict[str, Any]] = []
        if tfvars_file:
            changes.append({"file": tfvars_file, "content": tfvars_content})
        if access_file and access_content:
            changes.append({"file": access_file, "content": access_content})

        actions.append(
            {
                "repo": repo,
                "branch": branch,
                "commit_message": commit_msg,
                "pr_title": pr_title,
                "pr_body": pr_body,
                "changes": changes,
            }
        )

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
