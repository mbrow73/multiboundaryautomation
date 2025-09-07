#!/usr/bin/env python3
"""
VPC Service Controls request handler with TLM-ID, per-service methods/permissions,
and justification comments. Parses a GitHub issue (in Markdown) into rule structures,
normalises identities, creates access levels via a module, and adds justification
comments above each rule in the generated HCL.
"""

import argparse
import json
import re
import uuid
from typing import Any, Dict, List

import yaml  # type: ignore

def parse_issue_body(issue_text: str) -> Dict[str, Any]:
    """Parse the body of a VPC-SC request issue and return a structured dict.

    The incoming issue is expected to follow the VPC-SC request template: it may
    contain multiple perimeters, services, methods/permissions, identities and a
    justification.  This function extracts those fields, normalises identities and
    returns a dictionary with request ID, perimeter names, TLM-ID, justification
    text and a list of rule blocks.
    """
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

    # Capture TLM-ID or fallback to third-party name
    tlm_match = re.search(r"TLM[-\u2011\u2012\u2013\u2014]?ID.*?:\s*(.+)", issue_text, re.IGNORECASE)
    if not tlm_match:
        tlm_match = re.search(r"TLM[-\u2011\u2012\u2013\u2014]?ID.*?\n+([^\n]*)", issue_text, re.IGNORECASE)
    third_party_match = re.search(r"Third\s*-?Party\s*Name.*?:\s*(.+)", issue_text, re.IGNORECASE)
    if tlm_match:
        tlm_id = tlm_match.group(1).strip()
    elif third_party_match:
        tlm_id = third_party_match.group(1).strip()
    else:
        tlm_id = ""

    justification = ""
    # Capture the full justification block: everything after the "Justification" heading
    # up to the next heading (a line starting with `#`) or the end of the text.  This
    # allows multi-line justifications.  Remove empty lines and placeholder lines starting with `**`.
    just_match = re.search(r"(?i)Justification\s*?\n+([\s\S]*?)(?:\n\s*#+\s|\Z)", issue_text)
    if just_match:
        candidate = just_match.group(1).strip()
        lines = [ln.strip() for ln in candidate.splitlines() if ln.strip() and not ln.strip().startswith("**")]
        justification = "\n".join(lines)

    rules: List[Dict[str, Any]] = []
    rule_pattern = re.compile(
        r"Perimeter Name\(s\)?[^\n]*\n.*?(?=(?:\n\s*Perimeter Name\(s\)?|\Z))",
        re.IGNORECASE | re.DOTALL,
    )
    for rule_match in rule_pattern.finditer(clean_text):
        block = rule_match.group(0)
        dir_match = re.search(r"Direction[^\n]*\n\s*(INGRESS|EGRESS)", block, re.IGNORECASE)
        direction = dir_match.group(1).upper() if dir_match else ""
        headings = [
            "Perimeter Name", "Perimeter Name(s)", "Services", "Methods",
            "Permissions", "Source / From", "From", "Destination / To",
            "To", "Identities", "Direction", "TLM-ID", "TLM-ID (if applicable)",
            "Third-Party Name", "Third-Party Name (if applicable)", "Justification",
        ]
        non_data_headings = {"Direction", "TLM-ID", "TLM-ID (if applicable)",
                             "Third-Party Name", "Third-Party Name (if applicable)",
                             "Justification"}
        values: Dict[str, List[str]] = {h: [] for h in headings if h not in non_data_headings}
        current_heading: str | None = None

        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            normalized = re.sub(r"[*`#]+", "", stripped)
            normalized = (normalized
                          .replace("\u2011", "-")
                          .replace("\u2012", "-")
                          .replace("\u2013", "-")
                          .replace("\u2014", "-")
                          .strip())
            matched_heading = None
            for h in headings:
                h_norm = (h.replace("\u2011", "-")
                           .replace("\u2012", "-")
                           .replace("\u2013", "-")
                           .replace("\u2014", "-"))
                if re.match(rf"^{re.escape(h_norm)}", normalized, re.IGNORECASE):
                    matched_heading = h
                    break
            if matched_heading:
                key = matched_heading.lower().replace("\u2011", "-").replace("\u2012", "-") \
                                             .replace("\u2013", "-").replace("\u2014", "-")
                if key.startswith("direction") or "tlm-id" in key or "third-party" in key or key == "justification":
                    current_heading = None
                else:
                    current_heading = matched_heading
                continue
            if re.match(r"^(tlm|third)[-\u2011\u2012\u2013\u2014]?id", normalized, re.IGNORECASE) or \
               re.match(r"^third\s*-?party", normalized, re.IGNORECASE):
                current_heading = None
                continue
            if current_heading:
                # Skip example bullets or placeholders
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

        def split_values(key: str) -> List[str]:
            result: List[str] = []
            for val in values.get(key, []):
                for part in re.split(r",", val):
                    if part.strip():
                        result.append(part.strip())
            return result

        services = split_values("Services")
        methods_raw  = values.get("Methods", [])
        permissions_raw = values.get("Permissions", [])
        sources   = split_values("Source / From") + split_values("From")
        destinations = split_values("Destination / To") + split_values("To")

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

        # Parse per-service methods/permissions from "service: item1, item2" lines
        service_methods: Dict[str, List[str]] = {svc: [] for svc in services}
        service_permissions: Dict[str, List[str]] = {svc: [] for svc in services}

        for line in methods_raw:
            if ":" in line:
                svc, mlist = line.split(":", 1)
                svc = svc.strip()
                if svc in service_methods:
                    service_methods[svc] = [m.strip() for m in mlist.split(",") if m.strip()]
        for line in permissions_raw:
            if ":" in line:
                svc, plist = line.split(":", 1)
                svc = svc.strip()
                if svc in service_permissions:
                    service_permissions[svc] = [p.strip() for p in plist.split(",") if p.strip()]

        rules.append({
            "direction": direction,
            "services": services,
            "service_methods": service_methods,
            "service_permissions": service_permissions,
            "sources": sources,
            "destinations": destinations,
            "identities": identities,
            "perimeters": perim_vals,
        })

    return {
        "reqid": reqid,
        "perimeters": perimeters,
        "ttl": "",
        "tlm_id": tlm_id,
        "justification": justification,
        "rules": rules,
    }


def build_actions(parsed: Dict[str, Any], router: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate a list of actions (perimeter updates) from parsed issue data.

    Each rule in the parsed input is converted into ingress and/or egress policy
    structures.  These are then grouped per perimeter and converted to Terraform
    HCL with embedded justification comments.  The returned list contains one
    element per perimeter, specifying repository, branch, commit message, PR title
    and a list of file changes.
    """
    actions: List[Dict[str, Any]] = []
    reqid = parsed.get("reqid") or f"REQ-{uuid.uuid4().hex[:8]}"
    justification = parsed.get("justification") or ""
    tlm_id = parsed.get("tlm_id") or ""
    rules: List[Dict[str, Any]] = parsed.get("rules", [])

    perim_map: Dict[str, Dict[str, Any]] = {}
    def safe_name(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "-", s.lower())

    # Build a map of perimeters to their accumulated ingress/egress policies and access levels
    for idx, rule in enumerate(rules):
        direction = rule.get("direction", "").upper()
        services  = rule.get("services", [])
        service_methods  = rule.get("service_methods", {})
        service_permissions = rule.get("service_permissions", {})
        sources   = rule.get("sources", [])
        destinations = rule.get("destinations", [])
        identities  = rule.get("identities", [])
        rule_perims: List[str] = rule.get("perimeters", []) or parsed.get("perimeters", [])

        # Build operations mapping per service
        operations: Dict[str, Dict[str, Any]] = {}
        for svc in services:
            svc_methods = service_methods.get(svc)
            svc_perms   = service_permissions.get(svc)
            operations[svc] = {
                "methods": svc_methods if svc_methods else ["*"],
                "permissions": svc_perms if svc_perms else [],
            }

        for perim in rule_perims:
            perim_info = router.get("perimeters", {}).get(perim)
            if not perim_info:
                continue
            data = perim_map.setdefault(perim, {"ingress_policies": [], "egress_policies": [], "access_levels": []})
            policy_id = perim_info.get("policy_id")

            if direction == "INGRESS":
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
                    raw_name = tlm_id or f"{reqid}-rule{idx+1}"
                    level_name = safe_name(raw_name)
                    access_levels_list.append(level_name)
                    module_lines = [
                        f'module "vpc-service-controls-access-level_{level_name}" {{',
                        '  source  = "tfe. / /vpc-service-controls/google//modules/access_level"',
                        '  version = "0.0.4"',
                        '  policy  = var.policy',
                        f'  name    = "{level_name}"',
                        f'  ip_subnetworks = [' + ", ".join([f'"{ip}"' for ip in ip_subnets]) + ']',
                        "}\n",
                    ]
                    data["access_levels"].append("\n".join(module_lines))
                ingress_from["sources"] = {"resources": resource_sources, "access_levels": access_levels_list}
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

    def to_hcl(value: Any, indent: int = 0) -> str:
        indent_str = "  " * indent
        if isinstance(value, str):
            return f'"{value}"'
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "null"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            if not value:
                return "[]"
            if all(not isinstance(v, (dict, list)) for v in value):
                return "[" + ", ".join(to_hcl(v, indent) for v in value) + "]"
            lines = ["["]
            for item in value:
                lines.append(("  " * (indent + 1)) + to_hcl(item, indent + 1) + ",")
            lines.append(indent_str + "]")
            return "\n".join(lines)
        if isinstance(value, dict):
            if not value:
                return "{}"
            lines = ["{"]
            for key, val in value.items():
                key_repr = f'"{key}"' if re.search(r"[^A-Za-z0-9_]", key) else key
                lines.append(("  " * (indent + 1)) + f"{key_repr} = {to_hcl(val, indent + 1)}")
            lines.append(indent_str + "}")
            return "\n".join(lines)
        return json.dumps(value)

    # Convert the aggregated per-perimeter data into file changes and PR metadata
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
        pr_body = f"This pull request applies the VPC Service Controls request `{reqid}` to perimeter `{perim}`."

        tfvars_lines: List[str] = []
        # Ingress policies with justification comments inserted inside the rule
        if data["ingress_policies"]:
            tfvars_lines.append("ingress_policies = [")
            for pol in data["ingress_policies"]:
                hcl_pol = to_hcl(pol, indent=1)
                lines = hcl_pol.split("\n")
                if justification:
                    comment_lines = ["  # " + ln for ln in justification.split("\n")]
                    # Insert comments immediately after the opening brace
                    lines = [lines[0]] + comment_lines + lines[1:]
                tfvars_lines.extend(["  " + ln for ln in lines])
                tfvars_lines[-1] += ","
            tfvars_lines.append("]")
        else:
            tfvars_lines.append("ingress_policies = []")

        # Egress policies with justification comments inserted inside the rule
        if data["egress_policies"]:
            tfvars_lines.append("egress_policies  = [")
            for pol in data["egress_policies"]:
                hcl_pol = to_hcl(pol, indent=1)
                lines = hcl_pol.split("\n")
                if justification:
                    comment_lines = ["  # " + ln for ln in justification.split("\n")]
                    lines = [lines[0]] + comment_lines + lines[1:]
                tfvars_lines.extend(["  " + ln for ln in lines])
                tfvars_lines[-1] += ","
            tfvars_lines.append("]")
        else:
            tfvars_lines.append("egress_policies  = []")

        tfvars_content = "\n".join(tfvars_lines) + "\n"
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