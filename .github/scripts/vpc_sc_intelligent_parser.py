#!/usr/bin/env python3
"""
Intelligent VPC SC Request Parser

This parser takes a user-friendly issue description and automatically determines:
- Direction (INGRESS vs EGRESS)
- Which perimeters are involved
- What services and operations are needed
- Generates appropriate ingress/egress rules

Users don't need to understand VPC SC - they just describe what they're trying to do.
"""

import argparse
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import yaml

# Service name mappings (user-friendly → API name)
SERVICE_MAPPINGS = {
    "BigQuery (bigquery.googleapis.com)": "bigquery.googleapis.com",
    "Cloud Storage (storage.googleapis.com)": "storage.googleapis.com",
    "Pub/Sub (pubsub.googleapis.com)": "pubsub.googleapis.com",
    "Cloud Run (run.googleapis.com)": "run.googleapis.com",
    "Artifact Registry (artifactregistry.googleapis.com)": "artifactregistry.googleapis.com",
    "Compute Engine (compute.googleapis.com)": "compute.googleapis.com",
    "Cloud Logging (logging.googleapis.com)": "logging.googleapis.com",
    "IAM (iam.googleapis.com)": "iam.googleapis.com",
    "Container Registry (containerregistry.googleapis.com)": "containerregistry.googleapis.com",
}

# Access type → methods/permissions mapping
ACCESS_TYPE_TO_OPERATIONS = {
    "bigquery.googleapis.com": {
        "Read Only (list, get, read data)": {
            "methods": ["BigQueryRead.ReadRows", "DatasetService.GetDataset", "TableService.GetTable"],
            "permissions": ["bigquery.tables.getData", "bigquery.datasets.get"]
        },
        "Write Only (create, update, delete)": {
            "methods": ["TableDataService.InsertAll", "TableService.InsertTable"],
            "permissions": ["bigquery.tables.updateData", "bigquery.tables.create"]
        },
        "Read and Write (full access)": {
            "methods": ["*"],
            "permissions": []
        },
    },
    "storage.googleapis.com": {
        "Read Only (list, get, read data)": {
            "methods": ["google.storage.objects.get", "google.storage.objects.list"],
            "permissions": []
        },
        "Write Only (create, update, delete)": {
            "methods": ["google.storage.objects.create", "google.storage.objects.delete"],
            "permissions": []
        },
        "Read and Write (full access)": {
            "methods": ["*"],
            "permissions": []
        },
    },
    # Add more services as needed
}


def extract_project_number(text: str) -> Optional[str]:
    """Extract project number from text."""
    # Look for 10+ digit numbers (GCP project numbers)
    match = re.search(r'\b(\d{10,})\b', text)
    return match.group(1) if match else None


def extract_ip_from_error(error_msg: str) -> Optional[str]:
    """Extract IP address from error message."""
    # Look for IP addresses in error messages
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
    match = re.search(ip_pattern, error_msg)
    return match.group(0) if match else None


def normalize_identity(identity: str) -> str:
    """Normalize identity to proper format."""
    identity = identity.strip()
    if not identity:
        return ""

    # If already prefixed, return as-is
    if ":" in identity:
        return identity

    # Auto-detect type
    if identity.endswith(".iam.gserviceaccount.com") or identity.endswith(".gserviceaccount.com"):
        return f"serviceAccount:{identity}"
    elif "@googlegroups.com" in identity or identity.startswith("group-"):
        return f"group:{identity}"
    elif "@" in identity:
        return f"user:{identity}"

    return identity


def determine_direction_and_perimeters(
    source_desc: str,
    dest_desc: str,
    source_project: Optional[str],
    dest_project: Optional[str],
    external_ip: Optional[str],
    router: Dict[str, Any]
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Intelligently determine direction and perimeters based on source/destination.

    Returns:
        (perimeters_involved, rules_to_create)

    Rules can be:
    - INGRESS only (external → perimeter)
    - EGRESS only (perimeter → external)
    - BOTH (perimeter → perimeter)
    """
    perimeters = set()
    rules = []

    # Determine if source is external (outside all perimeters)
    source_is_external = bool(external_ip) or "external" in source_desc.lower()

    # Determine if destination is external
    dest_is_external = "external" in dest_desc.lower() or "internet" in dest_desc.lower()

    # Case 1: External source trying to access perimeter resource (INGRESS)
    if source_is_external and dest_project:
        # Find which perimeter contains the destination project
        dest_perimeter = find_perimeter_for_project(dest_project, router)
        if dest_perimeter:
            perimeters.add(dest_perimeter)
            rules.append({
                "direction": "INGRESS",
                "perimeter": dest_perimeter,
                "source_is_ip": bool(external_ip),
                "source": external_ip if external_ip else None,
                "destination": f"projects/{dest_project}" if dest_project else None,
            })

    # Case 2: Perimeter resource trying to access external (EGRESS)
    elif source_project and dest_is_external:
        source_perimeter = find_perimeter_for_project(source_project, router)
        if source_perimeter:
            perimeters.add(source_perimeter)
            rules.append({
                "direction": "EGRESS",
                "perimeter": source_perimeter,
                "source": f"projects/{source_project}" if source_project else None,
                "destination": None,  # External destination
            })

    # Case 3: Perimeter → Perimeter (BOTH INGRESS and EGRESS)
    elif source_project and dest_project:
        source_perimeter = find_perimeter_for_project(source_project, router)
        dest_perimeter = find_perimeter_for_project(dest_project, router)

        if source_perimeter and dest_perimeter and source_perimeter != dest_perimeter:
            perimeters.add(source_perimeter)
            perimeters.add(dest_perimeter)

            # EGRESS from source perimeter
            rules.append({
                "direction": "EGRESS",
                "perimeter": source_perimeter,
                "source": f"projects/{source_project}",
                "destination": f"projects/{dest_project}",
            })

            # INGRESS to destination perimeter
            rules.append({
                "direction": "INGRESS",
                "perimeter": dest_perimeter,
                "source": f"projects/{source_project}",
                "destination": f"projects/{dest_project}",
            })

    return list(perimeters), rules


def find_perimeter_for_project(project_num: str, router: Dict[str, Any]) -> Optional[str]:
    """
    Find which perimeter a project belongs to using router.yml mappings.

    Args:
        project_num: GCP project number (numeric string)
        router: Router configuration dict

    Returns:
        Perimeter name or default_perimeter or None
    """
    if not project_num:
        return None

    # Search all perimeters for this project
    perimeters = router.get("perimeters", {})
    for perim_name, perim_config in perimeters.items():
        projects = perim_config.get("projects", [])
        if project_num in projects:
            return perim_name

    # Fall back to default perimeter if configured
    return router.get("default_perimeter")


def parse_intelligent_issue(issue_text: str, router: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse user-friendly issue format and return structured VPC SC rules.
    """
    # Extract fields using regex
    def extract_field(label: str) -> str:
        pattern = rf"###?\s*{re.escape(label)}.*?\n\s*(.+?)(?=\n###|\Z)"
        match = re.search(pattern, issue_text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""

    reqid = extract_field("Request ID")
    error_message = extract_field("Error Message")
    what_trying_to_do = extract_field("What are you trying to do")
    source_desc = extract_field("WHERE is the request coming from")
    source_project = extract_field("Source Project Number")
    source_identity = extract_field("Service Account or Identity")
    dest_desc = extract_field("WHAT are you trying to access")
    dest_project = extract_field("Destination Project Number")
    service_raw = extract_field("Which GCP Service")
    access_type = extract_field("What kind of access")
    external_ip = extract_field("External IP Address")
    justification = extract_field("Business Justification")
    urgency = extract_field("How urgent is this")

    # Normalize service name
    service = SERVICE_MAPPINGS.get(service_raw, service_raw)
    if " (" in service:
        service = service.split("(")[1].rstrip(")")

    # Extract IP from error if not provided
    if error_message and not external_ip:
        external_ip = extract_ip_from_error(error_message)

    # Normalize identity
    identity = normalize_identity(source_identity)

    # Determine direction and perimeters
    perimeters, rule_specs = determine_direction_and_perimeters(
        source_desc, dest_desc, source_project, dest_project, external_ip, router
    )

    # Build operations based on access type
    operations = {service: {"methods": ["*"], "permissions": []}}
    if service in ACCESS_TYPE_TO_OPERATIONS and access_type in ACCESS_TYPE_TO_OPERATIONS[service]:
        ops = ACCESS_TYPE_TO_OPERATIONS[service][access_type]
        operations = {service: ops}

    # Build rules from specs
    rules = []
    for spec in rule_specs:
        rule = {
            "direction": spec["direction"],
            "perimeters": [spec["perimeter"]] if spec["perimeter"] else perimeters,
            "services": [service],
            "service_methods": operations,
            "service_permissions": {service: []},
            "identities": [identity] if identity else [],
            "sources": [],
            "destinations": [],
        }

        if spec["direction"] == "INGRESS":
            if spec.get("source"):
                if spec.get("source_is_ip"):
                    rule["sources"].append(spec["source"])
                else:
                    rule["sources"].append(spec["source"])
            if spec.get("destination"):
                rule["destinations"].append(spec["destination"])
        else:  # EGRESS
            if spec.get("destination"):
                rule["destinations"].append(spec["destination"])

        rules.append(rule)

    # If we couldn't auto-detect, create a sensible default
    if not rules:
        # Default to INGRESS if external IP provided, otherwise ask user
        direction = "INGRESS" if external_ip else "EGRESS"
        rules.append({
            "direction": direction,
            "perimeters": perimeters if perimeters else [],
            "services": [service],
            "service_methods": operations,
            "service_permissions": {service: []},
            "identities": [identity] if identity else [],
            "sources": [external_ip] if external_ip else [],
            "destinations": [f"projects/{dest_project}"] if dest_project else [],
        })

    return {
        "reqid": reqid,
        "perimeters": perimeters,
        "tlm_id": "",  # Would extract if external IP
        "justification": justification,
        "urgency": urgency,
        "what_trying_to_do": what_trying_to_do,
        "error_message": error_message,
        "rules": rules,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Intelligent VPC SC request parser")
    parser.add_argument("--issue-file", required=True, help="Path to issue body file")
    parser.add_argument("--router-file", required=True, help="Path to router.yml")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.issue_file, "r", encoding="utf-8") as f:
        issue_text = f.read()

    try:
        with open(args.router_file, "r", encoding="utf-8") as f:
            router = yaml.safe_load(f) or {}
    except Exception:
        router = {}

    parsed = parse_intelligent_issue(issue_text, router)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)

    print(json.dumps(parsed, indent=2))


if __name__ == "__main__":
    main()
