#!/usr/bin/env python3
"""
Extract VPC SC information from error messages.

Parses VPC SC audit logs (JSON) or plain text error messages to extract:
- Perimeter name
- Service name and method
- Project numbers
- Caller IP and type (public vs private)
- Service account
- Resource names
- Whether method-level restriction is supported

Uses cached project → perimeter mappings as fallback.
"""

import argparse
import ipaddress
import json
import re
from typing import Dict, Optional, Set

# Services that support VPC SC method-level restrictions
# Source: https://cloud.google.com/vpc-service-controls/docs/supported-method-restrictions
SUPPORTED_METHOD_RESTRICTION_SERVICES: Set[str] = {
    "artifactregistry.googleapis.com",
    "bigquery.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "containerregistry.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "storage.googleapis.com",
}


def is_public_ip(ip_str: str) -> bool:
    """
    Determine if an IP is public (requires TLM ID).

    Returns False for:
    - Private IPs (RFC 1918: 10.x, 172.16-31.x, 192.168.x)
    - Special strings: "gce-internal-ip", "private"
    - Loopback, link-local, multicast, reserved IPs

    Returns True for globally routable public IPs
    """
    if not ip_str:
        return False

    # Handle special GCP strings
    if ip_str.lower() in ["gce-internal-ip", "private"]:
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
        # is_global checks if the IP is globally routable
        # This correctly handles private IPs, reserved ranges, documentation IPs, etc.
        return ip.is_global
    except ValueError:
        # Not a valid IP, assume not public
        return False


def parse_audit_log(error_text: str) -> Optional[Dict]:
    """
    Try to parse error as JSON audit log.

    Returns parsed structure or None if not valid JSON.
    """
    try:
        # Try parsing as JSON
        data = json.loads(error_text)

        # Validate it looks like an audit log
        if "protoPayload" in data:
            return data

        return None
    except (json.JSONDecodeError, ValueError):
        return None


def extract_from_audit_log(audit_log: Dict) -> Dict:
    """
    Extract VPC SC info from structured audit log.

    Audit log structure (from GCP Cloud Audit Logs):
    {
      "protoPayload": {
        "serviceName": "storage.googleapis.com",
        "methodName": "storage.objects.get",
        "authenticationInfo": {
          "principalEmail": "sa@project.iam.gserviceaccount.com"
        },
        "requestMetadata": {
          "callerIp": "203.0.113.55"
        },
        "metadata": {
          "securityPolicyInfo": {
            "servicePerimeterName": "accessPolicies/123/servicePerimeters/prod_perimeter"
          },
          "ingressViolations": [
            {
              "targetResource": "projects/9988776655"
            }
          ]
        }
      },
      "resource": {
        "labels": {
          "project_id": "my-project-123"
        }
      }
    }
    """
    result = {
        "perimeter": None,
        "service": None,
        "method": None,
        "source_project": None,
        "dest_project": None,
        "service_account": None,
        "caller_ip": None,
        "is_public_ip": False,
        "supports_method_restriction": False,
    }

    proto = audit_log.get("protoPayload", {})

    # Service name
    service = proto.get("serviceName")
    if service:
        result["service"] = service
        result["supports_method_restriction"] = service in SUPPORTED_METHOD_RESTRICTION_SERVICES

    # Method name
    result["method"] = proto.get("methodName")

    # Service account
    auth_info = proto.get("authenticationInfo", {})
    result["service_account"] = auth_info.get("principalEmail")

    # Caller IP
    request_metadata = proto.get("requestMetadata", {})
    caller_ip = request_metadata.get("callerIp")
    if caller_ip:
        result["caller_ip"] = caller_ip
        result["is_public_ip"] = is_public_ip(caller_ip)

    # Perimeter name from metadata
    metadata = proto.get("metadata", {})
    security_policy = metadata.get("securityPolicyInfo", {})
    perimeter_path = security_policy.get("servicePerimeterName", "")

    # Extract perimeter name from path
    if perimeter_path:
        match = re.search(r'servicePerimeters/([a-zA-Z0-9_-]+)', perimeter_path)
        if match:
            result["perimeter"] = match.group(1)

    # Project numbers
    # Source project - try multiple sources

    # 1. Try callerNetwork (often has project number)
    caller_network = request_metadata.get("callerNetwork", "")
    if caller_network:
        match = re.search(r'projects/(\d+)/', caller_network)
        if match:
            result["source_project"] = match.group(1)

    # 2. Fallback to resource labels if numeric
    if not result["source_project"]:
        resource_labels = audit_log.get("resource", {}).get("labels", {})
        source_project_id = resource_labels.get("project_id", "")
        # Only use if it's a pure number (project number, not project ID)
        if source_project_id.isdigit():
            result["source_project"] = source_project_id

    # Destination project from ingressViolations
    ingress_violations = metadata.get("ingressViolations", [])
    if ingress_violations:
        target_resource = ingress_violations[0].get("targetResource", "")
        match = re.search(r'projects/(\d+)', target_resource)
        if match:
            result["dest_project"] = match.group(1)

    # Also check egressViolations
    egress_violations = metadata.get("egressViolations", [])
    if egress_violations and not result["dest_project"]:
        target_resource = egress_violations[0].get("targetResource", "")
        match = re.search(r'projects/(\d+)', target_resource)
        if match:
            result["dest_project"] = match.group(1)

    return result


def load_project_cache(cache_file: str) -> Dict[str, str]:
    """Load project → perimeter cache."""
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("projects", {})
    except Exception:
        return {}


def find_perimeter_for_project(project_num: str, cache: Dict[str, str]) -> Optional[str]:
    """Look up perimeter for a project number in cache."""
    return cache.get(project_num)


def extract_all_info(
    error_message: str,
    source_project: Optional[str],
    dest_project: Optional[str],
    cache_file: str
) -> Dict:
    """
    Extract all VPC SC information from JSON audit log + cache.

    REQUIRES: JSON audit log from Cloud Logging (plaintext not supported)

    Priority:
    1. JSON audit log (required - has all context)
    2. User-provided project numbers + cache (fallback)
    3. Unknown (requires user input)
    """
    # Try parsing as JSON audit log
    audit_log = parse_audit_log(error_message)

    if not audit_log:
        # Not a valid JSON audit log - fail with clear error
        return {
            "error": "Invalid input",
            "error_message": "Must provide JSON audit log from Cloud Logging. Plaintext errors are not supported.",
            "help": "See VPC_SC_SIMPLE_GUIDE.md for instructions on how to get audit logs",
            "perimeter_from_error": None,
            "service_from_error": None,
            "method_from_error": None,
            "source_project_from_error": None,
            "dest_project_from_error": None,
            "service_account_from_error": None,
            "caller_ip": None,
            "is_public_ip": False,
            "requires_tlm_id": False,
            "supports_method_restriction": False,
            "source_perimeter": None,
            "dest_perimeter": None,
            "source_project": None,
            "dest_project": None,
            "detection_method": {}
        }

    # Extract from structured audit log
    extracted = extract_from_audit_log(audit_log)
    detection_method = "audit_log"

    # Load cache for fallback lookups
    cache = load_project_cache(cache_file)

    # Build final result
    result = {
        # Raw extracted values
        "perimeter_from_error": extracted["perimeter"],
        "service_from_error": extracted["service"],
        "method_from_error": extracted["method"],
        "source_project_from_error": extracted["source_project"],
        "dest_project_from_error": extracted["dest_project"],
        "service_account_from_error": extracted["service_account"],
        "caller_ip": extracted["caller_ip"],
        "is_public_ip": extracted["is_public_ip"],
        "requires_tlm_id": extracted["is_public_ip"],  # TLM ID required if public IP
        "supports_method_restriction": extracted["supports_method_restriction"],

        # Final resolved values
        "source_perimeter": None,
        "dest_perimeter": None,
        "source_project": None,
        "dest_project": None,

        # Metadata
        "detection_method": {
            "error_parsing": detection_method
        }
    }

    # Use error-extracted projects or fall back to user-provided
    final_src_project = extracted["source_project"] or source_project
    final_dest_project = extracted["dest_project"] or dest_project

    result["source_project"] = final_src_project
    result["dest_project"] = final_dest_project

    # Determine destination perimeter
    if extracted["perimeter"]:
        result["dest_perimeter"] = extracted["perimeter"]
        result["detection_method"]["dest_perimeter"] = "error_message"
    elif final_dest_project:
        # Try cache lookup
        cached_perimeter = find_perimeter_for_project(final_dest_project, cache)
        if cached_perimeter:
            result["dest_perimeter"] = cached_perimeter
            result["detection_method"]["dest_perimeter"] = "cache"

    # Determine source perimeter (always use cache for source)
    if final_src_project:
        cached_perimeter = find_perimeter_for_project(final_src_project, cache)
        if cached_perimeter:
            result["source_perimeter"] = cached_perimeter
            result["detection_method"]["source_perimeter"] = "cache"

    # Validate: Check for same-perimeter access (invalid - everything in a perimeter can already talk)
    if result["source_perimeter"] and result["dest_perimeter"]:
        if result["source_perimeter"] == result["dest_perimeter"]:
            result["error"] = "Same-perimeter access"
            result["error_message"] = (
                f"Source and destination are both in '{result['source_perimeter']}'. "
                "Resources within the same perimeter can already communicate - no rule needed."
            )
            result["is_valid"] = False
        else:
            result["is_valid"] = True
    else:
        # Can't determine if valid without both perimeters
        result["is_valid"] = None  # Unknown

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract VPC SC info from error")
    parser.add_argument("--error-file", required=True, help="File with error message")
    parser.add_argument("--source-project", help="Source project number (if known)")
    parser.add_argument("--dest-project", help="Dest project number (if known)")
    parser.add_argument("--cache-file", default="vpc_sc_project_cache.json", help="Project cache")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.error_file, 'r', encoding='utf-8') as f:
        error_text = f.read()

    result = extract_all_info(
        error_text,
        args.source_project,
        args.dest_project,
        args.cache_file
    )

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
