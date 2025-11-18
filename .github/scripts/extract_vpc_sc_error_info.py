#!/usr/bin/env python3
"""
Extract VPC SC information from error messages.

Parses VPC SC error messages to extract:
- Perimeter name
- Service name
- Project numbers
- Resource names

Uses cached project → perimeter mappings as fallback.
"""

import argparse
import json
import re
from typing import Dict, List, Optional, Tuple


def extract_perimeter_from_error(error_text: str) -> Optional[str]:
    """
    Extract perimeter name from VPC SC error message.

    Example error:
        perimeterName: "accessPolicies/123/servicePerimeters/prod-data-perimeter"

    Returns just the perimeter name: "prod-data-perimeter"
    """
    if not error_text:
        return None

    # Pattern 1: Full perimeterName with accessPolicies path
    match = re.search(
        r'perimeterName[:\s]*["\']?accessPolicies/\d+/servicePerimeters/([a-zA-Z0-9_-]+)',
        error_text,
        re.IGNORECASE
    )
    if match:
        return match.group(1)

    # Pattern 2: Just servicePerimeters/name
    match = re.search(r'servicePerimeters/([a-zA-Z0-9_-]+)', error_text)
    if match:
        return match.group(1)

    # Pattern 3: Perimeter mentioned in plain text
    match = re.search(r'perimeter\s+["\']?([a-zA-Z0-9_-]+)["\']?', error_text, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def extract_service_from_error(error_text: str) -> Optional[str]:
    """
    Extract service name from VPC SC error.

    Example:
        serviceName: "bigquery.googleapis.com"
    """
    if not error_text:
        return None

    match = re.search(r'serviceName[:\s]*["\']([a-z.-]+\.googleapis\.com)["\']', error_text, re.IGNORECASE)
    if match:
        return match.group(1)

    # Also check methodName for service
    match = re.search(r'methodName[:\s]*["\']google\.cloud\.([a-z]+)', error_text, re.IGNORECASE)
    if match:
        service = match.group(1)
        return f"{service}.googleapis.com"

    return None


def extract_projects_from_error(error_text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract source and destination project numbers from error.

    Returns:
        (source_project, dest_project)
    """
    if not error_text:
        return None, None

    # Extract all project numbers mentioned
    project_numbers = re.findall(r'projects?/(\d{10,})', error_text)

    if not project_numbers:
        return None, None

    # If only one project mentioned, assume it's the destination
    if len(project_numbers) == 1:
        return None, project_numbers[0]

    # If multiple, first is usually source, last is destination
    return project_numbers[0], project_numbers[-1]


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
    Extract all VPC SC information from error + cache.

    Priority:
    1. Error message (most reliable)
    2. User-provided project numbers + cache
    3. Unknown (requires user input)
    """
    result = {
        "perimeter_from_error": None,
        "service_from_error": None,
        "source_project_from_error": None,
        "dest_project_from_error": None,
        "source_perimeter": None,
        "dest_perimeter": None,
        "detection_method": {}
    }

    # Extract from error
    result["perimeter_from_error"] = extract_perimeter_from_error(error_message)
    result["service_from_error"] = extract_service_from_error(error_message)
    proj_src, proj_dest = extract_projects_from_error(error_message)
    result["source_project_from_error"] = proj_src
    result["dest_project_from_error"] = proj_dest

    # Use error-extracted projects or fall back to user-provided
    final_src_project = proj_src or source_project
    final_dest_project = proj_dest or dest_project

    # Load cache
    cache = load_project_cache(cache_file)

    # Determine perimeters
    # If error has perimeter, use it (usually destination perimeter)
    if result["perimeter_from_error"]:
        result["dest_perimeter"] = result["perimeter_from_error"]
        result["detection_method"]["dest"] = "error_message"

    # Use cache for source perimeter
    if final_src_project and not result["source_perimeter"]:
        result["source_perimeter"] = find_perimeter_for_project(final_src_project, cache)
        if result["source_perimeter"]:
            result["detection_method"]["source"] = "cache"

    # Use cache for dest perimeter if not found in error
    if final_dest_project and not result["dest_perimeter"]:
        result["dest_perimeter"] = find_perimeter_for_project(final_dest_project, cache)
        if result["dest_perimeter"]:
            result["detection_method"]["dest"] = "cache"

    # Store final project numbers
    result["source_project"] = final_src_project
    result["dest_project"] = final_dest_project

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
