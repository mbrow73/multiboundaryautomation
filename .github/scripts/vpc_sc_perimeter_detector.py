#!/usr/bin/env python3
"""
Smart VPC SC Perimeter Detection - No Manual Mapping Required

Detection strategies (in order):
1. Parse perimeter name from VPC SC error message
2. Use project naming conventions (e.g., prod-*, dev-*)
3. Query GCP API (optional, cached)
4. Ask user to specify from dropdown

This eliminates the need to manually map thousands of projects.
"""

import argparse
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import yaml


def extract_perimeter_from_error(error_message: str) -> Optional[str]:
    """
    Extract perimeter name from VPC SC error message.

    VPC SC errors include the perimeter name in the error text:
    - "perimeterName: accessPolicies/123/servicePerimeters/my_perimeter"
    - "denied by VPC Service Controls perimeter 'my_perimeter'"
    """
    if not error_message:
        return None

    # Pattern 1: perimeterName field
    match = re.search(r'perimeterName[:\s]+accessPolicies/\d+/servicePerimeters/([a-zA-Z0-9_-]+)',
                     error_message, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern 2: "perimeter 'name'" format
    match = re.search(r"perimeter\s+['\"]([a-zA-Z0-9_-]+)['\"]", error_message, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern 3: "servicePerimeters/name" anywhere in text
    match = re.search(r'servicePerimeters/([a-zA-Z0-9_-]+)', error_message)
    if match:
        return match.group(1)

    return None


def extract_project_id_from_description(text: str) -> Optional[str]:
    """
    Extract project ID (not number) from description text.

    Examples:
    - "Cloud Run in project my-app-dev"
    - "BigQuery in my-analytics-prod"
    - "project: customer-data-staging"
    """
    if not text:
        return None

    # Pattern 1: "project <name>"
    match = re.search(r'project[:\s]+([a-z][a-z0-9-]{4,28}[a-z0-9])', text, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern 2: "in <name>" (if looks like project ID)
    match = re.search(r'\bin\s+([a-z][a-z0-9-]{4,28}[a-z0-9])\b', text, re.IGNORECASE)
    if match and '-' in match.group(1):  # Project IDs usually have hyphens
        return match.group(1)

    return None


def detect_perimeter_from_naming(project_id: str, router: Dict[str, Any]) -> Optional[str]:
    """
    Detect perimeter using project naming conventions.

    Common patterns:
    - prod-* → production perimeter
    - dev-* → development perimeter
    - staging-* → staging perimeter
    - <team>-prod-* → team-specific production perimeter

    Configuration in router.yml:
    ```yaml
    perimeter_naming_patterns:
      prod-perimeter:
        - "^prod-"
        - "-prod$"
        - "-prod-"
      dev-perimeter:
        - "^dev-"
        - "-dev$"
    ```
    """
    if not project_id:
        return None

    patterns = router.get("perimeter_naming_patterns", {})

    for perimeter, pattern_list in patterns.items():
        for pattern in pattern_list:
            if re.search(pattern, project_id, re.IGNORECASE):
                return perimeter

    return None


def query_gcp_for_perimeter(
    project_number: str,
    use_cache: bool = True,
    cache_file: str = "/tmp/vpc_sc_project_cache.json"
) -> Optional[str]:
    """
    Query GCP API to find which perimeter a project belongs to.

    This is expensive for thousands of projects, so we:
    1. Cache results to file
    2. Only call API if cache miss
    3. Make this OPTIONAL (disabled by default)

    To enable: Set environment variable VPC_SC_ENABLE_GCP_QUERY=true
    """
    import os

    # Only enable if explicitly requested
    if not os.environ.get("VPC_SC_ENABLE_GCP_QUERY"):
        return None

    # Check cache first
    if use_cache:
        try:
            with open(cache_file, 'r') as f:
                cache = json.load(f)
                if project_number in cache:
                    return cache.get(project_number)
        except Exception:
            cache = {}
    else:
        cache = {}

    # Query GCP API (requires gcloud or google-cloud-access-context-manager library)
    try:
        # This would require additional setup - left as TODO
        # from google.cloud import accesscontextmanager_v1
        # ... API calls to find perimeter ...

        # For now, return None (user must use other methods)
        perimeter = None

        # Update cache
        if perimeter and use_cache:
            cache[project_number] = perimeter
            with open(cache_file, 'w') as f:
                json.dump(cache, f)

        return perimeter
    except Exception:
        return None


def detect_perimeters_smart(
    source_desc: str,
    dest_desc: str,
    source_project: Optional[str],
    dest_project: Optional[str],
    error_message: Optional[str],
    router: Dict[str, Any],
    available_perimeters: List[str]
) -> Tuple[Optional[str], Optional[str], List[str]]:
    """
    Intelligently detect source and destination perimeters.

    Returns:
        (source_perimeter, dest_perimeter, suggested_perimeters_for_user_selection)

    If we can't auto-detect, return suggestions for user to choose from.
    """
    source_perimeter = None
    dest_perimeter = None
    suggestions = []

    # Strategy 1: Parse error message for perimeter names
    if error_message:
        perimeter_from_error = extract_perimeter_from_error(error_message)
        if perimeter_from_error:
            # Error usually relates to the destination perimeter being accessed
            dest_perimeter = perimeter_from_error
            suggestions.append(perimeter_from_error)

    # Strategy 2: Use project naming conventions
    source_project_id = extract_project_id_from_description(source_desc)
    dest_project_id = extract_project_id_from_description(dest_desc)

    if source_project_id:
        detected = detect_perimeter_from_naming(source_project_id, router)
        if detected:
            source_perimeter = detected
            if detected not in suggestions:
                suggestions.append(detected)

    if dest_project_id:
        detected = detect_perimeter_from_naming(dest_project_id, router)
        if detected:
            dest_perimeter = dest_perimeter or detected  # Don't override error-based detection
            if detected not in suggestions:
                suggestions.append(detected)

    # Strategy 3: GCP API query (optional, expensive)
    if not source_perimeter and source_project:
        source_perimeter = query_gcp_for_perimeter(source_project)

    if not dest_perimeter and dest_project:
        dest_perimeter = query_gcp_for_perimeter(dest_project)

    # If still unknown, return all available perimeters as suggestions
    if not suggestions:
        suggestions = available_perimeters

    return source_perimeter, dest_perimeter, suggestions


def main() -> None:
    parser = argparse.ArgumentParser(description="Smart VPC SC perimeter detection")
    parser.add_argument("--issue-file", required=True, help="Issue body file")
    parser.add_argument("--router-file", required=True, help="Router config")
    parser.add_argument("--output", required=True, help="Output JSON")
    args = parser.parse_args()

    with open(args.issue_file, 'r', encoding='utf-8') as f:
        issue_text = f.read()

    with open(args.router_file, 'r', encoding='utf-8') as f:
        router = yaml.safe_load(f) or {}

    # Extract fields from issue
    def extract_field(label: str) -> str:
        pattern = rf"###?\s*{re.escape(label)}.*?\n\s*(.+?)(?=\n###|\Z)"
        match = re.search(pattern, issue_text, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    source_desc = extract_field("WHERE is the request coming from")
    dest_desc = extract_field("WHAT are you trying to access")
    source_project = extract_field("Source Project Number")
    dest_project = extract_field("Destination Project Number")
    error_message = extract_field("Error Message")

    available_perimeters = list(router.get("perimeters", {}).keys())

    source_perim, dest_perim, suggestions = detect_perimeters_smart(
        source_desc, dest_desc, source_project, dest_project,
        error_message, router, available_perimeters
    )

    result = {
        "source_perimeter": source_perim,
        "dest_perimeter": dest_perim,
        "suggested_perimeters": suggestions,
        "detection_method": {
            "source": "auto" if source_perim else "needs_user_input",
            "dest": "auto" if dest_perim else "needs_user_input"
        }
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
