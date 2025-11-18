#!/usr/bin/env python3
"""
Daily Project → Perimeter Cache Updater

Queries GCP Access Context Manager API to build a cache of which projects
belong to which VPC SC perimeters. Runs once per day via GitHub Actions.

Cache is used as fallback when error message doesn't contain perimeter name.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Set


def query_perimeter_projects_gcloud(policy_id: str, perimeter_name: str) -> Set[str]:
    """
    Query GCP to get all projects in a perimeter using gcloud CLI.

    Args:
        policy_id: Access policy ID (e.g., "123456789")
        perimeter_name: Perimeter name (e.g., "prod-data-perimeter")

    Returns:
        Set of project numbers as strings
    """
    import subprocess

    # Query using gcloud (requires gcloud to be installed and authenticated)
    cmd = [
        "gcloud", "access-context-manager", "perimeters", "describe",
        perimeter_name,
        "--policy", policy_id,
        "--format", "json"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        # Extract project numbers from status.resources
        projects = set()
        resources = data.get("status", {}).get("resources", [])
        for resource in resources:
            # Resource format: "projects/PROJECT_NUMBER"
            if resource.startswith("projects/"):
                project_num = resource.split("/")[1]
                projects.add(project_num)

        return projects

    except subprocess.CalledProcessError as e:
        print(f"Error querying perimeter {perimeter_name}: {e.stderr}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"Error processing perimeter {perimeter_name}: {e}", file=sys.stderr)
        return set()


def build_cache(router_file: str) -> Dict[str, str]:
    """
    Build project → perimeter cache by querying all perimeters.

    Args:
        router_file: Path to router.yml

    Returns:
        Dict mapping project_number → perimeter_name
    """
    import yaml

    with open(router_file, 'r', encoding='utf-8') as f:
        router = yaml.safe_load(f) or {}

    cache = {}
    perimeters = router.get("perimeters", {})

    print(f"Querying {len(perimeters)} perimeters...")

    for perim_name, perim_config in perimeters.items():
        policy_id = perim_config.get("policy_id")
        if not policy_id:
            print(f"Warning: No policy_id for {perim_name}, skipping", file=sys.stderr)
            continue

        print(f"  Querying {perim_name}...")
        projects = query_perimeter_projects_gcloud(str(policy_id), perim_name)
        print(f"    Found {len(projects)} projects")

        for project in projects:
            cache[project] = perim_name

    print(f"✓ Cache built: {len(cache)} projects mapped")
    return cache


def load_existing_cache(cache_file: str) -> Dict:
    """Load existing cache if it exists."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache: Dict[str, str], cache_file: str) -> None:
    """Save cache with metadata."""
    cache_data = {
        "last_updated": datetime.utcnow().isoformat(),
        "project_count": len(cache),
        "projects": cache
    }

    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(cache_data, f, indent=2)

    print(f"✓ Cache saved to {cache_file}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update project → perimeter cache from GCP API"
    )
    parser.add_argument(
        "--router-file",
        default="router.yml",
        help="Path to router.yml"
    )
    parser.add_argument(
        "--cache-file",
        default="vpc_sc_project_cache.json",
        help="Output cache file"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force rebuild even if cache is recent"
    )
    args = parser.parse_args()

    # Check if cache is fresh (less than 24 hours old)
    existing = load_existing_cache(args.cache_file)
    if existing and not args.force:
        last_updated = existing.get("last_updated")
        if last_updated:
            from datetime import datetime, timedelta
            last_update_time = datetime.fromisoformat(last_updated)
            age = datetime.utcnow() - last_update_time

            if age < timedelta(hours=24):
                print(f"Cache is {age.total_seconds()/3600:.1f} hours old, skipping update")
                print("Use --force to rebuild anyway")
                return

    # Build new cache
    print("Building project → perimeter cache from GCP API...")
    print("This may take a few minutes for thousands of projects...")
    cache = build_cache(args.router_file)

    # Save cache
    save_cache(cache, args.cache_file)

    print("\n✓ Done! Cache is ready for use.")
    print(f"  Projects mapped: {len(cache)}")
    print(f"  Cache file: {args.cache_file}")


if __name__ == "__main__":
    main()
