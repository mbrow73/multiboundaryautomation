#!/usr/bin/env python3
"""
vpc_sc_request_handler.py

This script processes VPC Service Controls requests submitted via GitHub Issues.
It reads the issue body, uses a router YAML to determine which perimeter
repositories should be updated, and produces a JSON summary describing the
actions to perform.  The summary is consumed by the GitHub Actions workflow
to clone target repositories, update files and open pull requests.

The script does **not** directly modify any repositories.  It simply
parses the inputs and builds an "actions" list that the workflow
consumes.  Each action includes:

  - repo: the GitHub repository name to update (e.g. "test-perim-a-config").
  - branch: the branch name to use for the PR.
  - commit_message: a commit message for the change.
  - pr_title: a title for the pull request.
  - pr_body: the PR description.
  - changes: a list of file updates, each with "file" and "content".

For demonstration purposes this script implements minimal parsing.
It looks for a line in the issue body that begins with "### Request ID"
and extracts the REQID.  It also looks for lines containing
"Perimeter:" to determine which perimeter(s) the request targets.
You may extend this parser to support more fields.

Usage:
  python3 vpc_sc_request_handler.py --issue-file <issue.md> \
    --router-file <router.yml> --workdir <tempdir> --output <summary.json>

The script writes the JSON summary to --output.  If no valid actions
are detected it writes an empty JSON object.
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
    """Parse the issue body for basic VPC SC fields.

    Currently this parser extracts:
      - reqid (e.g. REQ1234567)
      - perimeters (list of perimeter names mentioned in the issue)

    The issue template should include a line like:
      Perimeter Name: <perimeter>

    Returns a dictionary with keys reqid and perimeters.
    """
    reqid_match = re.search(r"Request ID.*?:\s*([A-Za-z0-9_-]+)", issue_text)
    reqid = reqid_match.group(1).strip() if reqid_match else f"REQ-{uuid.uuid4().hex[:8]}"

    # Extract perimeter names.  Accept comma-separated list or one per line.
    perimeters: List[str] = []
    perimeter_regex = re.compile(r"Perimeter Name\s*:?\s*([A-Za-z0-9_-]+)", re.IGNORECASE)
    for match in perimeter_regex.finditer(issue_text):
        perim = match.group(1).strip()
        if perim:
            perimeters.append(perim)

    return {
        "reqid": reqid,
        "perimeters": perimeters,
    }


def build_actions(parsed: Dict[str, Any], router: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build action dicts based on parsed request and router mapping.

    For each perimeter mentioned in the request, look up the router to get
    repository information.  Then construct a branch name and create a
    dummy change to the tfvars file and accesslevel file.  The actual
    content written is placeholder text indicating where real logic
    should go.  The workflow will write these files verbatim.

    Returns a list of action dictionaries.
    """
    actions: List[Dict[str, Any]] = []
    reqid = parsed.get("reqid") or f"REQ-{uuid.uuid4().hex[:8]}"
    for perim in parsed.get("perimeters", []):
        perim_info = router.get("perimeters", {}).get(perim)
        if not perim_info:
            continue  # Unknown perimeter
        repo = perim_info.get("repo")
        tfvars_file = perim_info.get("tfvars_file")
        access_file = perim_info.get("accesslevel_file")

        branch = f"vpcsc/{reqid.lower()}-{perim}"
        commit_msg = f"[VPC-SC] Apply request {reqid}"
        pr_title = f"VPC SC request {reqid} for {perim}"
        pr_body = (
            f"This pull request applies the VPC Service Controls request `{reqid}` to perimeter `{perim}`.\n\n"
            f"**Note:** This is a stub change. You must implement logic in the hub's script to construct the correct ingress/egress policies and access level blocks."
        )

        # Build placeholder contents
        tfvars_content = json.dumps(
            {
                "ingress_policies": [],
                "egress_policies": [],
            },
            indent=2,
        ) + "\n"
        access_content = (
            "# Access levels required for third-party ingress will be defined here.\n"
        )
        changes = []
        if tfvars_file:
            changes.append({"file": tfvars_file, "content": tfvars_content})
        if access_file:
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
    parser = argparse.ArgumentParser(description="Process a VPC SC request issue")
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