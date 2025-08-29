#!/usr/bin/env python3
"""
apply_changes.py

Applies the changes described in request_processing.json to the target perimeter
repositories. This script will merge new ingress/egress policies and access level
modules instead of overwriting existing entries. It then commits, pushes, and
opens a PR for each perimeter.

Usage:
  python3 apply_changes.py --summary request_processing.json
"""

import argparse
import json
import os
import subprocess
import re
from typing import List


def extract_rules(tfvars_content: str, array_name: str) -> List[str]:
    """
    Extract rule objects from the specified array, scanning only between
    the array's '[' and matching ']'. Returns a list of rule JSON strings.
    """
    start_idx = tfvars_content.find(array_name)
    if start_idx == -1:
        return []
    start_bracket = tfvars_content.find('[', start_idx)
    if start_bracket == -1:
        return []
    # Find matching closing bracket
    bracket_count = 1
    idx = start_bracket + 1
    end_bracket = -1
    while idx < len(tfvars_content):
        char = tfvars_content[idx]
        if char == '[':
            bracket_count += 1
        elif char == ']':
            bracket_count -= 1
            if bracket_count == 0:
                end_bracket = idx
                break
        idx += 1
    if end_bracket == -1:
        return []
    body = tfvars_content[start_bracket + 1:end_bracket]
    rules = []
    brace_count = 0
    current = []
    for c in body:
        if c == '{':
            if brace_count == 0:
                current = []
            brace_count += 1
            current.append(c)
        elif c == '}':
            brace_count -= 1
            current.append(c)
            if brace_count == 0:
                rules.append(''.join(current).strip())
        elif brace_count > 0:
            current.append(c)
    return rules


def append_rule(existing_content: str, array_name: str, new_rule: str) -> str:
    """
    Append a new rule object to an existing array. If the array is absent,
    creates it. Ensures proper comma placement.
    """
    start_idx = existing_content.find(array_name)
    if start_idx != -1:
        start_bracket = existing_content.find('[', start_idx)
        if start_bracket == -1:
            return existing_content + f"\n{array_name} = [\n  {new_rule.strip()}\n]\n"
        # Find closing bracket
        bracket_count = 0
        idx = start_bracket
        while idx < len(existing_content):
            char = existing_content[idx]
            if char == '[':
                bracket_count += 1
            elif char == ']':
                bracket_count -= 1
                if bracket_count == 0:
                    break
            idx += 1
        body = existing_content[start_bracket+1:idx]
        trimmed = body.rstrip()
        if trimmed.strip():
            if trimmed.rstrip().endswith(','):
                new_body = trimmed + "\n  " + new_rule.strip()
            else:
                new_body = trimmed + ",\n  " + new_rule.strip()
        else:
            new_body = "\n  " + new_rule.strip()
        return existing_content[:start_bracket+1] + new_body + existing_content[idx:]
    else:
        return existing_content + f"\n{array_name} = [\n  {new_rule.strip()}\n]\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply changes from summary JSON.")
    parser.add_argument("--summary", required=True, help="Path to request_processing.json")
    args = parser.parse_args()

    with open(args.summary, "r", encoding="utf-8") as f:
        data = json.load(f)

    for action in data.get("actions", []):
        repo   = action["repo"]
        branch = action["branch"]
        commit_message = action["commit_message"]
        pr_title = action["pr_title"]
        pr_body  = action["pr_body"]
        changes  = action["changes"]

        repo_dir = f"tmp/{repo.replace('/', '_')}"
        subprocess.run(["git", "clone", f"https://github.com/{repo}.git", repo_dir], check=True)
        subprocess.run(["git", "-C", repo_dir, "checkout", "-b", branch], check=True)

        for change in changes:
            file_rel = change["file"]
            content_to_write = change["content"]
            file_path = os.path.join(repo_dir, file_rel)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Merge ingress/egress rules into existing tfvars files
            if file_rel.endswith(".tfvars") and "ingress_policies" in content_to_write and "egress_policies" in content_to_write:
                try:
                    existing = open(file_path, "r").read()
                except FileNotFoundError:
                    existing = ""
                if existing:
                    new_ingress_rules = extract_rules(content_to_write, "ingress_policies")
                    new_egress_rules  = extract_rules(content_to_write, "egress_policies")
                    updated = existing
                    for rule in new_ingress_rules:
                        updated = append_rule(updated, "ingress_policies", rule)
                    for rule in new_egress_rules:
                        updated = append_rule(updated, "egress_policies", rule)
                    content_to_write = updated

            # Append access-level modules to .tf files
            elif file_rel.endswith(".tf") and 'module "vpc-service-controls-access-level_' in content_to_write:
                try:
                    existing = open(file_path, "r").read()
                except FileNotFoundError:
                    existing = ""
                if existing:
                    existing_trimmed = existing.rstrip()
                    new_trimmed = content_to_write.strip()
                    if existing_trimmed:
                        content_to_write = existing_trimmed + "\n\n" + new_trimmed + "\n"
                    else:
                        content_to_write = new_trimmed + "\n"

            with open(file_path, "w") as f:
                f.write(content_to_write)

        subprocess.run(["git", "-C", repo_dir, "config", "user.email", "bot@example.com"], check=True)
        subprocess.run(["git", "-C", repo_dir, "config", "user.name", "VPC SC Bot"], check=True)
        subprocess.run(["git", "-C", repo_dir, "add", "."], check=True)
        # Only commit if there are staged changes
        status = subprocess.run(["git", "-C", repo_dir, "diff", "--cached", "--quiet"])
        if status.returncode != 0:
            subprocess.run(["git", "-C", repo_dir, "commit", "-m", commit_message], check=True)
            # Push changes to the remote branch. Use --force-with-lease to handle cases
            # where the branch already exists on the remote (e.g., a previous run of the
            # same request). This ensures the push succeeds even if the remote has diverged
            # slightly, while still protecting against overwriting remote changes made by
            # others (force-with-lease will refuse if the remote tip has moved since
            # our last fetch).
            subprocess.run([
                "git", "-C", repo_dir, "push", "--force-with-lease", "--set-upstream", "origin", branch
            ], check=True)
            # Check if a pull request already exists for this branch. If it does, skip
            # creating a new PR to avoid errors from the GitHub CLI. We use gh pr list
            # with --head to find any existing PRs for this branch.
            try:
                # Check for existing PRs on this branch. We request the PR number so we can close it.
                pr_check = subprocess.run([
                    "gh", "pr", "list", "--repo", repo, "--head", branch, "--json", "number"
                ], cwd=repo_dir, capture_output=True, text=True, check=True)
                existing_prs = json.loads(pr_check.stdout or "[]")
            except Exception:
                existing_prs = []
            # If a PR already exists for this branch, close it before creating a new one
            if existing_prs:
                for pr in existing_prs:
                    pr_number = pr.get("number")
                    if pr_number:
                        try:
                            subprocess.run([
                                "gh", "pr", "close", str(pr_number), "--repo", repo
                            ], cwd=repo_dir, check=True)
                        except subprocess.CalledProcessError as e:
                            # Ignore errors closing the PR, but log
                            print(f"Failed to close existing PR #{pr_number} for {branch}: {e}")
            # Always create a new PR after closing (or if none existed)
            subprocess.run([
                "gh", "pr", "create", "--repo", repo, "--head", branch,
                "--title", pr_title, "--body", pr_body
            ], cwd=repo_dir, check=True)


if __name__ == "__main__":
    main()