#!/usr/bin/env python3
"""
firewall_request_validator.py

This script validates firewall rule requests submitted via GitHub issues. It expects
to be passed the path to the GitHub event payload (a JSON file provided by
GitHub Actions in the GITHUB_EVENT_PATH environment variable). The payload must
contain an "issue" object with a "body" field representing the Markdown issue
content.

The validator parses the issue body for one or more firewall rules, ensuring
that each rule contains all required fields. Supported field labels include
both the legacy format (e.g. "New Source IP(s) or CIDR(s)") and the
simplified format (e.g. "New Source IP"). The validator is case-insensitive
and tolerant of extra whitespace. If any required field is missing or blank,
validation errors are printed between ``VALIDATION_ERRORS_START`` and
``VALIDATION_ERRORS_END`` markers and the script exits with a non-zero status.
Otherwise it prints a success message.

Example usage (from within a GitHub Action):

  python3 .github/scripts/firewall_request_validator.py "$GITHUB_EVENT_PATH"

For local testing you can wrap your issue body in a minimal JSON structure:

  {
    "issue": { "body": "### Request ID (REQID): REQ123\n..." }
  }

and pass the resulting JSON file as the first argument to this script.
"""

import json
import re
import sys
from pathlib import Path

def load_event(event_path: str) -> dict:
    """Load the GitHub event payload from a JSON file."""
    try:
        with open(event_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise SystemExit(f"Failed to load event JSON from {event_path}: {exc}")

def normalise_key(key: str) -> str:
    """Normalise field keys by stripping punctuation and suffixes.

    The validator accepts both legacy labels (e.g. "New Source IP(s) or CIDR(s)")
    and simplified labels (e.g. "New Source IP"). This helper removes text
    inside parentheses and normalises whitespace so that both map to a single
    canonical key.
    """
    # Remove anything in parentheses and strip whitespace
    key = re.sub(r"\(.*?\)", "", key)
    key = key.strip().rstrip(":").strip()
    return key.lower()

def parse_rules(body: str) -> list:
    """Extract a list of rule dictionaries from the issue body.

    The body is expected to contain one or more sections starting with a
    heading like ``#### Rule X`` followed by lines of the form ``Key: Value``.
    Emoji bullets (e.g. ``🔹``) and dashes are ignored. Blank lines and
    comments are skipped. Lines without a colon are ignored.

    Returns a list of dictionaries where each key is the canonicalised field
    name (lowercase) and the value is the trimmed string after the colon.
    """
    rules = []
    current_rule = None
    for line in body.splitlines():
        stripped = line.strip()
        # Start a new rule when encountering a rule header. Users may
        # include markdown headings (e.g. "#### Rule 1") or plain text
        # (e.g. "Rule 1"). The pattern below makes the leading ``#``
        # characters optional to support both cases.
        if re.match(r"^(?:#+\s*)?Rule\s+\d+", stripped, re.IGNORECASE):
            if current_rule:
                rules.append(current_rule)
            current_rule = {}
            continue
        # Skip comments and empty lines
        if not stripped or stripped.startswith("<!--"):
            continue
        # Remove leading emojis or bullets
        stripped = re.sub(r"^[\W_]+", "", stripped)
        if ":" not in stripped:
            continue
        raw_key, raw_value = stripped.split(":", 1)
        # Skip top-level metadata like Request ID and CARID. They are
        # parsed separately and should not be treated as rule fields.
        if re.match(r"(?i)\s*(request id|carid)\b", raw_key):
            continue
        key = normalise_key(raw_key)
        value = raw_value.strip()
        # Only start collecting a rule after encountering a "New ..." field
        if current_rule is None:
            # Do not implicitly start a rule for unrelated keys
            if not key.startswith("new "):
                continue
            current_rule = {}
        current_rule[key] = value
    if current_rule:
        rules.append(current_rule)
    return rules

def validate_rules(rules: list) -> list:
    """Return a list of error messages if required fields are missing."""
    # Required fields in canonical form
    # Define the canonical names of the required fields. The ``normalise_key``
    # helper removes text inside parentheses (e.g. "(s)") and strips trailing
    # colons, so the required keys should not include parentheses here. This
    # allows both "New Port" and "New Port(s)" to satisfy the requirement.
    required_fields = [
        "new source ip",
        "new destination ip",
        "new port",
        "new protocol",
        "new direction",
        "new business justification",
    ]
    errors = []
    for idx, rule in enumerate(rules, start=1):
        for field in required_fields:
            if field not in rule or not rule[field]:
                errors.append(f"Rule {idx}: Missing {field.title()}")
    return errors

def main(event_path: str) -> None:
    event = load_event(event_path)
    try:
        body = event["issue"]["body"]
    except KeyError:
        raise SystemExit("GitHub event JSON does not contain issue.body")
    rules = parse_rules(body)
    errors = validate_rules(rules)
    if errors:
        print("VALIDATION_ERRORS_START")
        for err in errors:
            print(err)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)
    print("Validation successful")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: firewall_request_validator.py <path_to_event_json>",
            file=sys.stderr,
        )
        sys.exit(2)
    main(sys.argv[1])