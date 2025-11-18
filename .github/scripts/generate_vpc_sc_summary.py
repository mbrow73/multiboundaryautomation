#!/usr/bin/env python3
"""
Generate human-readable summary for VPC SC requests.

Creates clear, detailed summaries for:
1. User feedback (what will be created)
2. NetSec review (what's being requested and why)
3. PR descriptions (technical details)
"""

import argparse
import json
from typing import Any, Dict, List


def format_direction_explanation(direction: str, rule: Dict[str, Any]) -> str:
    """Explain what a direction means in plain English."""
    if direction == "INGRESS":
        return f"**Allowing traffic INTO the perimeter**\n   - From: {', '.join(rule.get('sources', ['Any source']))}\n   - To: {', '.join(rule.get('destinations', ['Resources in perimeter']))}"
    else:  # EGRESS
        return f"**Allowing traffic OUT OF the perimeter**\n   - From: Resources in perimeter\n   - To: {', '.join(rule.get('destinations', ['External resources']))}"


def format_services_and_access(rule: Dict[str, Any]) -> str:
    """Format services and access levels clearly."""
    services = rule.get("services", [])
    methods = rule.get("service_methods", {})

    lines = []
    for svc in services:
        svc_methods = methods.get(svc, {}).get("methods", ["*"])
        if svc_methods == ["*"]:
            lines.append(f"   - {svc}: **All operations**")
        else:
            lines.append(f"   - {svc}: {len(svc_methods)} specific operations")

    return "\n".join(lines) if lines else "   - No services specified"


def generate_user_summary(parsed: Dict[str, Any], actions: List[Dict[str, Any]]) -> str:
    """Generate user-facing summary explaining what will happen."""
    reqid = parsed.get("reqid", "UNKNOWN")
    rules = parsed.get("rules", [])
    urgency = parsed.get("urgency", "Normal")

    summary = f"### ✅ Request {reqid} - Processed Successfully\n\n"

    summary += f"**Urgency:** {urgency}\n\n"

    summary += "---\n\n### 📋 What You Requested\n\n"
    summary += f"**Goal:** {parsed.get('what_trying_to_do', 'Not specified')}\n\n"

    if parsed.get("error_message"):
        summary += f"**Error You Were Seeing:**\n```\n{parsed['error_message'][:200]}...\n```\n\n"

    summary += "---\n\n### 🔧 What We're Creating\n\n"

    for idx, rule in enumerate(rules, 1):
        direction = rule.get("direction", "UNKNOWN")
        perimeters = rule.get("perimeters", ["Unknown"])

        summary += f"#### Rule {idx}: {direction} Access\n\n"
        summary += f"**Perimeter(s):** {', '.join(perimeters)}\n\n"
        summary += format_direction_explanation(direction, rule) + "\n\n"

        summary += "**Services & Access:**\n"
        summary += format_services_and_access(rule) + "\n\n"

        identities = rule.get("identities", [])
        if identities:
            summary += f"**Who Can Access:** {', '.join(identities)}\n\n"

    summary += "---\n\n### 📁 Pull Requests Created\n\n"

    if actions:
        for action in actions:
            repo = action.get("repo", "Unknown")
            branch = action.get("branch", "Unknown")
            summary += f"- **{repo}** (branch: `{branch}`)\n"
    else:
        summary += "_No pull requests needed (validation failed or no changes required)_\n"

    summary += "\n---\n\n### ⏭️  Next Steps\n\n"
    summary += "1. **NetSec Review** - Security team will review the PRs (typically < 24 hours)\n"
    summary += "2. **Approval & Merge** - Once approved, changes deploy automatically\n"
    summary += "3. **Notification** - You'll get a comment here when it's done\n"
    summary += "4. **Test** - Try your access again - it should work!\n\n"

    if urgency == "Critical (production down, need ASAP)":
        summary += "🚨 **CRITICAL URGENCY DETECTED** - NetSec team has been notified for expedited review.\n\n"

    summary += "_Questions? Reply to this issue._\n"

    return summary


def generate_netsec_summary(parsed: Dict[str, Any], rules: List[Dict[str, Any]]) -> str:
    """Generate detailed summary for NetSec PR review."""
    reqid = parsed.get("reqid", "UNKNOWN")

    summary = f"## 🔐 VPC SC Access Request: {reqid}\n\n"

    summary += "### 📊 Request Overview\n\n"
    summary += f"**Request ID:** {reqid}\n"
    summary += f"**Urgency:** {parsed.get('urgency', 'Normal')}\n\n"

    summary += "**Business Justification:**\n"
    summary += f"> {parsed.get('justification', 'Not provided')}\n\n"

    summary += "---\n\n### 🎯 What User is Trying to Do\n\n"
    summary += f"{parsed.get('what_trying_to_do', 'Not specified')}\n\n"

    if parsed.get("error_message"):
        summary += "**Error Message (Original):**\n"
        summary += f"```\n{parsed['error_message']}\n```\n\n"

    summary += "---\n\n### 🔍 Technical Details\n\n"

    for idx, rule in enumerate(rules, 1):
        direction = rule.get("direction", "UNKNOWN")
        perimeters = rule.get("perimeters", [])

        summary += f"#### Rule {idx}: {direction}\n\n"
        summary += f"- **Perimeters Affected:** {', '.join(perimeters) if perimeters else 'TBD'}\n"
        summary += f"- **Direction:** {direction}\n"

        sources = rule.get("sources", [])
        dests = rule.get("destinations", [])
        identities = rule.get("identities", [])
        services = rule.get("services", [])

        if sources:
            summary += f"- **Sources:** {', '.join(sources)}\n"
        if dests:
            summary += f"- **Destinations:** {', '.join(dests)}\n"
        if identities:
            summary += f"- **Identities:** {', '.join(identities)}\n"
        if services:
            summary += f"- **Services:** {', '.join(services)}\n"

        summary += "\n"

    summary += "---\n\n### ✅ Review Checklist\n\n"
    summary += "- [ ] Business justification is adequate\n"
    summary += "- [ ] Perimeter assignments are correct\n"
    summary += "- [ ] Service access is appropriate (not overly broad)\n"
    summary += "- [ ] Identities are properly scoped\n"
    summary += "- [ ] TLM ID provided for external access (if applicable)\n"
    summary += "- [ ] No security policy violations\n\n"

    summary += "---\n\n**⚠️ Security Notes:**\n"
    summary += "- This change modifies VPC Service Controls perimeter access\n"
    summary += "- Review for principle of least privilege\n"
    summary += "- Confirm requester has authorization for perimeter changes\n"

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate VPC SC summaries")
    parser.add_argument("--parsed-file", required=True, help="Parsed issue JSON")
    parser.add_argument("--actions-file", required=False, help="Actions JSON (if available)")
    parser.add_argument("--output-user", required=True, help="User summary output")
    parser.add_argument("--output-netsec", required=True, help="NetSec summary output")
    args = parser.parse_args()

    with open(args.parsed_file, "r", encoding="utf-8") as f:
        parsed = json.load(f)

    actions = []
    if args.actions_file:
        try:
            with open(args.actions_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                actions = data.get("actions", [])
        except Exception:
            pass

    rules = parsed.get("rules", [])

    user_summary = generate_user_summary(parsed, actions)
    netsec_summary = generate_netsec_summary(parsed, rules)

    with open(args.output_user, "w", encoding="utf-8") as f:
        f.write(user_summary)

    with open(args.output_netsec, "w", encoding="utf-8") as f:
        f.write(netsec_summary)

    print("Summaries generated successfully")


if __name__ == "__main__":
    main()
