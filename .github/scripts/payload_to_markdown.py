#!/usr/bin/env python3
"""
payload_to_markdown.py

Reads a JSON request from the environment variable CLIENT_PAYLOAD and converts it
into the Markdown format expected by vpc_sc_request_handler.py. This allows
repository_dispatch events carrying a JSON payload to be processed without
modifying the existing parsing logic.

Usage (within a GitHub Actions step):
  env:
    CLIENT_PAYLOAD: ${{ toJSON(github.event.client_payload) }}
  run: python3 payload_to_markdown.py > issue_body.md

The script writes the formatted Markdown to standard output.
"""

import json
import os
import sys

def main() -> None:
    payload = os.environ.get("CLIENT_PAYLOAD", "{}")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        # If payload isn't valid JSON, just print nothing.
        return
    # If the payload contains a raw issue body, emit it directly.
    issue_body = data.get("issue_body")
    if isinstance(issue_body, str) and issue_body.strip():
        sys.stdout.write(issue_body)
        return

    lines: list[str] = []
    # Support simple rule definitions akin to the issue template. If 'rules' is
    # present and is a list of dicts, convert each rule into a Markdown block.
    rules = data.get("rules")
    if isinstance(rules, list) and rules:
        # Optional top-level request ID
        reqid = data.get("reqid") or ""
        if reqid:
            lines.append(f"Request ID: {reqid}")
        tlm = data.get("tlm_id") or ""
        justification = data.get("justification") or ""
        for rule in rules:
            # Perimeter(s)
            perims = rule.get("perimeter_name") or rule.get("perimeters") or ""
            perim_list: list[str] = []
            if isinstance(perims, str):
                perim_list = [p.strip() for p in perims.split(",") if p.strip()]
            elif isinstance(perims, list):
                perim_list = [str(p).strip() for p in perims if str(p).strip()]
            if perim_list:
                lines.append("")
                lines.append("Perimeter Name(s)")
                for p in perim_list:
                    lines.append(p)
            # Direction
            direction = (rule.get("direction") or "").upper()
            if direction:
                lines.append("")
                lines.append("Direction")
                lines.append(direction)
            # Services
            services_field = rule.get("services") or ""
            services_list: list[str] = []
            if isinstance(services_field, str):
                services_list = [s.strip() for s in services_field.split(",") if s.strip()]
            elif isinstance(services_field, list):
                services_list = [str(s).strip() for s in services_field if str(s).strip()]
            if services_list:
                lines.append("")
                lines.append("Services")
                lines.append(", ".join(services_list))
            # Methods (optional)
            methods_field = rule.get("methods") or ""
            method_lines: list[str] = []
            if isinstance(methods_field, str) and methods_field.strip():
                # Expect format: svc1: method1,method2; svc2: method
                parts = [p.strip() for p in methods_field.split(";") if p.strip()]
                for part in parts:
                    method_lines.append(part)
            elif isinstance(methods_field, dict):
                for svc, mlist in methods_field.items():
                    if isinstance(mlist, list) and mlist:
                        method_lines.append(f"{svc}: " + ", ".join(str(m) for m in mlist))
            if method_lines:
                lines.append("")
                lines.append("Methods")
                lines.extend(method_lines)
            # Permissions (optional)
            perms_field = rule.get("permissions") or ""
            perm_lines: list[str] = []
            if isinstance(perms_field, str) and perms_field.strip():
                parts = [p.strip() for p in perms_field.split(";") if p.strip()]
                for part in parts:
                    perm_lines.append(part)
            elif isinstance(perms_field, dict):
                for svc, plist in perms_field.items():
                    if isinstance(plist, list) and plist:
                        perm_lines.append(f"{svc}: " + ", ".join(str(p) for p in plist))
            if perm_lines:
                lines.append("")
                lines.append("Permissions")
                lines.extend(perm_lines)
            # From / To
            from_field = rule.get("from") or ""
            from_list: list[str] = []
            if isinstance(from_field, str):
                from_list = [f.strip() for f in from_field.split(",") if f.strip()]
            elif isinstance(from_field, list):
                from_list = [str(f).strip() for f in from_field if str(f).strip()]
            if from_list:
                lines.append("")
                lines.append("Source / From")
                for f in from_list:
                    lines.append(f)
            to_field = rule.get("to") or ""
            to_list: list[str] = []
            if isinstance(to_field, str):
                to_list = [t.strip() for t in to_field.split(",") if t.strip()]
            elif isinstance(to_field, list):
                to_list = [str(t).strip() for t in to_field if str(t).strip()]
            if to_list:
                lines.append("")
                lines.append("Destination / To")
                for t in to_list:
                    lines.append(t)
            # Identities
            id_field = rule.get("identities") or ""
            id_list: list[str] = []
            if isinstance(id_field, str):
                id_list = [i.strip() for i in id_field.split(",") if i.strip()]
            elif isinstance(id_field, list):
                id_list = [str(i).strip() for i in id_field if str(i).strip()]
            if id_list:
                lines.append("")
                lines.append("Identities")
                lines.append(", ".join(id_list))
        # Append optional TLM-ID and justification
        if tlm:
            lines.append("")
            lines.append("TLM-ID (if applicable)")
            lines.append(str(tlm))
        if justification:
            lines.append("")
            lines.append("Justification")
            # Support multi-line justification: emit each line separately
            for jl in str(justification).splitlines():
                lines.append(jl)
        sys.stdout.write("\n".join(lines))
        return

    # If no 'rules' list was provided, look for a simplified single-rule schema.
    # This allows requesters to specify the same fields as the issue template
    # without embedding arrays. Keys such as 'perimeters' (string), 'services',
    # 'methods', 'permissions', 'resources', 'to', 'from' and 'identities'
    # may be provided at the top level of the payload. These are converted
    # into the same Markdown sections that the handler expects.
    simple_fields = any(k in data for k in ["services", "methods", "permissions", "resources", "to", "from", "identities"])
    if simple_fields:
        # Request ID
        reqid = data.get("reqid") or ""
        if reqid:
            lines.append(f"Request ID: {reqid}")
        # Perimeter names: accept comma separated string or list
        perims = data.get("perimeters") or data.get("perimeter") or ""
        perim_list: list[str] = []
        if isinstance(perims, str):
            perim_list = [p.strip() for p in perims.split(",") if p.strip()]
        elif isinstance(perims, list):
            perim_list = [str(p).strip() for p in perims if str(p).strip()]
        if perim_list:
            lines.append("")
            lines.append("Perimeter Name(s)")
            for p in perim_list:
                lines.append(p)
        # Direction
        direction = (data.get("direction") or "").upper()
        if direction:
            lines.append("")
            lines.append("Direction")
            lines.append(direction)
        # Services
        services_field = data.get("services") or ""
        services_list: list[str] = []
        if isinstance(services_field, str):
            services_list = [s.strip() for s in services_field.split(",") if s.strip()]
        elif isinstance(services_field, list):
            services_list = [str(s).strip() for s in services_field if str(s).strip()]
        if services_list:
            lines.append("")
            lines.append("Services")
            lines.append(", ".join(services_list))
        # Methods (optional) - allow semicolon separated list of service: methods
        methods_field = data.get("methods") or ""
        method_lines: list[str] = []
        if isinstance(methods_field, str) and methods_field.strip():
            parts = [p.strip() for p in methods_field.split(";") if p.strip()]
            for part in parts:
                method_lines.append(part)
        elif isinstance(methods_field, dict):
            for svc, mlist in methods_field.items():
                if isinstance(mlist, list) and mlist:
                    method_lines.append(f"{svc}: " + ", ".join(str(m) for m in mlist))
        if method_lines:
            lines.append("")
            lines.append("Methods")
            lines.extend(method_lines)
        # Permissions (optional)
        perms_field = data.get("permissions") or ""
        perm_lines: list[str] = []
        if isinstance(perms_field, str) and perms_field.strip():
            parts = [p.strip() for p in perms_field.split(";") if p.strip()]
            for part in parts:
                perm_lines.append(part)
        elif isinstance(perms_field, dict):
            for svc, plist in perms_field.items():
                if isinstance(plist, list) and plist:
                    perm_lines.append(f"{svc}: " + ", ".join(str(p) for p in plist))
        if perm_lines:
            lines.append("")
            lines.append("Permissions")
            lines.extend(perm_lines)
        # Source / From and Destination / To
        # Accept 'from' or 'source' or 'from_resources' for ingress, 'to' or 'destination' or 'resources' for egress
        from_field = data.get("from") or data.get("source") or ""
        to_field = data.get("to") or data.get("destination") or data.get("resources") or ""
        from_list: list[str] = []
        to_list: list[str] = []
        if isinstance(from_field, str):
            from_list = [f.strip() for f in from_field.split(",") if f.strip()]
        elif isinstance(from_field, list):
            from_list = [str(f).strip() for f in from_field if str(f).strip()]
        if isinstance(to_field, str):
            to_list = [t.strip() for t in to_field.split(",") if t.strip()]
        elif isinstance(to_field, list):
            to_list = [str(t).strip() for t in to_field if str(t).strip()]
        if from_list and direction == "INGRESS":
            lines.append("")
            lines.append("Source / From")
            for f in from_list:
                lines.append(f)
        if to_list and direction == "EGRESS":
            lines.append("")
            lines.append("Destination / To")
            for t in to_list:
                lines.append(t)
        # Identities
        id_field = data.get("identities") or ""
        id_list: list[str] = []
        if isinstance(id_field, str):
            id_list = [i.strip() for i in id_field.split(",") if i.strip()]
        elif isinstance(id_field, list):
            id_list = [str(i).strip() for i in id_field if str(i).strip()]
        if id_list:
            lines.append("")
            lines.append("Identities")
            lines.append(", ".join(id_list))
        # TLM-ID and Justification optional
        tlm = data.get("tlm_id") or ""
        justification = data.get("justification") or ""
        if tlm:
            lines.append("")
            lines.append("TLM-ID (if applicable)")
            lines.append(str(tlm))
        if justification:
            lines.append("")
            lines.append("Justification")
            # Support multi-line justification: emit each line separately
            for jl in str(justification).splitlines():
                lines.append(jl)
        sys.stdout.write("\n".join(lines))
        return

    # Default behaviour: old schema with egress_policies/ingress_policies
    # Request ID
    reqid = data.get("reqid") or ""
    if reqid:
        lines.append(f"Request ID: {reqid}")
    # Perimeter names
    perimeters = data.get("perimeters") or []
    if perimeters:
        lines.append("")
        lines.append("Perimeter Name(s)")
        for p in perimeters:
            lines.append(str(p))
    # Direction
    direction = (data.get("direction") or "").upper()
    if direction:
        lines.append("")
        lines.append("Direction")
        lines.append(direction)
    # Determine which policies list to use based on direction
    policies = []
    if direction == "EGRESS":
        policies = data.get("egress_policies") or []
    elif direction == "INGRESS":
        policies = data.get("ingress_policies") or []
    # Process each policy
    for policy in policies:
        services: list[str] = []
        methods: list[str] = []
        perms: list[str] = []
        # Operations are under 'to' for egress, 'from' for ingress
        ops = {}
        if direction == "EGRESS":
            ops = policy.get("to", {}).get("operations", {})
        else:
            ops = policy.get("from", {}).get("operations", {})
        for svc, op in ops.items():
            services.append(svc)
            if op.get("methods"):
                methods.append(f"{svc}: " + ", ".join(op["methods"]))
            if op.get("permissions"):
                perms.append(f"{svc}: " + ", ".join(op["permissions"]))
        if services:
            lines.append("")
            lines.append("Services")
            lines.append(", ".join(services))
        if methods:
            lines.append("")
            lines.append("Methods")
            lines.extend(methods)
        if perms:
            lines.append("")
            lines.append("Permissions")
            lines.extend(perms)
        # Identities: from for egress, to for ingress
        identities: list[str] = []
        who = policy.get("from", {}) if direction == "EGRESS" else policy.get("to", {})
        ids = who.get("identities") or []
        if isinstance(ids, list):
            identities.extend(str(i) for i in ids)
        if identities:
            lines.append("")
            lines.append("Identities")
            lines.append(", ".join(identities))
        # Resources/destinations
        if direction == "EGRESS":
            resources = policy.get("to", {}).get("resources", [])
            label = "Destination / To"
        else:
            resources = policy.get("from", {}).get("resources", [])
            label = "Source / From"
        if resources:
            lines.append("")
            lines.append(label)
            for r in resources:
                lines.append(str(r))
    sys.stdout.write("\n".join(lines))

if __name__ == "__main__":
    main()