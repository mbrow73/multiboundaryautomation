#!/usr/bin/env python3
"""
Firewall rule updater.

This script processes "Update Firewall Rule" GitHub issues and applies
requested changes to the JSON files under ``firewall-requests/``.  It ensures
updated rules are written to a new per‑request JSON file (named after the
supplied REQID) while leaving the original source files untouched.  The
updated rules are validated in the same manner as the new rule workflow:
REQID and CARID formats are checked, IP/CIDR syntax is validated, port
ranges and protocols are enforced, health‑check and restricted API ranges
are verified to be on the correct side of the rule, and duplicate rules
within the update request are detected.  When a rule crosses the
third‑party peering boundary, a Third‑Party ID (TLM ID) must be provided
unless both the source and destination are third‑party networks.  Updated
rules receive fresh priority values beginning at 1000 (or one greater than
the current maximum priority ≥1000) so as not to collide with manual
NetSec rules.

For rules that involve a third‑party VPC, a Third‑Party ID (TLM ID) must be
supplied in the issue.  To determine which IP ranges correspond to
third‑party networks, this script loads ``boundary_map.json`` from the repo
root.  All entries whose keys contain ``"third"`` are treated as third‑party
boundaries.  If the boundary map cannot be read or contains no such
entries, the updater falls back to the default CIDR of ``10.150.1.0/24``.
"""

import re
import sys
import os
import glob
import json
import ipaddress
import subprocess
from typing import Dict, List, Tuple, Any

# Allowed public ranges for Google services.
ALLOWED_PUBLIC_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
    ipaddress.ip_network("199.36.153.4/30"),
]

# Subset of public ranges reserved for GCP health checks.
HEALTH_CHECK_RANGES = [
    ipaddress.ip_network("35.191.0.0/16"),
    ipaddress.ip_network("130.211.0.0/22"),
]

# Restricted API ranges that may only appear on the destination side of a rule.
RESTRICTED_API_RANGES = [
    ipaddress.ip_network("199.36.153.4/30"),
]

# Private address space used for on‑premises and intranet networks.
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Dynamically load third‑party peering ranges from boundary_map.json.  The map
# lives at the repository root.  We locate it relative to this file (two
# directories up) so the script can be executed from anywhere within the
# project.  If reading the map fails or yields no ranges, we fall back to a
# sensible default.
try:
    boundary_map_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "boundary_map.json")
    )
    with open(boundary_map_path, "r", encoding="utf-8") as f:
        _boundary_map = json.load(f)
    THIRD_PARTY_PEERING_RANGES = [
        ipaddress.ip_network(cidr)
        for name, cidrs in _boundary_map.items()
        if "third" in name.lower()
        for cidr in cidrs
    ]
    if not THIRD_PARTY_PEERING_RANGES:
        THIRD_PARTY_PEERING_RANGES = [ipaddress.ip_network("10.150.1.0/24")]
except Exception:
    THIRD_PARTY_PEERING_RANGES = [ipaddress.ip_network("10.150.1.0/24")]

# Placeholder for the TLM ID extracted from the issue (for update requests).
NEW_TLM_ID = ""


def validate_reqid(reqid: str) -> bool:
    """Validate that the REQID follows the pattern REQ followed by 7–8 digits."""
    return bool(re.fullmatch(r"REQ\d{7,8}", reqid or ""))


def validate_carid(carid: str) -> bool:
    """Validate that the CARID is exactly 9 digits."""
    return bool(re.fullmatch(r"\d{9}", carid or ""))


def validate_ip(ip: str) -> bool:
    """Return True if the string represents a valid IP address or network."""
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def validate_port(port: str) -> bool:
    """Validate that a port or port range is within 1–65535."""
    if re.fullmatch(r"\d{1,5}", port or ""):
        n = int(port)
        return 1 <= n <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", port or ""):
        a, b = map(int, port.split("-"))
        return 1 <= a <= b <= 65535
    return False


def validate_protocol(proto: str) -> bool:
    """Validate that the protocol is one of tcp, udp, icmp, or sctp (case insensitive)."""
    return proto.lower() in {"tcp", "udp", "icmp", "sctp"}


def load_all_rules() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Load all existing firewall rules from the ``firewall-requests`` directory.

    Returns a tuple of (rule_map, file_map) where rule_map maps rule names to
    rule dictionaries and file_map maps rule names to their originating file.
    """
    rule_map: Dict[str, Dict[str, Any]] = {}
    file_map: Dict[str, str] = {}
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            # Skip unreadable files gracefully
            continue
        for rule in data.get("auto_firewall_rules", []):
            name = rule.get("name")
            if name:
                rule_map[name] = rule
                file_map[name] = path
    return rule_map, file_map


def update_rule_fields(rule: Dict[str, Any], updates: Dict[str, Any], new_reqid: str, new_carid: str) -> Dict[str, Any]:
    """Return a copy of ``rule`` with ``updates`` applied and a new name constructed.

    The rule name includes the new REQID, CARID, protocol, ports, and an index to
    avoid collisions. Description text is preserved or replaced according to
    the update request.
    """
    updated = rule.copy()
    # Use the stored update index (or default to 1) to create a unique suffix.
    idx = updated.get("_update_index", 1)
    proto = updates.get("protocol") or updated.get("protocol", "tcp")
    ports = updates.get("ports") or updated.get("ports", [])
    # Derive the CARID: prefer the newly provided one, otherwise retain the old one from the name.
    try:
        old_carid = updated.get("name", "AUTO-REQ-0-0").split("-")[2]
    except Exception:
        old_carid = ""
    carid = new_carid or old_carid
    new_name = f"AUTO-{new_reqid}-{carid}-{proto.upper()}-{','.join(ports)}-{idx}"
    updated["name"] = new_name
    # Apply provided field updates.  Lowercase protocol and direction values to maintain consistency.
    for key, value in updates.items():
        if value:
            updated[key] = value.lower() if key in {"protocol", "direction"} else value
    # Update the description: keep only the justification portion of the previous description.
    desc_just = updates.get("description") or updated.get("description", "").split("|", 1)[-1]
    updated["description"] = f"{new_name} | {desc_just.strip()}"
    return updated


def compute_next_priorities(updated_count: int) -> List[int]:
    """Determine a sequence of new priorities for updated rules.

    Priorities for auto‑managed rules must live in a high range (≥1000) to
    avoid colliding with hand‑crafted NetSec rules. This helper scans all
    existing auto rules across the repository, finds the maximum priority
    already assigned at or above 1000, and returns a list of ``updated_count``
    sequential values starting just above that maximum. If no existing
    priorities are found, the sequence starts at 1000.

    Args:
        updated_count: The number of updated rules that will need new priorities.

    Returns:
        A list of length ``updated_count`` containing monotonically increasing
        integer priorities.
    """
    existing_priorities: List[int] = []
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue
        for rule in data.get("auto_firewall_rules", []):
            prio = rule.get("priority")
            if isinstance(prio, int) and prio >= 1000:
                existing_priorities.append(prio)
    max_prio = max(existing_priorities) if existing_priorities else 999
    start = max(max_prio, 999) + 1
    return [start + i for i in range(updated_count)]


def validate_rule(rule: Dict[str, Any], idx: int) -> List[str]:
    """Validate a single firewall rule and return a list of error messages."""
    errors: List[str] = []
    third_party_src = False
    third_party_dst = False
    # Validate IP ranges and determine third‑party involvement
    for field in ["src_ip_ranges", "dest_ip_ranges"]:
        label = "Source" if field == "src_ip_ranges" else "Destination"
        for ip in rule.get(field, []):
            if "/" not in ip:
                errors.append(f"Rule {idx}: {label} '{ip}' must include a CIDR mask (e.g. /32).")
                continue
            if not validate_ip(ip):
                errors.append(f"Rule {idx}: Invalid {label.lower()} IP/CIDR '{ip}'.")
                continue
            net = ipaddress.ip_network(ip, strict=False)
            if net == ipaddress.ip_network("0.0.0.0/0"):
                errors.append(f"Rule {idx}: {label} may not be 0.0.0.0/0.")
                continue
            # Oversized prefix: /0–/23 must either be allowed public ranges or health check ranges
            if net.prefixlen < 24:
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: {label} '{ip}' is /{net.prefixlen}, must be /24 or smaller unless it’s a GCP health‑check range.")
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    # Mark rule as involving third‑party
                    rule["_uses_third_party"] = True
                    if field == "src_ip_ranges":
                        third_party_src = True
                    else:
                        third_party_dst = True
                continue
            # For prefixlen ≥24, ensure public ranges are within allowed GCP ranges; otherwise treat as private
            if not any(net.subnet_of(r) for r in PRIVATE_RANGES):
                if not any(net.subnet_of(r) for r in ALLOWED_PUBLIC_RANGES):
                    errors.append(f"Rule {idx}: Public {label} '{ip}' not in allowed GCP ranges.")
                if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                    rule["_uses_third_party"] = True
                    if field == "src_ip_ranges":
                        third_party_src = True
                    else:
                        third_party_dst = True
                continue
            # If private and in third‑party ranges
            if any(net.subnet_of(r) for r in THIRD_PARTY_PEERING_RANGES):
                rule["_uses_third_party"] = True
                if field == "src_ip_ranges":
                    third_party_src = True
                else:
                    third_party_dst = True

    # Validate ports
    for p in rule.get("ports", []):
        if not validate_port(p):
            errors.append(f"Rule {idx}: Invalid port or range: '{p}'.")
    # Validate protocol
    proto = (rule.get("protocol") or "").lower()
    if not validate_protocol(proto):
        errors.append(f"Rule {idx}: Protocol must be one of: tcp, udp, icmp, sctp (lowercase). Found: '{rule.get('protocol')}'.")
    # Validate direction
    direction = rule.get("direction", "")
    if direction and direction.upper() not in {"INGRESS", "EGRESS"}:
        errors.append(f"Rule {idx}: Direction must be INGRESS or EGRESS when provided. Found: '{direction}'.")
    # Validate CARID present in the rule name
    try:
        carid = rule.get("name", "AUTO-REQ-0000000-0-0").split("-")[2]
    except Exception:
        carid = ""
    if not validate_carid(carid):
        errors.append(f"Rule {idx}: CARID must be 9 digits. Found: '{carid}'.")
    # Restricted API and health‑check placement
    try:
        if any(ipaddress.ip_network(ip).subnet_of(r) for ip in rule.get("src_ip_ranges", []) for r in RESTRICTED_API_RANGES if "/" in ip):
            errors.append(f"Rule {idx}: Restricted Google APIs ranges (199.36.153.4/30) may only appear on the destination side.")
        if any(ipaddress.ip_network(ip).subnet_of(r) for ip in rule.get("dest_ip_ranges", []) for r in HEALTH_CHECK_RANGES if "/" in ip):
            errors.append(f"Rule {idx}: Health‑check ranges (35.191.0.0/16, 130.211.0.0/22) may only appear on the source side.")
    except Exception:
        pass
    # Require a TLM ID only when exactly one side of the rule is third‑party.
    try:
        if rule.get("_uses_third_party") and not NEW_TLM_ID and not (third_party_src and third_party_dst):
            errors.append(
                f"Rule {idx}: A Third Party ID (TLM ID) must be provided when using the third‑party‑peering boundary."
            )
    except Exception:
        pass
    return errors


def parse_blocks(issue_body: str) -> List[str]:
    """Split the update issue body into individual rule blocks."""
    blocks = re.split(r"(?:^|\n)#{0,6}\s*Rule\s*\d+\s*\n", issue_body, flags=re.IGNORECASE)
    return [b for b in blocks[1:] if b.strip()]


def extract_field(block: str, label: str) -> str:
    """Extract a field value from a rule block by its label.

    Iterate over each line in ``block`` and look for a line that starts with
    ``label`` (case‑insensitive) followed by a colon.  Return the text after
    the colon on that same line, stripped of leading/trailing whitespace.  This
    implementation avoids matching across newlines, so an empty value (e.g.
    ``New CARID:``) will yield an empty string rather than capturing the next
    heading.
    """
    for line in block.splitlines():
        m = re.match(rf"\s*{re.escape(label)}.*?:\s*(.*)", line, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def make_update_summary(idx: int, old_rule: Dict[str, Any], updates: Dict[str, Any], new_rule: Dict[str, Any]) -> str:
    """Create a human‑readable summary of the changes applied to a rule."""
    changes: List[str] = []
    for field, label in [
        ("src_ip_ranges", "Source"), ("dest_ip_ranges", "Destination"), ("ports", "Ports"),
        ("protocol", "Protocol"), ("direction", "Direction"), ("carid", "CARID"), ("description", "Justification")
    ]:
        old_val = old_rule.get(field)
        new_val = updates.get(field) if updates.get(field) else None
        if new_val is not None and old_val != new_val:
            old_str = ",".join(old_val) if isinstance(old_val, list) else old_val
            new_str = ",".join(new_val) if isinstance(new_val, list) else new_val
            changes.append(f"{label}: `{old_str}` → `{new_str}`")
    if old_rule.get("name") != new_rule.get("name"):
        changes.append(f"Rule Name: `{old_rule['name']}` → `{new_rule['name']}`")
    if not changes:
        changes = ["(No fields updated, only name/desc changed)"]
    return f"- **Rule {idx}** (`{old_rule['name']}`): " + "; ".join(changes)


def main() -> None:
    """Entry point for the rule updater."""
    global NEW_TLM_ID
    # Determine where to read the issue body from: argument or STDIN
    issue_body = sys.stdin.read() if len(sys.argv) < 2 else sys.argv[1]
    errors: List[str] = []
    summaries: List[str] = []

    # Extract the new REQID from the issue body.  We match the first occurrence of
    # "New Request ID:" and extract the alphanumeric token that follows.
    m_reqid = re.search(r"New Request ID.*?:\s*([A-Z0-9]+)", issue_body, re.IGNORECASE)
    new_reqid = m_reqid.group(1).strip() if m_reqid else None
    if not validate_reqid(new_reqid):
        errors.append(f"New REQID must be 'REQ' followed by 7 or 8 digits. Found: '{new_reqid}'.")
    # Extract the new Third‑Party ID on the same line as the label.  This prevents blank
    # lines later in the issue body from being captured as the TLM ID.
    m_tlm = re.search(r"New Third Party ID\b.*?:[ \t]*([^\n\r]*)", issue_body, re.IGNORECASE)
    NEW_TLM_ID = m_tlm.group(1).strip() if m_tlm else ""

    # Split the issue body into rule update blocks.  Accept headings with any number
    # of '#' characters so that "Rule 1" and "#### Rule 2" both match.
    blocks = parse_blocks(issue_body)
    update_reqs: List[Dict[str, Any]] = []
    for idx, block in enumerate(blocks, 1):
        # Extract the current rule name; this is required to locate the rule to update.
        m_name = re.search(r"Current Rule Name.*?:\s*([^\n]+)", block, re.IGNORECASE)
        rule_name = m_name.group(1).strip() if m_name else None
        if not rule_name:
            errors.append(f"Rule {idx}: 'Current Rule Name' is required.")
            continue
        # Collect new values from the update block.  Empty strings are stored
        # explicitly; we filter them out later when applying updates.
        update_reqs.append({
            "idx": idx,
            "rule_name": rule_name,
            "src_ip_ranges": [ip.strip() for ip in extract_field(block, "New Source IP").split(",") if ip.strip()],
            "dest_ip_ranges": [ip.strip() for ip in extract_field(block, "New Destination IP").split(",") if ip.strip()],
            "ports": [p.strip() for p in extract_field(block, "New Port").split(",") if p.strip()],
            "protocol": extract_field(block, "New Protocol"),
            "direction": extract_field(block, "New Direction"),
            "carid": extract_field(block, "New CARID"),
            "description": extract_field(block, "New Business Justification"),
        })

    # Detect duplicate rule definitions within the update request.  Duplicate
    # definitions (same src, dst, ports, protocol, direction) are likely an
    # accidental repetition and should be rejected.
    seen_keys = set()
    for req in update_reqs:
        key = (
            tuple(req.get("src_ip_ranges", [])),
            tuple(req.get("dest_ip_ranges", [])),
            tuple(req.get("ports", [])),
            (req.get("protocol") or "").lower(),
            (req.get("direction") or "").upper(),
        )
        if key in seen_keys:
            errors.append(f"Rule {req['idx']}: Duplicate rule in update request.")
        else:
            seen_keys.add(key)

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    # Load all existing rules to build a mapping of names to rule definitions.
    rule_map, file_map = load_all_rules()
    updated_rules: List[Dict[str, Any]] = []

    for req in update_reqs:
        idx = req["idx"]
        name = req["rule_name"]
        if name not in rule_map:
            errors.append(f"Rule {idx}: No rule found in codebase with name '{name}'.")
            continue
        original = rule_map[name]
        # Work on a copy so we don't mutate the cached rule_map entry.
        to_update = original.copy()
        # Assign a unique update index; use the order of the update block to prevent
        # collisions when constructing new names.  This differs from the original
        # updater which derived the index from the rule's position within its file.
        to_update["_update_index"] = idx
        # Build a dictionary of fields that are explicitly being updated.  Skip
        # empty lists or empty strings; these indicate the field should remain
        # unchanged.
        new_fields: Dict[str, Any] = {}
        if req["src_ip_ranges"]:
            new_fields["src_ip_ranges"] = req["src_ip_ranges"]
        if req["dest_ip_ranges"]:
            new_fields["dest_ip_ranges"] = req["dest_ip_ranges"]
        if req["ports"]:
            new_fields["ports"] = req["ports"]
        if req["protocol"]:
            new_fields["protocol"] = req["protocol"]
        if req["direction"]:
            new_fields["direction"] = req["direction"]
        if req["description"]:
            new_fields["description"] = req["description"]
        new_carid = req["carid"]
        # Determine whether this update actually changes anything.  If not, flag it as an error.
        actual_change = False
        if req["src_ip_ranges"] and req["src_ip_ranges"] != to_update.get("src_ip_ranges", []):
            actual_change = True
        if req["dest_ip_ranges"] and req["dest_ip_ranges"] != to_update.get("dest_ip_ranges", []):
            actual_change = True
        if req["ports"] and req["ports"] != to_update.get("ports", []):
            actual_change = True
        if req["protocol"] and req["protocol"].lower() != to_update.get("protocol", "").lower():
            actual_change = True
        if req["direction"] and req["direction"].upper() != to_update.get("direction", "").upper():
            actual_change = True
        if req["carid"]:
            old_carid = to_update.get("name", "AUTO-REQ-0-0").split("-")[2] if '-' in to_update.get("name", "") else ""
            if req["carid"] != old_carid:
                actual_change = True
        if req["description"]:
            old_desc_just = to_update.get("description", "").split("|", 1)[-1].strip()
            if req["description"].strip() != old_desc_just:
                actual_change = True
        if not actual_change and new_reqid == (to_update.get("name", "AUTO-REQ-0-0").split("-")[1] if '-' in to_update.get("name", "") else ""):
            errors.append(f"Rule {idx}: No fields were changed; update request must modify at least one field.")
            continue
        # Construct the updated rule and validate it.  Validation may attach
        # metadata such as _uses_third_party to the rule copy.
        updated_rule = update_rule_fields(to_update, new_fields, new_reqid, new_carid)
        errs = validate_rule(updated_rule, idx)
        if errs:
            errors.extend(errs)
        else:
            updated_rules.append(updated_rule)
            summaries.append(make_update_summary(idx, to_update, req, updated_rule))

    if errors:
        print("VALIDATION_ERRORS_START")
        for e in errors:
            print(e)
        print("VALIDATION_ERRORS_END")
        sys.exit(1)

    if not updated_rules:
        # Nothing to update; exit gracefully without writing any files.
        return

    # Assign new priorities to each updated rule.  Compute the next available
    # priority values across all existing auto firewall rules.  Append
    # sequentially for each updated rule.
    next_priorities = compute_next_priorities(len(updated_rules))
    for i, r in enumerate(updated_rules):
        # Remove internal markers before writing to disk
        r.pop("_update_index", None)
        r.pop("_uses_third_party", None)
        # Normalise lists: drop empty strings
        r["src_ip_ranges"] = [ip for ip in r.get("src_ip_ranges", []) if ip]
        r["dest_ip_ranges"] = [ip for ip in r.get("dest_ip_ranges", []) if ip]
        r["ports"] = [p for p in r.get("ports", []) if p]
        # Assign the computed priority
        r["priority"] = next_priorities[i]
        # Always enable logging for auto rules
        r.setdefault("enable_logging", True)

    # Prepare the destination file path.  Ensure the firewall‑requests directory exists.
    dest_dir = "firewall-requests"
    os.makedirs(dest_dir, exist_ok=True)
    new_path = os.path.join(dest_dir, f"{new_reqid}.auto.tfvars.json")
    # Load any existing rules from the destination file; append the updated rules.
    existing_rules: List[Dict[str, Any]] = []
    if os.path.exists(new_path):
        try:
            with open(new_path) as nf:
                existing_data = json.load(nf)
                existing_rules = existing_data.get("auto_firewall_rules", [])
        except Exception:
            # If the file exists but cannot be parsed, we start fresh.
            existing_rules = []
    combined_rules = existing_rules + updated_rules
    # Write the combined rules back to the destination file.  Use a temporary
    # file then rename to avoid partial writes in the case of interruption.
    tmp_new = new_path + ".tmp"
    with open(tmp_new, "w") as nf:
        json.dump({"auto_firewall_rules": combined_rules}, nf, indent=2)
        nf.write("\n")
    os.replace(tmp_new, new_path)

    # Write the update summary to a separate file so that the workflow can attach it to the PR.
    with open("rule_update_summary.txt", "w") as f:
        for line in summaries:
            f.write(line + "\n")

    # After writing updated rules, re‑derive src_vpc/dest_vpc fields for the new file using
    # boundary_mapper.py.  This step mirrors the behaviour used when adding new rules.
    try:
        map_file = "boundary_map.json"
        if os.path.exists(new_path):
            subprocess.run([
                sys.executable,
                os.path.join(os.path.dirname(__file__), "boundary_mapper.py"),
                "--map-file", map_file,
                "--json-file", new_path,
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        # Mapping errors are suppressed; boundary mapping will be retried in the GitHub workflow.
        pass


if __name__ == "__main__":
    main()