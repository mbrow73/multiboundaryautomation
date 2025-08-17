import csv
import argparse


def load_address_objects(path):
    """Load address objects from CSV using headers: Name,Type,Address,Tag (case-insensitive)."""
    objs = {}
    with open(path, encoding='utf-8-sig') as f:
        lines = (line for line in f if line.strip())
        reader = csv.DictReader(lines)
        headers = {h.lower(): h for h in reader.fieldnames}
        for row in reader:
            name = row[headers['name']].strip()
            value = row[headers['address']].strip()
            tags_field = row.get(headers.get('tag'), '').strip()
            # Tags may be separated by semicolons or commas
            tags = [t.strip() for t in tags_field.replace(',', ';').split(';') if t.strip()]
            objs[name] = {'value': value, 'tags': tags}
    return objs


def load_address_groups(path):
    """Load address groups from CSV using headers: Name,Members Count,Addresses.

    Parses the Addresses column to extract dynamic filter after 'filter:' (case-insensitive). Assumes all groups are dynamic.
    """
    groups = {}
    with open(path, encoding='utf-8-sig') as f:
        lines = (line for line in f if line.strip())
        reader = csv.DictReader(lines)
        headers = {h.lower(): h for h in reader.fieldnames}
        for row in reader:
            name = row[headers['name']].strip()
            addresses_field = row.get(headers.get('addresses'), '').strip()
            # Example: "Dynamic Address Group: prod-src-group; filter: prod"
            criteria = ''
            # Look for 'filter:' in the string
            parts = addresses_field.split(';')
            for p in parts:
                if 'filter:' in p.lower():
                    criteria = p.split(':', 1)[1].strip()
                    break
            groups[name] = {
                'type': 'dynamic',
                'members': [],
                'criteria': criteria
            }
    return groups


def load_service_objects(path):
    """Load service objects using headers: Name,Protocol,Destination Port (case-insensitive)."""
    services = {}
    with open(path, encoding='utf-8-sig') as f:
        lines = (line for line in f if line.strip())
        reader = csv.DictReader(lines)
        headers = {h.lower(): h for h in reader.fieldnames}
        for row in reader:
            name = row[headers['name']].strip().lower()
            protocol = row[headers['protocol']].strip().lower()
            ports_field = row[headers['destination port']].strip()
            # Ports may be comma or semicolon separated
            entries = []
            for part in ports_field.replace(',', ';').split(';'):
                part = part.strip()
                if not part:
                    continue
                entries.append((part, protocol))
            services[name] = entries
    return services


def parse_rules(path):
    """Parse rules using headers: Name,Source Address,Destination Address,Service."""
    rules = []
    with open(path, encoding='utf-8-sig') as f:
        lines = (line for line in f if line.strip())
        reader = csv.DictReader(lines)
        headers = {h.lower(): h for h in reader.fieldnames}
        for row in reader:
            name = row[headers['name']].strip()
            src_field = row[headers['source address']].strip()
            dst_field = row[headers['destination address']].strip()
            svc_field = row[headers['service']].strip()
            # Split by comma or semicolon
            src_names = [s.strip() for s in src_field.replace(',', ';').split(';') if s.strip()]
            dst_names = [d.strip() for d in dst_field.replace(',', ';').split(';') if d.strip()]
            svc_names = [s.strip() for s in svc_field.replace(',', ';').split(';') if s.strip()]
            rules.append({
                'name': name,
                'source': src_names,
                'destination': dst_names,
                'service': svc_names
            })
    return rules


def expand_entity(name, objs, groups, visited=None):
    """Expand an address or group name into IPs. Supports dynamic groups using tags."""
    if visited is None:
        visited = set()
    if name in visited:
        return []
    visited.add(name)
    # Address object
    if name in objs:
        return [objs[name]['value']]
    # Address group
    if name in groups:
        info = groups[name]
        # dynamic group: criteria is tag; match address objects whose tags include the criteria
        tag = info['criteria'].lower()
        ips = []
        for obj in objs.values():
            if tag in [t.lower() for t in obj['tags']]:
                ips.append(obj['value'])
        return ips
    # 'any' represents the wildcard and should result in an empty list so that
    # the caller can emit 'any' in the final output.  If the entity name is
    # not found in either the objects or groups, return the literal name so
    # it can be surfaced in the output rather than silently treated as 'any'.
    if name.lower() == 'any':
        return []
    # unknown entity: return name as-is for visibility
    return [name]


def generate_issue(rules_csv, objs_csv, groups_csv, services_csv, reqid=None, carid=None, tlmid=None):
    objs = load_address_objects(objs_csv)
    groups = load_address_groups(groups_csv)
    services = load_service_objects(services_csv)
    rules = parse_rules(rules_csv)
    # Print header
    print("---")
    print("name: \"Firewall Rule Request\"")
    print("about: \"Request new or updated GCP firewall rules\"")
    print("labels: [\"firewall-request\"]")
    print("---\n")
    print(f"### Request ID (REQID): {reqid or '<REQID>'}")
    print(f"### CARID: {carid or '<CARID>'}")
    print(f"### Third Party ID (TLM ID) (required for third‑party VPC access): {tlmid or ''}\n")
    rule_index = 1
    for r in rules:
        # Expand sources and destinations
        src_ips = []
        for s in r['source']:
            src_ips.extend(expand_entity(s, objs, groups))
        dst_ips = []
        for d in r['destination']:
            dst_ips.extend(expand_entity(d, objs, groups))
        src_ips = sorted(set(src_ips)) if src_ips else []
        dst_ips = sorted(set(dst_ips)) if dst_ips else []
        # Determine ports and protocols and group them by protocol
        port_proto_list = []
        for svc in r['service']:
            svc_lower = svc.lower()
            if svc_lower in services:
                port_proto_list.extend(services[svc_lower])
            elif svc_lower in ('application-default', 'any'):
                port_proto_list.append(('any', 'tcp'))
            else:
                port_proto_list.append((svc, 'tcp'))
        # Group ports by protocol
        proto_to_ports = {}
        for port, proto in port_proto_list:
            if proto not in proto_to_ports:
                proto_to_ports[proto] = []
            proto_to_ports[proto].append(port)
        # Compose justification based on src/dst names (not IPs) for netsec migration
        src_desc = ','.join(r['source'])
        dst_desc = ','.join(r['destination'])
        justification = f"{src_desc} to {dst_desc} for netsec migration"
        # For each protocol, produce a rule; if multiple protocols, increment rule index for each
        for proto, ports in proto_to_ports.items():
            # Deduplicate and preserve order
            seen_ports = []
            for p in ports:
                if p not in seen_ports:
                    seen_ports.append(p)
            ports_str = ','.join(seen_ports)
            print(f"#### Rule {rule_index}")
            print(f"🔹 New Source IP(s) or CIDR(s): {', '.join(src_ips) if src_ips else 'any'}  ")
            print(f"🔹 New Destination IP(s) or CIDR(s): {', '.join(dst_ips) if dst_ips else 'any'}  ")
            print(f"🔹 New Port(s): {ports_str}  ")
            print(f"🔹 New Protocol: {proto}  ")
            print(f"🔹 New Business Justification: {justification}\n")
            rule_index += 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert Palo Alto CSV exports to GCP firewall issue template.')
    # By default, use the sample files with additional unused fields.  These names
    # correspond to the "garbage" sample CSVs provided with the repository.  If
    # you have your own exports, override them via the command line.
    parser.add_argument('--rules', default='pa_rules.csv',
                        help='Rules CSV file (Name,Source Address,Destination Address,Service)')
    parser.add_argument('--objects', default='pa_address_objects.csv',
                        help='Address objects CSV file (Name,Type,Address,Tag)')
    parser.add_argument('--groups', default='pa_address_groups.csv',
                        help='Address groups CSV file (Name, Members Count, Addresses)')
    parser.add_argument('--services', default='pa_service_objects.csv',
                        help='Service objects CSV file (Name,Protocol,Destination Port)')
    parser.add_argument('--reqid', help='Request ID (REQID)')
    parser.add_argument('--carid', help='CARID')
    parser.add_argument('--tlmid', help='Third party ID (TLM ID)')
    args = parser.parse_args()
    generate_issue(args.rules, args.objects, args.groups, args.services, args.reqid, args.carid, args.tlmid)
