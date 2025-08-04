# .github/scripts/firewall_request_validator.py
#!/usr/bin/env python3
"""
Validate only CARID/REQID, IPs, ports, protocol, justification, duplicates.
Direction is no longer required in the issue template.
"""
import re
import sys
import ipaddress
import glob
import json
from collections import defaultdict

def validate_reqid(x): return bool(re.fullmatch(r"REQ\d{7,8}", x))
def validate_carid(x): return bool(re.fullmatch(r"\d{9}", x))
def validate_ip(ip):
    if "/" not in ip: return False
    try: ipaddress.ip_network(ip, strict=False); return True
    except: return False
def validate_port(p):
    if re.fullmatch(r"\d{1,5}", p):
        return 1 <= int(p) <= 65535
    if re.fullmatch(r"\d{1,5}-\d{1,5}", p):
        a,b=map(int,p.split("-")); return 1<=a<=b<=65535
    return False

def parse_rule_block(b):
    def ex(lbl):
        m=re.search(rf"{lbl}.*?:\s*(.+)",b,re.IGNORECASE)
        return m.group(1).strip() if m else ""
    return {
        "src": ex("New Source IP") or ex("New Source"),
        "dst": ex("New Destination IP") or ex("New Destination"),
        "ports": ex("New Port"),
        "proto": ex("New Protocol"),
        "just": ex("New Business Justification")
    }

def parse_existing():
    out=[]
    for path in glob.glob("firewall-requests/*.auto.tfvars.json"):
        d=json.load(open(path))
        for r in d.get("auto_firewall_rules",[]):
            out.append({
                "src": ",".join(r.get("src_ip_ranges",[])),
                "dst": ",".join(r.get("dest_ip_ranges",[])),
                "ports": ",".join(r.get("ports",[])),
                "proto": r.get("protocol",""),
                "src_vpc": r.get("src_vpc",""),
                "dst_vpc": r.get("dest_vpc",""),
            })
    return out

def print_errors(errs):
    print("VALIDATION_ERRORS_START")
    for e in errs: print(e)
    print("VALIDATION_ERRORS_END")
    sys.exit(1)

def main():
    text = open(sys.argv[1]).read()
    errs = []
    # REQID
    m=re.search(r"Request ID.*?:\s*([A-Z0-9]+)",text,re.IGNORECASE)
    reqid=m.group(1).strip() if m else ""
    if not validate_reqid(reqid):
        errs.append(f"❌ REQID must be 'REQ' +7–8 digits. Found '{reqid}'")
    # CARID
    m=re.search(r"CARID.*?:\s*(\d+)",text,re.IGNORECASE)
    carid=m.group(1).strip() if m else ""
    if not validate_carid(carid):
        errs.append(f"❌ CARID must be 9 digits. Found '{carid}'")
    # Rule blocks
    blks = re.split(r"#### Rule", text, flags=re.IGNORECASE)[1:]
    seen=set()
    for i,b in enumerate(blks,1):
        r=parse_rule_block(b)
        # all fields present?
        if not all([r["src"],r["dst"],r["ports"],r["proto"],r["just"]]):
            errs.append(f"❌ Rule {i}: missing one of src/dst/port/proto/just")
            continue
        # protocol
        if r["proto"] not in {"tcp","udp","icmp","sctp"}:
            errs.append(f"❌ Rule {i}: protocol must be tcp|udp|icmp|sctp")
        # IPs
        for lbl,val in [("source",r["src"]),("destination",r["dst"])]:
            for ip in val.split(","):
                if not validate_ip(ip.strip()):
                    errs.append(f"❌ Rule {i}: invalid {lbl} IP '{ip.strip()}'")
        # ports
        for p in r["ports"].split(","):
            if not validate_port(p.strip()):
                errs.append(f"❌ Rule {i}: invalid port '{p.strip()}'")
        key=(r["src"],r["dst"],r["ports"],r["proto"])
        if key in seen:
            errs.append(f"❌ Rule {i}: duplicate in request")
        seen.add(key)
    # redundancy
    existing=parse_existing()
    for i,b in enumerate(blks,1):
        r=parse_rule_block(b)
        if r["src"] and r["dst"]:
            # reuse exact/redundant logic if desired...
            pass
    if errs: print_errors(errs)

if __name__=="__main__":
    main()
