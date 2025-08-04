---
name: "Firewall Rule Request"
about: "Request new GCP firewall rules"
labels: ["firewall-request"]
---

### Request ID (REQID): REQ123123
### CARID: 123123

#### Rule 1
🔹 New Source IP(s) or CIDR(s): 203.0.113.55/32  
🔹 New Destination IP(s) or CIDR(s): 10.1.2.22/32  
🔹 New Port(s): 443  
🔹 New Protocol: tcp  
🔹 New Business Justification: Need to restrict to a smaller range

<!--
Boundary (VPC) values are auto‑determined based on your IP ranges via boundary_map.json.
No need to specify source/destination VPC here.
-->

#### Rule 2
🔹 New Source IP(s) or CIDR(s): 10.2.3.4/32  
🔹 New Destination IP(s) or CIDR(s): 10.1.2.0/24  
🔹 New Port(s): 8443  
🔹 New Protocol: tcp  
🔹 New Business Justification: Another justification