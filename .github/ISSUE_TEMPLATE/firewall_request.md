---
name: "Firewall Rule Request"
about: "Request new or updated GCP firewall rules"
labels: ["firewall-request"]
---

### Request ID (REQID): REQ123123
### CARID: 123123

#### Rule 1
🔹 New Source IP(s) or CIDR(s): 203.0.113.55/32  
🔹 New Destination IP(s) or CIDR(s): 10.1.2.22/32  
<!--
Boundary (VPC) values are now computed automatically based on the IP ranges
using the boundary_map.json in the repository.  Do NOT specify source/destination
VPC boundaries here.  The automation will determine which VPC each IP belongs to.
-->
🔹 New Port(s): 443  
🔹 New Protocol: tcp  
🔹 New Direction: INGRESS  
🔹 New Business Justification: Need to restrict to a smaller range

#### Rule 2
🔹 New Source IP(s) or CIDR(s): 10.2.3.4/32  
🔹 New Destination IP(s) or CIDR(s): 10.1.2.0/24  
<!-- See above note regarding boundaries. -->
🔹 New Port(s): 8443  
🔹 New Protocol: tcp  
🔹 New Direction: EGRESS  
🔹 New Business Justification: Another justification
