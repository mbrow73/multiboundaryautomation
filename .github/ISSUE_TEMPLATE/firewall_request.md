---
name: Firewall Rule Request
about: Request a new firewall rule
title: "CARXXXX-REQXXXX: Add firewall rule"
labels: [firewall-request]
---

**CAR ID**

Provide the CAR (Change Approval Record) identifier associated with this request.

**REQ ID**

Provide a unique request identifier for this firewall rule.  This will be used
as the filename for the generated Terraform variables file.

**New Source IP**

Enter the source IP address or CIDR (e.g. `203.0.113.10/32`).

**New Destination IP**

Enter the destination IP address or CIDR (e.g. `10.0.0.0/24`).

**Ports**

Specify one or more ports or port ranges (e.g. `443` or `80,443`).

**Protocol**

Specify the protocol (e.g. `tcp`, `udp`, `icmp`).

**Direction**

Is this an `INGRESS` or `EGRESS` rule?

**Justification**

Provide a brief justification for why this firewall rule is needed.