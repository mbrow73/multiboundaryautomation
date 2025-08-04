---
name: "Update Firewall Rule(s)"
about: "Request updates to one or more existing GCP firewall rules"
labels: ["firewall-update-request"]
---

<!-- 
How to use:
- For each rule you want to update, copy/paste the "#### Rule N" block below.
- You MUST specify the exact current rule name (shown in PR summaries, in repository under firewall-requests directory, or in the gcp console).
- Fill only the fields you want to update. Delete all lines that you do not need to update.
- "New REQID" is required and will be used in the new rule name and filename for audit.
- "New CARID" is optional, for transfering ownership of a rule to a different app/team.
-->

### New Request ID (REQID): <!-- e.g. REQ2345678 -->

#### Rule 1
**Current Rule Name**: <!-- e.g. AUTO-REQ1234567-123456789-TCP-443-1 -->
**New Source IP(s) or CIDR(s)** (optional):  
**New Destination IP(s) or CIDR(s)** (optional):  
**New Port(s)** (optional):  
**New Protocol** (optional):  
**New Direction** (optional):  
**New CARID** (optional):  
**New Business Justification** (optional):  

#### Rule 2
**Current Rule Name**:
**New Source IP(s) or CIDR(s)** (optional):  
**New Destination IP(s) or CIDR(s)** (optional):  
**New Source VPC (boundary)** (optional):  
**New Destination VPC (boundary)** (optional):  
**New Port(s)** (optional):  
**New Protocol** (optional):  
**New Direction** (optional):  
**New CARID** (optional):  
**New Business Justification** (optional):  
