
#  Validation Script: What It Checks

---

##  Required Fields Present
Ensures the following fields are present and non-empty:
- `source_ip_s_or_cidr_s`
- `destination_ip_s_or_cidr_s`
- `port_s`
- `protocol`
- `direction`
- `business_justification`
- `request_id_reqid`

---

##  Protocol Must Be Lowercase
- Protocol value must be lowercase: `tcp`, `udp`, or `icmp`
- Rejects:
  - Mixed/uppercase values: `TCP`, `Tcp`
  - Invalid protocols outside the allowed set

---

##  Valid IP Addresses or CIDRs
- Validates all entries in `source_ip_s_or_cidr_s` and `destination_ip_s_or_cidr_s`
- Must be well-formed IPs or CIDRs (e.g., `10.0.0.0/8`, `1.2.3.4/32`)

---

##  Valid Port(s)
- Ports must be numeric and within range `1–65535`
- Accepts:
  - Individual ports (e.g., `443`)
  - Comma-separated lists (e.g., `443,8443`)
  - Ranges (e.g., `1000-2000`)

---

## ↕ Valid Direction
- Must be either `INGRESS` or `EGRESS`
- Case-insensitive, but normalized to uppercase internally

---

##  Valid Request ID
- Must match format: `REQ` followed by digits (e.g., `REQ12345`)

---

##  Duplicate Rule Detection
- Checks normalized input against:
  - `inet_firewall_rules`
  - `auto_firewall_rules`
  - `manual_firewall_rules`
- Detects duplicates based on:
  - Source(s), Destination(s), Port(s), Protocol, Direction
- Ignores name or justification differences

---

##  What Happens If a Check Fails?
- **Descriptive error message** is printed (and appears as a comment on the GitHub Issue)
- **GitHub Actions workflow stops** further processing for that request
- Issue is either left open or closed (based on current workflow logic)

---

##  Benefits
- Prevents misconfigurations and typos
- Stops rule drift (e.g., protocol capitalization)
- Blocks duplicate firewall rules
- Keeps your IaC and GCP firewall policies clean and consistent


