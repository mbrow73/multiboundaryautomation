#  Automated Firewall Rule Request Workflow — Summary

---

##  Self-Service Requests
- Teams request firewall rules using a **structured GitHub Issue template**
- Streamlined and consistent intake process

---

##  Label-Driven Triggering
- Only issues labeled as `firewall-request` trigger automation
- Reduces noise and keeps workflows focused

---

##  Automated Parsing
- Extracts all required rule fields from the issue body:
  - Source/Destination IPs or CIDRs
  - Ports, Protocols, Direction
  - CARID, REQID, Team, Application metadata

---

##  Validation
- Checks for:
  - Required fields and correct syntax
  - Valid IPs/CIDRs and port ranges
  - Protocol and direction formatting
- **Duplicate detection** across inet/auto/manual rules
- **Feedback loop**:
  - Posts errors as GitHub comments
  - Auto-closes issue if validation fails

---

##  Audit-Ready Naming
- Enforces a consistent naming scheme:
  - Includes `CARID`, `REQID`, direction, port/protocol, etc.
- Enhances traceability across logs, code, and GCP policy

---

##  IaC-First Pipeline
- On validation success:
  - Rule is injected into a structured `tfvars.json`
  - Used as source-of-truth by Terraform

---

##  Safe Terraform Updates
- Terraform plan/validate runs are triggered
- Ensures format and logic checks before applying

---

##  Pull Request Automation
- Automatically generates a PR:
  - Includes rule details and justification summary
  - Requires **NetSec approval** before merge

---

##  Separation of Duties
- Auto-generated (self-service) and manual rules are **managed separately**
- Supports clear ownership and NetSec oversight

---

##  Result
A scalable, auditable, self-service firewall automation workflow  
— with strong security controls, policy consistency, and minimal NetSec overhead.
