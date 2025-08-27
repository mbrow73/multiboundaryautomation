---
name: VPC Service Controls Request
about: Request to add one or more ingress/egress rules to a VPC Service Controls perimeter
labels: vpc-sc-request
---

Thank you for submitting a VPC Service Controls request. Use the sections below to define one or more rules. For multiple rules, copy the **Rule** section as many times as needed. If different services need different methods/permissions, create separate rules.

### Request ID
Provide a unique request identifier (e.g., `REQ123456`).

### Perimeter Name
Name(s) of the VPC Service Controls perimeter(s) to update.  If you need to target more than one perimeter, separate them with commas or list each on its own line. Example:
test-perim-a, test-perim-b

### Rules
Below is a template for one rule. Copy this entire block for each additional rule.

**Direction (INGRESS or EGRESS)**  
Specify whether this rule is for **INGRESS** (allowing traffic into the perimeter) or **EGRESS** (allowing traffic out of the perimeter).

**Services**  
List the Google APIs/services this rule applies to (one per line or separated by commas). Example:  
`storage.googleapis.com, bigquery.googleapis.com`

**Methods (optional)**  
List specific RPC methods or service methods that apply to all services in this rule (comma‑separated or one per line). Example:  
`storage.buckets.get, storage.objects.get`

**Permissions (optional)**  
List specific IAM permissions that apply to all services in this rule (comma‑separated or one per line). Example:  
`bigquery.jobs.get, bigquery.tables.get`

**Source / From (for ingress rules)**  
For ingress rules, specify the sources that should be allowed. This can include IP ranges (e.g., `192.0.2.0/24`), VPC networks, or resources. Separate multiple sources with commas or list each on its own line. Leave blank for egress rules.

**Destination / To (for egress rules)**  
For egress rules, specify the destinations that should be allowed (e.g., projects or services). Separate multiple destinations with commas or list each on its own line. Leave blank for ingress rules.

**Identities**  
List the identities (e.g., `user:email@example.com`, `serviceAccount:sa@example.iam.gserviceaccount.com`) that are allowed to use this rule. If left blank, the rule applies to all identities.

### Third‑Party Name (if applicable)
If this request involves a third party (e.g., contractor or partner), provide the organization’s name. Otherwise, leave blank.

### Justification
Explain why the requested access is needed and how it complies with policy.