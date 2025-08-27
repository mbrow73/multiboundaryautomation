---
name: VPC Service Controls Request
about: Request to add one or more ingress/egress rules to one or more VPC Service Controls perimeters
labels: vpc-sc-request
---

Thank you for submitting a VPC Service Controls request. Use the sections below to define one or more rules. For multiple rules, copy the **Rule** section as many times as needed. Each rule can target one or more perimeters.

### Request ID
Provide a unique request identifier (e.g., `REQ123456`).

### Rules
Below is a template for one rule. Copy this entire block for each additional rule you need.

**Perimeter Name(s)**  
Specify the perimeter or perimeters this rule applies to. Separate multiple perimeters with commas or list each on its own line. Example:  
`test-perim-a`

**Direction (INGRESS or EGRESS)**  
Specify whether this rule is for **INGRESS** (allowing traffic into the perimeter) or **EGRESS** (allowing traffic out of the perimeter).

**Services**  
List the Google APIs/services this rule applies to (one per line or separated by commas). Example:  
`storage.googleapis.com, bigquery.googleapis.com`

**Methods (optional)**  
List specific RPC or service methods that apply to all services in this rule (comma‑separated or one per line). Leave blank to allow all methods. Example:  
`storage.buckets.get, storage.objects.get`

**Permissions (optional)**  
List specific IAM permissions that apply to all services in this rule (comma‑separated or one per line). Leave blank to allow all permissions. Example:  
`bigquery.jobs.get, bigquery.tables.get`

**From**  
List the sources and/or identities for this rule.  
- For **ingress** rules, this is where the traffic originates (e.g., IP ranges like `132.1.2.3/32`, or ( `*` for all projects or `projects/my-project-number`))
projects/

**To**  
List the target resources for this rule.  
- For **ingress** rules, specify the internal projects or resources being accessed (e.g., `*` for all projects or `projects/my-project-number`).  
- For **egress** rules, specify the external projects being accessed. (e.g., `*` for all projects or `projects/my-project-number`).

**Identities**  
List the identities (e.g., `user:email@example.com`, `serviceAccount:sa@example.iam.gserviceaccount.com`) that are allowed to use this rule. If left blank, the rule applies to all identities.

### Third‑Party Name (if applicable)
If this request involves a third party (e.g., contractor or partner), provide the organization’s name. Otherwise, leave blank.

### Justification
Explain why the requested access is needed and how it complies with your policies.