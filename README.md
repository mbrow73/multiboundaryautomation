# inetconfig-boundary-full

This repository automates the creation and management of Google Cloud
Network Firewall policies using Terraform and GitHub Actions.  It is
based on the original **inetconfig** project and extends it with
support for multiple logical boundaries (for example **inet**,
**intranet**, **third_party** and **on_prem**).  Each boundary maps to
a VPC network and has its own global firewall policy.  When a
firewall rule crosses boundaries the automation automatically applies
a security profile group to the rule so that deep packet inspection or
other security profiles are enforced.

## Key features

* **Automatic rule creation** – File an issue using the
  `Firewall Rule Request` template and the GitHub Actions workflow
  will validate the input, determine the source and destination
  boundaries, compute the next available priority and generate a
  `firewall-requests/REQID.auto.tfvars.json` file containing the rule.

* **Rule updates and removals** – Use the `Update Firewall Rule` or
  `Remove Firewall Rule` issue templates to modify or delete existing
  rules.  The update workflow recalculates boundaries when IPs
  change.

* **Priority normalization** – After merging rule changes to the
  `main` branch, the `post-merge-priority-normalize` workflow
  reassigns priorities to ensure consistent spacing.

* **Extensible modules** – In addition to the boundary policy module
  there are placeholders for certificate authority, TLS inspection,
  security profiles and firewall endpoint modules.  These can be
  populated as needed without breaking the existing structure.

## Directory structure

```
.
├── boundary_map.json              # Defines IP ranges for each logical boundary
├── firewall-requests/             # Auto‑generated tfvars files live here
├── modules/
│   ├── boundary_firewall_policy/  # Creates one firewall policy per boundary
│   ├── firewall_policy/           # Original single‑policy module (retained)
│   ├── ca/                        # Placeholder CA module
│   ├── tls_inspection/            # Placeholder TLS inspection module
│   ├── security_profiles/         # Placeholder security profile module
│   └── firewall_endpoint/         # Placeholder firewall endpoint module
├── .github/
│   ├── ISSUE_TEMPLATE/            # Issue templates for requests, updates, removals
│   ├── workflows/                 # GitHub Actions workflows
│   └── scripts/                   # Python helper scripts
├── main.tf                        # Top‑level Terraform configuration
├── variables.tf                   # Variables used by main.tf
└── README.md                      # This file
```

## Usage

1. **Configure boundary VPCs** – Define the `boundary_vpcs` variable in
   your Terraform configuration or via an `*.tfvars` file.  For
   example:

   ```hcl
   boundary_vpcs = {
     inet        = "projects/my-project/global/networks/inet-vpc"
     intranet    = "projects/my-project/global/networks/intranet-vpc"
     third_party = "projects/my-project/global/networks/third-party-vpc"
     on_prem     = "projects/my-project/global/networks/onprem-vpc"
   }
   security_profile_group_id = "projects/my-project/global/securityProfileGroups/default"
   ```

2. **Submit a request** – Open a new GitHub issue using the `Firewall
   Rule Request` template.  Provide the CAR ID, REQ ID, source and
   destination IPs, ports, protocol and direction.  The automation will
   create a pull request containing a new `tfvars` file.

3. **Approve and merge** – Review the generated pull request.  Once
   approved and merged into `main` the rule will be deployed by
   Terraform (outside the scope of this repository).

4. **Update or remove** – Use the `Update Firewall Rule` or
   `Remove Firewall Rule` templates to modify or delete a rule.  The
   corresponding workflows will adjust the `tfvars` files and create a
   pull request.

5. **Normalize priorities** – After merging changes the
   `post-merge-priority-normalize` workflow will normalize rule
   priorities across all `tfvars` files.

## Extending the modules

The `modules/ca`, `modules/tls_inspection`, `modules/security_profiles`
and `modules/firewall_endpoint` directories are provided as stubs so
that you can implement certificate authorities, TLS inspection,
security profiles or firewall endpoints within the same repository.
These modules are referenced (but commented out) in `main.tf`.  To
enable them, populate the module code and uncomment the corresponding
module blocks in `main.tf`.