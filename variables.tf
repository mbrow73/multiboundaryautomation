variable "project_id" {
  description = "GCP project ID for the firewall deployment"
  type        = string
  default = "default"
}

variable "boundary_vpcs" {
  description = <<-EOT
    Mapping of logical boundary names to the self‑link of the VPC network to which the
    corresponding network firewall policy should be attached.  Keys must match the
    boundary identifiers referenced in the automation (e.g. inet, intranet,
    third_party, on_prem).  The on_prem entry should contain an empty string or
    placeholder as on‑prem traffic is routed via the intranet boundary.
  EOT
  type = map(string)
  default = {
    inet        = "projects/my‑project/global/networks/inet‑vpc"
    intranet    = "projects/my‑project/global/networks/intranet‑vpc"
    third_party = "projects/my‑project/global/networks/thirdparty‑vpc"
    on_prem     = ""  # Placeholder for on-prem boundary
  }
}

variable "security_profile_group_id" {
  description = "ID of the security profile group used for deep packet inspection on cross‑boundary egress flows"
  type        = string
  default     = "global/securityProfileGroups/my-security-profile-group"
}

variable "manual_firewall_rules" {
  description = <<-EOT
    A list of manual firewall policy rules.  Each object must include:
      - name                   = unique name for the rule
      - description            = human description
      - priority               = rule priority (lower numbers have higher precedence)
      - direction              = "INGRESS" or "EGRESS"
      - action                 = one of ["allow", "deny", "apply_security_profile_group"]
      - security_profile_group = (optional) ID of the security profile group if action is apply_security_profile_group
      - enable_logging         = bool
      - src_ip_ranges          = list(string)
      - dest_ip_ranges         = list(string)
      - ports                  = list(string)
      - protocol               = string (e.g. tcp, udp)
      - tls_inspection         = optional(bool)
      - src_boundary           = string (boundary name)
      - dest_boundary          = string (boundary name)
  EOT
  type = list(object({
    name                   = string
    description            = string
    priority               = number
    direction              = string
    action                 = string
    security_profile_group = optional(string)
    enable_logging         = bool
    src_ip_ranges          = list(string)
    dest_ip_ranges         = list(string)
    ports                  = list(string)
    protocol               = string
    tls_inspection         = optional(bool)
    src_boundary           = string
    dest_boundary          = string
  }))
}