variable "project_id" {
  description = "GCP project ID for the TLS inspection policy and firewall policies"
  type        = string
  default     = "meta-episode-463418-i2"
}

variable "vpc_network_id" {
  description = "The default VPC network (self‑link or ID) used when no explicit boundaries are supplied"
  type        = string
  default     = ""
}

variable "zone" {
  description = "Zone for the firewall endpoint (must match zone of workloads)"
  type        = string
  default     = ""
}

variable "billing_project_id" {
  description = "Billing project ID for the NGFW endpoint"
  type        = string
  default     = ""
}

variable "region" {
  description = "Region for the TLS inspection policy (must be same as CA region)"
  type        = string
  default     = "us-central1"
}

variable "ca_organization" {
  description = "Organization name for the CA"
  type        = string
  default     = ""
}

variable "ca_country_code" {
  description = "Country code for the CA"
  type        = string
  default     = "US"
}

variable "manual_firewall_rules" {
  description = <<-EOT
    A list of manually maintained firewall policy rules.  Each object must include:
      - name                   = unique name for the rule
      - description            = human description
      - priority               = rule priority (lower = higher match)
      - direction              = "INGRESS" or "EGRESS"
      - action                 = one of ["allow","deny","apply_security_profile_group"]
      - security_profile_group = (if action == "apply_security_profile_group")
      - enable_logging         = bool
      - src_ip_ranges          = list(string)
      - dest_ip_ranges         = list(string)
      - ports                  = list(string)  # layer4 ports
      - protocol               = string
      - tls_inspection         = bool         # whether to decrypt TLS
      - src_vpc                = string       # source boundary name
      - dest_vpc               = string       # destination boundary name
    The src_vpc/dest_vpc fields correspond to keys in var.vpc_boundaries.
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
    src_vpc                = string
    dest_vpc               = string
  }))
}

variable "credentials" {
  description = "Path to the service account credentials JSON file"
  type        = string
  default     = ""
}

variable "vpc_boundaries" {
  description = "Map of boundary name to VPC network self‑link.  Example: { inet = \"projects/.../global/networks/default\", intranet = \"projects/...\" }"
  type        = map(string)
  default = {
    inet = ""
  }
}

variable "security_profile_group_id" {
  description = "ID of the security profile group to apply when inspection is required for cross‑boundary traffic"
  type        = string
  default     = ""
}