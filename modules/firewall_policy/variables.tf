variable "project_id" {
  description = "GCP project ID for the firewall policies"
  type        = string
}

variable "policy_name" {
  description = "Base name for the firewall policies; each boundary name will be appended"
  type        = string
}

variable "security_profile_group_id" {
  description = "ID of the security profile group to apply for inspected rules"
  type        = string
}

variable "vpc_boundaries" {
  description = "Map of boundary name to VPC network self‑link.  Keys must match src_vpc/dest_vpc fields in rules."
  type        = map(string)
}

variable "inet_firewall_rules" {
  description = "List of firewall rules including VPC boundaries.  Each rule must specify the source and destination VPC names which correspond to the keys in vpc_boundaries."
  type = list(object({
    name            = string
    description     = string
    priority        = number
    direction       = string
    src_vpc         = string
    dest_vpc        = string
    src_ip_ranges   = list(string)
    dest_ip_ranges  = list(string)
    ports           = list(string)
    protocol        = string
    enable_logging  = bool
    tls_inspect     = optional(bool)
  }))
}