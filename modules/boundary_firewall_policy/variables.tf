variable "project_id" {
  description = "GCP project ID for the firewall policies"
  type        = string
}

variable "security_profile_group_id" {
  description = "Default security profile group ID used when a rule applies deep inspection and the rule does not specify a custom security profile group."
  type        = string
}

variable "boundary_policies" {
  description = <<-EOT
    A map of boundary identifiers to the policy configuration for that boundary.
    Each entry in the map must contain:
      - vpc_id:         self‑link of the VPC network to which the policy attaches
      - policy_name:    name of the firewall policy resource
      - firewall_rules: list of rule objects.  Each rule must include at least
        the standard fields name, description, priority, direction, protocol,
        ports, enable_logging, src_ip_ranges, dest_ip_ranges, src_boundary
        and dest_boundary.  If action is omitted or set to null it will be
        computed based on whether the rule is intra‑ or inter‑boundary.  If
        security_profile_group is omitted on an inter‑boundary rule then
        security_profile_group_id will be applied.
  EOT
  type = map(object({
    vpc_id        = string
    policy_name   = string
    firewall_rules = list(object({
      name                   = string
      description            = string
      priority               = number
      direction              = string
      protocol               = string
      ports                  = list(string)
      enable_logging         = bool
      src_ip_ranges          = list(string)
      dest_ip_ranges         = list(string)
      src_boundary           = string
      dest_boundary          = string
      action                 = optional(string)
      security_profile_group = optional(string)
      tls_inspection         = optional(bool)
    }))
  }))
}