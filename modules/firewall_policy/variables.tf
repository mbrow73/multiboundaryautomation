/*
 * Input variables for the simple firewall policy module.  These
 * definitions follow the original inetconfig module.  See the
 * documentation for descriptions of each field.
 */

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "vpc_id" {
  description = "Identifier of the VPC network to attach the policy to"
  type        = string
}

variable "policy_name" {
  description = "Name of the network firewall policy"
  type        = string
}

variable "rules" {
  description = "List of firewall rule objects"
  type = list(object({
    name            = string
    description     = string
    priority        = number
    direction       = string
    action          = string
    src_ip_ranges   = list(string)
    dest_ip_ranges  = list(string)
    protocol        = string
    ports           = list(string)
    enable_logging  = bool
  }))
  default = []
}