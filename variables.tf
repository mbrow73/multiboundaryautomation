variable "project_id" {
  description = "GCP project ID for the TLS inspection policy and firewall policies"
  type        = string
  default     = "meta-episode-463418-i2"
}

variable "vpc_network_id" {
  description = "The default VPC network (self‑link or ID) used when no explicit boundaries are supplied"
  type        = string
  default     = "projects/dummy-project/global/networks/onprem"
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