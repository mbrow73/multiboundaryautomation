variable "org_id" {
  description = "GCP project ID for security profiles"
  type        = string
}

variable "location" {
  description = "Location for profiles (use \"global\" for security profiles)"
  type        = string
  default     = "global"
}

variable "ips_profile_name" {
  description = "Name of the Intrusion Prevention security profile"
  type        = string
}

variable "av_profile_name" {
  description = "Name of the Anti-Virus/Anti-Malware security profile"
  type        = string
}

variable "profile_group_name" {
  description = "Name of the security profile group"
  type        = string
}
