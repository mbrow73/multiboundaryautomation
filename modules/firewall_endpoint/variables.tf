variable "billing_project_id" {
  description = "Billing project ID used when creating firewall endpoints."
  type        = string
}

variable "org_id" {
  description = "Organization ID or parent path (e.g. 'organizations/123456789012')."
  type        = string
}

variable "firewall_endpoints" {
  description = <<EOT
Map of firewall endpoints to create.  The key becomes the endpoint name, and the
value must specify the zone.  For example:

{
  "ngfw-us-east1-b" = { zone = "us-east1-b" },
  "ngfw-us-central1-a" = { zone = "us-central1-a" }
}
EOT
  type = map(object({
    zone = string
  }))
}

variable "firewall_endpoint_associations" {
  description = <<EOT
Map of firewall endpoint associations to create.  The key becomes the association
name.  Each value must specify:

- endpoint_name: the name of an endpoint from the firewall_endpoints map.
- zone: the zone of the endpoint.
- network_id: the VPC network self-link to attach to the endpoint.
- tls_policy_id: (optional) TLS inspection policy to apply.

Example:

{
  "ngfw-us-east1-b-dmz" = {
    endpoint_name = "ngfw-us-east1-b"
    zone          = "us-east1-b"
    network_id    = "projects/my-proj/global/networks/dmz"
    tls_policy_id = null
  },
  "ngfw-us-central1-a-intranet" = {
    endpoint_name = "ngfw-us-central1-a"
    zone          = "us-central1-a"
    network_id    = "projects/my-proj/global/networks/intranet"
    tls_policy_id = "organizations/123456789012/locations/global/tlsInspectionPolicies/ngfw-policy"
  }
}
EOT
  type = map(object({
    endpoint_name = string
    zone          = string
    network_id    = string
    tls_policy_id = optional(string)
  }))
}
