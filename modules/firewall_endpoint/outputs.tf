output "created_endpoints" {
  description = "Map of endpoint names to their IDs."
  value       = { for name, ep in google_network_security_firewall_endpoint.endpoint : name => ep.id }
}

output "created_associations" {
  description = "Map of association names to their IDs."
  value       = { for name, assoc in google_network_security_firewall_endpoint_association.assoc : name => assoc.id }
}