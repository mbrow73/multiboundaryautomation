output "policies" {
  description = "Map of boundary name to firewall policy ID"
  value       = { for k, p in google_compute_network_firewall_policy.policies : k => p.id }
}