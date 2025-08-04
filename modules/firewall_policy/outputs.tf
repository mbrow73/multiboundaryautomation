output "policy_ids" {
  description = "Map of firewall policy IDs keyed by boundary name"
  value       = { for k, p in google_compute_network_firewall_policy.policies : k => p.id }
}