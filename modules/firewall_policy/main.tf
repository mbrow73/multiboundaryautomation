/*
 * Simple firewall policy module.  This module mirrors the original
 * inetconfig firewall policy implementation.  It creates a single
 * global network firewall policy and attaches it to the supplied VPC
 * network.  A firewall policy rule is created for each entry in the
 * `rules` variable.  Note that this module does not support
 * boundary‑aware logic; it is retained for completeness.
 */

resource "google_compute_network_firewall_policy" "policy" {
  name    = var.policy_name
  project = var.project_id
  description = "Global NGFW policy for ${var.policy_name}"
}

resource "google_compute_network_firewall_policy_association" "association" {
  name            = var.policy_name
  firewall_policy = google_compute_network_firewall_policy.policy.id
  attachment_target = var.vpc_id
}

resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each        = { for r in var.rules : r.name => r }
  firewall_policy = google_compute_network_firewall_policy.policy.id
  description     = each.value.description
  priority        = each.value.priority
  direction       = each.value.direction
  action          = each.value.action
  enable_logging  = each.value.enable_logging
  match {
    src_ip_ranges  = each.value.src_ip_ranges
    dest_ip_ranges = each.value.dest_ip_ranges
    layer4_configs {
      ip_protocol = each.value.protocol
      ports       = each.value.ports
    }
  }
}