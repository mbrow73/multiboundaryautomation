resource "google_compute_network_firewall_policy_rule" "manual_dmz_ingress" {
  firewall_policy = module.inet_firewall_policy.policies["dmz"]
  priority        = 1
  direction       = "INGRESS"
  action          = "apply_security_profile_group"
  security_profile_group = var.security_profile_group_id
  enable_logging  = true

  match {
    src_ip_ranges  = ["203.0.113.0/24"]
    dest_ip_ranges = ["10.10.0.0/16"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443"]
    }
  }
}