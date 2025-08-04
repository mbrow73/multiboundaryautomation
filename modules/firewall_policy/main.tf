/*
 * Network Firewall Policy Module — Multi‑Boundary, Direction‑Free
 */

resource "google_compute_network_firewall_policy" "policies" {
  for_each    = var.vpc_boundaries
  name        = "${var.policy_name}-${each.key}"
  project     = var.project_id
  description = "NGFW firewall policy for ${each.key}"
}

resource "google_compute_network_firewall_policy_association" "attach" {
  for_each          = var.vpc_boundaries
  name              = each.key
  attachment_target = each.value
  firewall_policy   = google_compute_network_firewall_policy.policies[each.key].id
}

locals {
  expanded_rules = flatten([
    for r in var.inet_firewall_rules : [
      for entry in concat(
        # DEST entry (always ingress into the boundary)
        [
          {
            policy             = lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc)
            suffix             = "dest"
            direction_override = "INGRESS"
          }
        ],
        # SRC entry (always egress out of the boundary) if pols differ
        (
          (lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc))
          != (lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc))
        ) ? [
            {
              policy             = lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc)
              suffix             = "src"
              direction_override = "EGRESS"
            }
          ] : []
      ) : {
        key                = "${r.name}-${entry.policy}-${entry.suffix}"
        rule               = r
        target_policy      = entry.policy
        direction_override = entry.direction_override
      }
    ]
  ])

  expanded_rules_map = {
    for obj in local.expanded_rules : obj.key => merge(
      obj.rule,
      {
        target_policy      = obj.target_policy,
        direction_override = obj.direction_override
      }
    )
  }
}

resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each        = local.expanded_rules_map
  firewall_policy = google_compute_network_firewall_policy.policies[each.value.target_policy].id
  description     = each.value.description
  priority        = each.value.priority
  direction       = each.value.direction_override

  # Cross-boundary → inspection, except intranet→onprem → allow
  action = (
    lower(each.value.src_vpc) != lower(each.value.dest_vpc) &&
    !(lower(each.value.src_vpc) == "intranet" && lower(each.value.dest_vpc) == "onprem")
  ) ? "apply_security_profile_group" : "allow"

  security_profile_group = (
    lower(each.value.src_vpc) != lower(each.value.dest_vpc) &&
    !(lower(each.value.src_vpc) == "intranet" && lower(each.value.dest_vpc) == "onprem")
  ) ? var.security_profile_group_id : null

  enable_logging = each.value.enable_logging
  tls_inspect    = try(each.value.tls_inspect, false)

  match {
    src_ip_ranges  = each.value.src_ip_ranges
    dest_ip_ranges = each.value.dest_ip_ranges

    layer4_configs {
      ip_protocol = each.value.protocol
      ports       = each.value.ports
    }
  }
}