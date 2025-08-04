// modules/firewall_policy/main.tf

/*
 * Expand each “intent” rule into one or two boundary‐specific rules,
 * auto-deriving direction and inspection.
 */
locals {
  expanded_rules = flatten([
    for r in var.inet_firewall_rules : concat(
      // 1) Always emit SRC‐side EGRESS
      [
        {
          key                = "${r.name}-${lower(r.src_vpc)}-egress"
          policy             = lower(r.src_vpc)
          direction_override = "EGRESS"
          apply_inspect      = lower(r.src_vpc) != lower(r.dest_vpc)
          priority           = r.priority
          rule               = r
        }
      ],
      // 2) DEST‐side: either an INGRESS allow (normal), or a second EGRESS (onprem case)
      lower(r.dest_vpc) == "onprem"
        ? (
            lower(r.src_vpc) != "intranet"
              ? [ // non-intranet → onprem: egress in intranet, inspect
                  {
                    key                = "${r.name}-intranet-egress"
                    policy             = "intranet"
                    direction_override = "EGRESS"
                    apply_inspect      = true
                    priority           = r.priority + 1
                    rule               = r
                  }
                ]
              : []  // intranet→onprem: only one egress (above), no ingress
          )
        : [  // normal cross- or intra-VPC: INGRESS allow
            {
              key                = "${r.name}-${lower(r.dest_vpc)}-ingress"
              policy             = lower(r.dest_vpc)
              direction_override = "INGRESS"
              apply_inspect      = false
              priority           = r.priority
              rule               = r
            }
          ]
    )
  ])
}

# 1) One policy per boundary
resource "google_compute_network_firewall_policy" "policies" {
  for_each    = var.vpc_boundaries
  name        = "${var.policy_name}-${each.key}"
  project     = var.project_id
  description = "NGFW policy for ${each.key}"
}

# 2) Attach each policy to its VPC
resource "google_compute_network_firewall_policy_association" "attach" {
  for_each          = var.vpc_boundaries
  name              = each.key
  attachment_target = each.value
  firewall_policy   = google_compute_network_firewall_policy.policies[each.key].id
}

# 3) Emit the per‐boundary rules
resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each = {
    for e in local.expanded_rules : e.key => e
  }

  firewall_policy = google_compute_network_firewall_policy.policies[each.value.policy].id
  description     = each.value.rule.description
  priority        = each.value.priority
  direction       = each.value.direction_override

  # EGRESS + cross-boundary ⇒ inspect; otherwise allow
  action                 = each.value.direction_override == "EGRESS" && each.value.apply_inspect ? "apply_security_profile_group" : "allow"
  security_profile_group = each.value.direction_override == "EGRESS" && each.value.apply_inspect ? var.security_profile_group_id              : null

  enable_logging = each.value.rule.enable_logging
  tls_inspect    = try(each.value.rule.tls_inspect, false)

  match {
    src_ip_ranges  = each.value.rule.src_ip_ranges
    dest_ip_ranges = each.value.rule.dest_ip_ranges

    layer4_configs {
      ip_protocol = each.value.rule.protocol
      ports       = each.value.rule.ports
    }
  }
}
