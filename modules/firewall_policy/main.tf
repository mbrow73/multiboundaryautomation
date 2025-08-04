/*
 * Network Firewall Policy Module — Multi‑Boundary
 *
 * This module provisions a Google Cloud network firewall policy per logical
 * boundary/VPC.  Each policy is attached to its own VPC network and
 * populated with the provided firewall rules.  Rules include the source
 * and destination VPC identifiers so that cross‑boundary traffic can be
 * treated differently from intra‑VPC traffic.  An action of
 * `apply_security_profile_group` is automatically applied to any rule
 * where the source and destination VPC differ (except for the special
 * intranet→on‑prem case).  Intra‑VPC traffic is always allowed.  The
 * security profile group ID used for inspection comes from the
 * `security_profile_group_id` input variable.
 */


/*
 * Create one firewall policy per boundary.  The map keys of
 * `vpc_boundaries` should match the `src_vpc`/`dest_vpc` values used in
 * firewall rules.  Each policy is named by combining the base
 * `policy_name` with the boundary key.
 */
resource "google_compute_network_firewall_policy" "policies" {
  for_each    = var.vpc_boundaries
  name        = "${var.policy_name}-${each.key}"
  project     = var.project_id
  description = "NGFW firewall policy for ${each.key}"
}

/*
 * Attach each policy to its corresponding VPC network.  The
 * `attachment_target` must be the self‑link of the VPC provided in
 * `vpc_boundaries`.
 */
resource "google_compute_network_firewall_policy_association" "attach" {
  for_each         = var.vpc_boundaries
  name             = each.key
  attachment_target = each.value
  firewall_policy   = google_compute_network_firewall_policy.policies[each.key].id
}

/*
 * Expand the input rules into one or more per‑policy rules.  When a rule
 * references the special "onprem" boundary, it must traverse the
 * intranet boundary before leaving the cloud.  This means:
 *   • If either the src_vpc or dest_vpc is "onprem", a copy of the rule
 *     is always applied to the intranet policy.
 *   • If the other boundary is not "intranet", another copy is applied to
 *     that boundary as well (to handle the leg between the other VPC and
 *     the intranet hub).
 *   • When both sides are intranet/onprem, only a single intranet rule
 *     is generated.
 */
locals {
  # For each input rule, build one or two per‑policy entries to ensure both
  # ingress and egress sides are represented.  The 'dest' entry uses the
  # original direction relative to the destination policy; the 'src' entry
  # (if the source policy differs) uses the opposite direction.
  expanded_rules = flatten([
    for r in var.inet_firewall_rules : [
      for entry in concat(
        # always include the destination side
        [
          {
            policy             = lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc)
            suffix             = "dest"
            direction_override = r.direction
          }
        ],
        # include the source side (opposite direction) only if the policies differ
        (
          (
            lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc)
          ) != (
            lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc)
          )
        ) ? [
          {
            policy             = lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc)
            suffix             = "src"
            direction_override = (upper(r.direction) == "INGRESS" ? "EGRESS" : "INGRESS")
          }
        ] : []
      ) : {
        key               = "${r.name}-${entry.policy}-${entry.suffix}"
        rule              = r
        target_policy     = entry.policy
        direction_override= entry.direction_override
      }
    ]
  ])

  # Convert list to map keyed by unique key for use in for_each
  expanded_rules_map = {
    for obj in local.expanded_rules : obj.key => merge(
      obj.rule,
      {
        target_policy     = obj.target_policy,
        direction_override= obj.direction_override
      }
    )
  }
}

/*
 * Create firewall rules on the appropriate policy.  The policy is
 * selected based on the `target_policy` computed above.  The action
 * and security profile group are derived on‑the‑fly according to the
 * boundary logic: if the source and destination VPC differ (and it is
 * not the intranet→onprem case) then inspection is applied.
 */
resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each        = local.expanded_rules_map
  firewall_policy = google_compute_network_firewall_policy.policies[each.value.target_policy].id
  description     = each.value.description
  priority        = each.value.priority
  # Use the overridden direction computed during rule expansion.  This ensures
  # that each boundary receives an appropriate ingress/egress rule.
  direction       = each.value.direction_override

  # Derive action based on boundary logic (using original src_vpc/dest_vpc)
  action = (
    lower(each.value.src_vpc) != lower(each.value.dest_vpc) &&
    !(lower(each.value.src_vpc) == "intranet" && lower(each.value.dest_vpc) == "onprem")
  ) ? "apply_security_profile_group" : "allow"

  # Conditionally set the security profile group
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
