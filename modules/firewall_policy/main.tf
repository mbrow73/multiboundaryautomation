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
  for_each = {
    for k, v in var.vpc_boundaries : k => v if lower(k) != "onprem"
  }
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
  for_each = {
    for k, v in var.vpc_boundaries : k => v if lower(k) != "onprem"
  }
  name              = each.key
  attachment_target = each.value
  firewall_policy   = google_compute_network_firewall_policy.policies[each.key].id
}

/*
 * Expand the input rules into one or more per‑policy rules.  When a rule
 * references the special "onprem" boundary, it must traverse the
 * intranet boundary before leaving the cloud.  The logic below implements
 * the following behaviour:
 *
 *   • Health‑check and restricted‑API ranges (src_vpc == dest_vpc) result in
 *     a single rule on that boundary; the requested direction is preserved.
 *
 *   • onprem → intranet         → one ingress rule on intranet.
 *   • intranet → onprem         → one egress rule on intranet.
 *   • onprem → non‑intranet     → one ingress rule on the destination VPC
 *                                 with inspection (apply_security = true).
 *   • non‑intranet → onprem     → one egress rule on the source VPC
 *                                 with inspection (apply_security = true).
 *
 *   • All other cross‑boundary traffic → two rules: an ingress rule on
 *     the destination VPC and an egress rule on the source VPC.  The
 *     egress rule is inspected (apply_security = true).
 */
locals {
  expanded_rules = flatten([
    for r in var.inet_firewall_rules : (
      # Same boundary (health‑check or restricted‑API).  Use caller-supplied direction.
      lower(r.src_vpc) == lower(r.dest_vpc) ? [
        {
          key                = "${r.name}-${(lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc))}-dest"
          policy             = lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc)
          suffix             = "dest"
          direction_override = (trimspace(r.direction) != "" ? upper(r.direction) : "INGRESS")
          apply_security     = false
          rule               = r
        }
      ] :
      # onprem → intranet: ingress rule on intranet
      (lower(r.src_vpc) == "onprem" && lower(r.dest_vpc) == "intranet") ? [
        {
          key                = "${r.name}-intranet-dest"
          policy             = "intranet"
          suffix             = "dest"
          direction_override = "INGRESS"
          apply_security     = false
          rule               = r
        }
      ] :
      # intranet → onprem: egress rule on intranet
      (lower(r.dest_vpc) == "onprem" && lower(r.src_vpc) == "intranet") ? [
        {
          key                = "${r.name}-intranet-dest"
          policy             = "intranet"
          suffix             = "dest"
          direction_override = "EGRESS"
          apply_security     = false
          rule               = r
        }
      ] :
      # onprem → non‑intranet: ingress rule on destination with inspection
      (lower(r.src_vpc) == "onprem" && lower(r.dest_vpc) != "intranet") ? [
        {
          key                = "${r.name}-${lower(r.dest_vpc)}-dest"
          policy             = lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc)
          suffix             = "dest"
          direction_override = "INGRESS"
          apply_security     = true
          rule               = r
        }
      ] :
      # non‑intranet → onprem: egress rule on source with inspection
      (lower(r.dest_vpc) == "onprem" && lower(r.src_vpc) != "intranet") ? [
        {
          key                = "${r.name}-${lower(r.src_vpc)}-dest"
          policy             = lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc)
          suffix             = "dest"
          direction_override = "EGRESS"
          apply_security     = true
          rule               = r
        }
      ] :
      # General cross‑VPC case: create both dest and src entries
      [
        {
          key                = "${r.name}-${(lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc))}-dest"
          policy             = lower(r.dest_vpc) == "onprem" ? "intranet" : lower(r.dest_vpc)
          suffix             = "dest"
          direction_override = (
            lower(r.dest_vpc) == "onprem" ? "EGRESS" : (
              lower(r.dest_vpc) == lower(r.src_vpc) ?
                (trimspace(r.direction) != "" ? upper(r.direction) : "INGRESS") :
                "INGRESS"
            )
          )
          apply_security     = false
          rule               = r
        },
        {
          key                = "${r.name}-${(lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc))}-src"
          policy             = lower(r.src_vpc) == "onprem" ? "intranet" : lower(r.src_vpc)
          suffix             = "src"
          direction_override = "EGRESS"
          apply_security     = true
          rule               = r
        }
      ]
    )
  ])

  expanded_rules_map = {
    for obj in local.expanded_rules :
    obj.key => merge(
      obj.rule,
      {
        target_policy      = obj.policy,
        direction_override = obj.direction_override,
        apply_security     = obj.apply_security
      }
    )
  }
}

/*
 * Create firewall rules on the appropriate policy.  The policy is
 * selected based on the `target_policy` computed above.  The action
 * and security profile group are derived on‑the‑fly according to the
 * boundary logic: if apply_security is true, we set the action to
 * `apply_security_profile_group` and assign the configured security
 * profile group ID; otherwise, we just allow the traffic.
 */
resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each        = local.expanded_rules_map

  firewall_policy = google_compute_network_firewall_policy.policies[each.value.target_policy].id
  description     = each.value.description
  priority        = each.value.priority
  direction       = each.value.direction_override

  action                 = each.value.apply_security ? "apply_security_profile_group" : "allow"
  security_profile_group = each.value.apply_security ? var.security_profile_group_id : null

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
