# Define a network firewall policy for each boundary specified in the input map.
resource "google_compute_network_firewall_policy" "policy" {
  for_each    = var.boundary_policies
  name        = each.value.policy_name
  project     = var.project_id
  description = "Boundary‑aware NGFW policy for boundary ${each.key}"
}

# Attach each policy to its corresponding VPC network.  The on‑prem boundary is a
# stub: consumers should provide an empty string for vpc_id and Terraform will
# skip creating an association.
resource "google_compute_network_firewall_policy_association" "association" {
  for_each = {
    for k, v in var.boundary_policies : k => v
    if v.vpc_id != ""
  }
  name              = each.key
  attachment_target = each.value.vpc_id
  firewall_policy   = google_compute_network_firewall_policy.policy[each.key].id
}

locals {
  # Flatten all rules across boundaries and compute derived fields.  The keys of
  # the resulting map are unique identifiers combining the boundary and rule
  # name.  We build a list of per‑boundary maps then merge them into a single
  # map using the splat operator (...).
  flattened_rules = merge([
    for boundary, cfg in var.boundary_policies : {
      for r in cfg.firewall_rules :
      "${boundary}-${r.name}" => {
        boundary = boundary
        rule     = r
      }
    }
  ]...)
}

resource "google_compute_network_firewall_policy_rule" "rule" {
  for_each = local.flattened_rules

  firewall_policy = google_compute_network_firewall_policy.policy[each.value.boundary].id
  priority        = each.value.rule.priority
  description     = each.value.rule.description
  direction       = each.value.rule.direction

  # Determine the action: apply security profiles on inter‑boundary flows unless
  # explicitly overridden.  When action is set to apply_security_profile_group but
  # no custom security_profile_group is provided, fall back to the module
  # variable security_profile_group_id.
  action = coalesce(
    # honour explicit action if provided
    each.value.rule.action,
    # default action: apply_security_profile_group when src and dest boundaries differ
    each.value.rule.src_boundary != each.value.rule.dest_boundary ? "apply_security_profile_group" : "allow"
  )

  enable_logging = each.value.rule.enable_logging
  tls_inspect    = try(each.value.rule.tls_inspection, null)
  security_profile_group = (
    # If the resolved action is apply_security_profile_group
    (coalesce(each.value.rule.action, each.value.rule.src_boundary != each.value.rule.dest_boundary ? "apply_security_profile_group" : "allow") == "apply_security_profile_group")
      ? coalesce(each.value.rule.security_profile_group, var.security_profile_group_id)
      : try(each.value.rule.security_profile_group, null)
  )

  match {
    src_ip_ranges  = each.value.rule.src_ip_ranges
    dest_ip_ranges = each.value.rule.dest_ip_ranges
    layer4_configs {
      ip_protocol = each.value.rule.protocol
      ports       = each.value.rule.ports
    }
  }
}