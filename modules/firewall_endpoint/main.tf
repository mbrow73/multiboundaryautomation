# Create each firewall endpoint exactly as specified in the firewall_endpoints variable.
resource "google_network_security_firewall_endpoint" "endpoint" {
  for_each           = var.firewall_endpoints
  billing_project_id = var.billing_project_id
  parent             = var.org_id
  name               = each.key
  location           = each.value.zone
}

# Create each association exactly as specified in the firewall_endpoint_associations variable.
resource "google_network_security_firewall_endpoint_association" "assoc" {
  for_each = var.firewall_endpoint_associations

  name     = each.key
  location = each.value.zone

  # Reference the correct endpoint by name.  The endpoint must exist in the
  # firewall_endpoints map; Terraform will error if it does not.
  firewall_endpoint     = google_network_security_firewall_endpoint.endpoint[each.value.endpoint_name].id
  network               = each.value.network_id
}
