#resource "google_network_security_firewall_endpoint" "this" {
#  billing_project_id = var.billing_project_id
#  parent             = var.org_id
#  name               = var.endpoint_name
#  location           = var.zone            # The zone for the endpoint, e.g., "us-central1-a"
#}
#
#resource "google_network_security_firewall_endpoint_association" "this" {
#  name              = "${var.endpoint_name}-assoc"
#  location          = var.zone
#  firewall_endpoint = google_network_security_firewall_endpoint.this.id
#  network           = var.vpc_network_id    # attach to this VPC in the same zone
#  tls_inspection_policy = var.tls_policy_id # attach the TLS inspection policy to this endpoint association
#}
