#resource "google_privateca_ca_pool" "this" {
#  name     = var.ca_pool_name
#  project  = var.project_id
#  location = var.location         # e.g. "us-central1"
#  tier     = "ENTERPRISE"         
#}
#
#resource "google_privateca_certificate_authority" "this" {
#  certificate_authority_id = "${var.ca_name}-ca"  # Unique ID for CA
#  name    = var.ca_name
#  project = var.project_id
#  location = var.location
#  pool    = google_privateca_ca_pool.this.name
#  type    = "SELF_SIGNED"         
#  key_spec {
#    algorithm = "RSA_PSS_2048_SHA256"  # Placeholder key algorithm
#  }
#  config {
#    subject_config {
#    subject {
#        common_name  = var.ca_common_name    # e.g. "Example TLS Inspection CA"
#        organization = var.ca_organization   # e.g. "ExampleCorp"
#        country_code = var.ca_country        # e.g. "US"
#      }
#    }
#    x509_config {
#      ca_options { is_ca = true }
#      key_usage {
#        base_key_usage {
#          cert_sign = true
#          crl_sign  = true
#        }
#        extended_key_usage {
#          server_auth = true
#          client_auth = true
#        }
#      }
#    }
#  }
#  lifetime = "8760h"  # 1 year (placeholder)
#  depends_on = [google_privateca_ca_pool.this]
#}
#