#resource "google_certificate_manager_trust_config" "this" {
#  location    = var.location
#  name        = var.trust_config_name
#  project     = var.project_id
#  description = "Trusted CAs for TLS inspection (placeholder)"
#  trust_stores {
#    trust_anchors { 
#      pem_certificate = var.trust_anchor_cert
#    }
#    intermediate_cas { 
#      pem_certificate = var.intermediate_ca_cert
#    }
#  }
#}
#
#resource "google_network_security_tls_inspection_policy" "this" {
#  name     = var.tls_policy_name
#  project  = var.project_id
#  location = var.location      # Must match CA pool region&#8203;:contentReference[oaicite:11]{index=11}
#  description = "TLS inspection policy for NGFW"
#  
#  ca_pool     = var.ca_pool_id  # reference to CA pool (from CA module)
#  trust_config = google_certificate_manager_trust_config.this.id  # attach trust config
#  
#  min_tls_version = "TLS_1_2"   # require TLS 1.2 or higher (optional)
#  tls_feature_profile = "MODERN"  # TLS feature profile 
#  # custom_tls_features could be set if needed for specific ciphers
#}
#