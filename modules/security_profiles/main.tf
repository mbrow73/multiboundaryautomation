# Example Intrusion Prevention profile (IPS)
#resource "google_network_security_security_profile" "ips_profile" {
#  type        = "INTRUSION_PREVENTION"  # Type of security profile
#  name        = var.ips_profile_name
#  parent      = var.org_id
#  description = "Intrusion Prevention profile "
#  
#   threat_prevention_profile {
#    severity_overrides {
#      action   = "ALLOW"
#      severity = "INFORMATIONAL"
#    }
#
#    severity_overrides {
#      action   = "ALERT"
#      severity = "LOW"
#    }
#
#    severity_overrides {
#      action   = "ALERT"
#      severity = "MEDIUM"
#    }
#
#    severity_overrides {
#      action   = "BLOCK"
#      severity = "HIGH"
#    }
#
#    severity_overrides {
#      action   = "BLOCK"
#      severity = "CRITICAL"
#    }
#   }
#  }
#
## Group the profiles into a Security Profile Group
#resource "google_network_security_security_profile_group" "this" {
#  name     = var.profile_group_name
#  parent   = var.org_id
#  location = var.location     # likely "global"
#  description = "Security profile group with IPS/AV"
#  threat_prevention_profile = [
#    google_network_security_security_profile.ips_profile.id
#  ]
#}
#