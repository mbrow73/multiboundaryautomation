# Configure the Google provider (authenticate and set project)
provider "google" {
  project     = var.project_id
  region      = var.region
  credentials = var.credentials
}

locals {
  auto_firewall_rules = flatten([
    for fname in fileset("${path.module}/firewall-requests", "*.auto.tfvars.json") :
      jsondecode(
        file("${path.module}/firewall-requests/${fname}")
      ).auto_firewall_rules
  ])
}

# Deploy network firewall policies for each boundary and expand auto rules.
module "inet_firewall_policy" {
  source = "./modules/firewall_policy"

  project_id               = var.project_id
  policy_name              = "boundary"
  vpc_boundaries           = var.vpc_boundaries
  security_profile_group_id= var.security_profile_group_id

  # Only pass auto firewall rules; manual rules are handled separately.
  inet_firewall_rules      = local.auto_firewall_rules
}

module "fw_endpoints" {
  source = "./modules/firewall_endpoint"

  billing_project_id = "dummy-project"
  org_id             = "organizations/123456789012"

  # Define only the endpoints you want.
  firewall_endpoints = {
#    "ngfw-us-east1-b"     = { zone = "us-east1-b" }
    "ngfw-us-central1-a"  = { zone = "us-central1-a" }
  }

  # Define only the associations you want.  Each key becomes the association name.
  firewall_endpoint_associations = {
    "ngfw-us-central1-a-dmz" = {
      endpoint_name = "ngfw-us-central1-a"
      zone          = "us-central1-a"
      network_id    = "projects/dummy-project/global/networks/dmz"
    }
    "ngfw-us-central1-a-intranet" = {
      endpoint_name = "ngfw-us-central1-a"
      zone          = "us-central1-a"
      network_id    = "projects/dummy-project/global/networks/intranet"
    },
    "ngfw-us-central1-a-third-party-peering" = {
      endpoint_name = "ngfw-us-central1-a"
      zone          = "us-central1-a"
      network_id    = "projects/dummy-project/global/networks/intranet"
    }
  }
}
