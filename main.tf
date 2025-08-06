# Configure the Google provider (authenticate and set project)
provider "google" {
  project     = var.project_id
  region      = var.region
  credentials = var.credentials
}

#
# Collect firewall rules from auto‑generated requests and manually
# maintained entries.  Both lists must include the source and
# destination VPC names (src_vpc/dest_vpc) to enable boundary logic.
locals {
  auto_firewall_rules = flatten([
    for f in fileset("${path.module}/firewall-requests", "*.auto.tfvars.json") :
      jsondecode(file("${path.module}/firewall-requests/${f}")).auto_firewall_rules
  ])
  manual_firewall_rules = jsondecode(file("${path.module}/manual.auto.tfvars.json")).manual_firewall_rules
  all_firewall_rules    = concat(local.auto_firewall_rules, local.manual_firewall_rules)
}

# Module: Network firewall policies.  Creates one policy per VPC
# boundary defined in `var.vpc_boundaries` and populates it with the
# combined list of firewall rules.  Cross‑boundary traffic is
# automatically inspected via `apply_security_profile_group`.
module "inet_firewall_policy" {
  source  = "./modules/firewall_policy"
  project_id = var.project_id
  policy_name = "inet-policy"
  vpc_boundaries = var.vpc_boundaries
  security_profile_group_id = var.security_profile_group_id
  inet_firewall_rules = local.all_firewall_rules
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
    "ngfw-us-east1-b-dmz" = {
      endpoint_name = "ngfw-us-central1-a"
      zone          = "us-central1-a"
      network_id    = "projects/dummy-project/global/networks/dmz"
    }
    "ngfw-us-central1-a-intranet" = {
      endpoint_name = "ngfw-us-central1-a"
      zone          = "us-central1-a"
      network_id    = "projects/dummy-project/global/networks/intranet"
    }
  }
}
