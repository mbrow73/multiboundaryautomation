# terraform.tfvars – dummy values for offline planning
project_id  = "dummy-project"
region      = "us-central1"
credentials = "dummy-creds.json"
security_profile_group_id = "SG1"

vpc_boundaries = {
  dmz     = "projects/dummy-project/global/networks/dmz"
  intranet = "projects/dummy-project/global/networks/intranet"
  onprem   = "projects/dummy-project/global/networks/onprem"
  third_party_peering = "projects/dummy-project/global/networks/onprem"
}
