# AC-2035 — custom VPC + single subnet with Flow Logs enabled.
#
# Flow Logs are turned on at 5s aggregation with full metadata so the
# detector/collector pipeline (later phases) has raw network telemetry to
# correlate honeytoken triggers against.

resource "google_compute_network" "main" {
  project                 = var.project_id
  name                     = "ac2035-vpc-${var.environment}"
  auto_create_subnetworks  = false
  routing_mode             = "REGIONAL"
}

resource "google_compute_subnetwork" "main" {
  project       = var.project_id
  name          = "ac2035-subnet-${var.environment}"
  network       = google_compute_network.main.id
  region        = var.region
  ip_cidr_range = "10.10.0.0/20"

  # Secondary ranges required for a VPC-native (alias IP) GKE cluster.
  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.20.0.0/14"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.30.0.0/20"
  }

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }

  private_ip_google_access = true
}

resource "google_compute_router" "main" {
  project = var.project_id
  name    = "ac2035-router-${var.environment}"
  network = google_compute_network.main.id
  region  = var.region
}

resource "google_compute_router_nat" "main" {
  project                            = var.project_id
  name                               = "ac2035-nat-${var.environment}"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
