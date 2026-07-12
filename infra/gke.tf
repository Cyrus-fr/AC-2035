# AC-2035 — GKE cluster (VPC-native, workload identity, single node pool).

resource "google_container_cluster" "main" {
  project  = var.project_id
  name     = var.cluster_name
  location = var.region

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.main.id

  # Manage node pools explicitly via google_container_node_pool below.
  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  deletion_protection = false

  resource_labels = {
    environment = var.environment
    project     = "ac2035"
  }
}

resource "google_container_node_pool" "primary" {
  project  = var.project_id
  name     = "${var.cluster_name}-pool"
  location = var.region
  cluster  = google_container_cluster.main.name

  node_count = 1

  node_config {
    machine_type = "e2-standard-4"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    labels = {
      environment = var.environment
      project     = "ac2035"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
