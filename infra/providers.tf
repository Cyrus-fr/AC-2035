# AC-2035 — Terraform + provider version pins.

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # Remote state in GCS (U12). Partial config — bucket/prefix are supplied at
  # init time from backends/<env>.gcs.tfbackend. For OFFLINE validation that
  # never touches GCS: `terraform init -backend=false && terraform validate`.
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}
