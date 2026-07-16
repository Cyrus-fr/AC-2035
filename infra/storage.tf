# ARTIFACT-ONLY: written to spec, not deployed.
# Requires GCP project + terraform apply on Linux.
# See Live Verification Checklist in infra/README.md
#
# AC-2035 — immutable audit storage + isolated CI Terraform state (U12).

# Immutable forensic audit sink (the U11 application sink streams here). The
# bucket retention policy with is_locked = true is GCS's Object Lock: once
# locked, objects cannot be deleted or overwritten before the retention period
# elapses — an attacker who compromises the cluster cannot alter what was
# already written.
resource "google_storage_bucket" "audit" {
  name                        = "ac2035-audit-${var.project_id}" # bucket names are globally unique
  project                     = var.project_id
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # 7-day minimum retention, permanently locked (irreversible once applied).
  retention_policy {
    is_locked        = true
    retention_period = 7 * 24 * 60 * 60
  }

  labels = {
    environment = var.environment
    project     = "ac2035"
    purpose     = "immutable-audit"
  }
}

# Ephemeral CI Terraform-state bucket. Per-run state lives under run-$GITHUB_SHA/
# (see infra/backends/ci.gcs.tfbackend). A lifecycle rule auto-deletes objects
# older than ~24h so a CI crash mid-teardown can never leave zombie state that
# affects prod.
resource "google_storage_bucket" "ci_tfstate" {
  name                        = "ac2035-tfstate-ci"
  project                     = var.project_id
  location                    = var.region
  force_destroy               = true # CI state is disposable
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # GCS lifecycle age is day-granular; age = 1 deletes objects > ~24h old.
  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment = "ci"
    project     = "ac2035"
    purpose     = "ephemeral-tfstate"
  }
}

# CI service account, granted delete rights ONLY on the CI state bucket
# (bucket-scoped roles/storage.admin includes storage.buckets.delete). This lets
# CI tear down its own zombie state without any access to prod state.
resource "google_service_account" "ci" {
  account_id   = "ac2035-ci"
  display_name = "AC-2035 CI (ephemeral integration tests)"
  project      = var.project_id
}

resource "google_storage_bucket_iam_member" "ci_state_admin" {
  bucket = google_storage_bucket.ci_tfstate.name
  role   = "roles/storage.admin" # bucket-scoped; grants storage.buckets.delete on this bucket only
  member = "serviceAccount:${google_service_account.ci.email}"
}
