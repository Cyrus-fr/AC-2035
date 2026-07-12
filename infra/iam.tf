# AC-2035 — least-privilege service accounts + Workload Identity bindings.
#
# Each service account is scoped to only the roles its component needs:
#   collector   subscribes to telemetry-raw/honeytoken-triggers, and reads
#               historical Cloud Logging + VPC Flow Logs to run the T-30min
#               forensic backtrace (Phase 2/3) — needs log READ, not just write
#   deployer    generates/injects/rotates honeytokens in Secret Manager —
#               needs version write access, not just accessor (read)
#   killswitch  revokes credentials/access fast — IAM + compute admin scoped
#               to just what's needed to disable a principal
#
# All three run as GKE workloads, so each GSA is bound to a matching
# Kubernetes service account (same name as the component) via Workload
# Identity. The KSAs themselves are created by the k8s manifests in later
# phases; the binding here just authorizes that link in advance.

locals {
  workload_identity_namespace = "ac2035"
}

# ── Collector ────────────────────────────────────────
resource "google_service_account" "collector" {
  project      = var.project_id
  account_id   = "ac2035-collector"
  display_name = "AC-2035 Collector"
  description  = "Consumes telemetry-raw/honeytoken-triggers and reads historical logs for forensic backtracing."
}

resource "google_project_iam_member" "collector_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.collector.email}"
}

# Read access to Cloud Logging (VPC Flow Logs + audit logs) for the T-30min
# backtrace window. logWriter alone only lets it emit its own logs.
resource "google_project_iam_member" "collector_logging_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.collector.email}"
}

resource "google_project_iam_member" "collector_logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.collector.email}"
}

resource "google_service_account_iam_member" "collector_workload_identity" {
  service_account_id = google_service_account.collector.name
  role                = "roles/iam.workloadIdentityUser"
  member              = "serviceAccount:${var.project_id}.svc.id.goog[${local.workload_identity_namespace}/collector]"
}

# ── Deployer ─────────────────────────────────────────
resource "google_service_account" "deployer" {
  project      = var.project_id
  account_id   = "ac2035-deployer"
  display_name = "AC-2035 Deployer"
  description  = "Generates, injects, and auto-rotates honeytokens; publishes to honeytoken-triggers."
}

resource "google_project_iam_member" "deployer_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# secretAccessor alone is read-only (secrets.versions.access) and cannot
# create/rotate versions. secretmanager.admin grants create/add/destroy on
# versions and secrets. Project-scoped for Phase 0; tighten to per-secret
# IAM conditions once real honeytoken secret names exist.
resource "google_project_iam_member" "deployer_secretmanager_admin" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_service_account_iam_member" "deployer_workload_identity" {
  service_account_id = google_service_account.deployer.name
  role                = "roles/iam.workloadIdentityUser"
  member              = "serviceAccount:${var.project_id}.svc.id.goog[${local.workload_identity_namespace}/deployer]"
}

# ── Killswitch ───────────────────────────────────────
resource "google_service_account" "killswitch" {
  project      = var.project_id
  account_id   = "ac2035-killswitch"
  display_name = "AC-2035 Killswitch"
  description  = "Revokes compromised principals/access in response to a confirmed attribution."
}

resource "google_project_iam_member" "killswitch_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.killswitch.email}"
}

resource "google_project_iam_member" "killswitch_security_admin" {
  project = var.project_id
  role    = "roles/iam.securityAdmin"
  member  = "serviceAccount:${google_service_account.killswitch.email}"
}

resource "google_service_account_iam_member" "killswitch_workload_identity" {
  service_account_id = google_service_account.killswitch.name
  role                = "roles/iam.workloadIdentityUser"
  member              = "serviceAccount:${var.project_id}.svc.id.goog[${local.workload_identity_namespace}/killswitch]"
}
