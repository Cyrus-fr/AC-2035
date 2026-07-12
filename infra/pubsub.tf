# AC-2035 — Pub/Sub topics for honeytoken triggers and raw telemetry.

resource "google_pubsub_topic" "honeytoken_triggers" {
  project = var.project_id
  name    = "honeytoken-triggers"

  labels = {
    environment = var.environment
    project     = "ac2035"
  }
}

resource "google_pubsub_subscription" "honeytoken_triggers" {
  project = var.project_id
  name    = "honeytoken-triggers-sub"
  topic   = google_pubsub_topic.honeytoken_triggers.id

  ack_deadline_seconds       = 30
  message_retention_duration = "604800s" # 7 days

  expiration_policy {
    ttl = "" # never expires
  }
}

resource "google_pubsub_topic" "telemetry_raw" {
  project = var.project_id
  name    = "telemetry-raw"

  labels = {
    environment = var.environment
    project     = "ac2035"
  }
}

resource "google_pubsub_subscription" "telemetry_raw" {
  project = var.project_id
  name    = "telemetry-raw-sub"
  topic   = google_pubsub_topic.telemetry_raw.id

  ack_deadline_seconds       = 30
  message_retention_duration = "604800s" # 7 days

  expiration_policy {
    ttl = "" # never expires
  }
}
