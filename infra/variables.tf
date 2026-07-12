# AC-2035 — shared Terraform input variables.

variable "project_id" {
  description = "GCP project ID that all AC-2035 resources are created in."
  type        = string
}

variable "region" {
  description = "Primary GCP region for regional resources (GKE, subnet, Pub/Sub)."
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "Name of the GKE cluster running the AC-2035 control plane services."
  type        = string
  default     = "ac2035-cluster"
}

variable "environment" {
  description = "Deployment environment label (e.g. dev, staging, prod). Applied as a resource label/tag."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}
