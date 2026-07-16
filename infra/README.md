# AC-2035 Infrastructure (Terraform)

> **ARTIFACT-ONLY.** Everything under `infra/` is written to spec and reviewed,
> but **not deployed** from this repo checkout. It requires a real GCP project,
> billing, and `terraform` on Linux with credentials. Nothing here has been
> `terraform apply`-ed by the build — see the checklist below to verify it live.

## Layout
- `providers.tf` — provider pins + GCS remote-state backend (partial config).
- `vpc.tf`, `gke.tf`, `pubsub.tf`, `iam.tf` — the AC-2035 cluster stack.
- `storage.tf` (U12) — immutable audit bucket (GCS Object Lock) + ephemeral CI
  state bucket (≈24h lifecycle) + CI service account.
- `backends/{prod,dev,ci}.gcs.tfbackend` — isolated remote-state configs.

## Bootstrap (one-time, out of band)
A remote-state bucket cannot hold its own state, so create the state buckets
once with local state before configuring the `gcs` backend:

```bash
gsutil mb -l us-central1 gs://ac2035-tfstate-prod
gsutil mb -l us-central1 gs://ac2035-tfstate-dev
gsutil mb -l us-central1 gs://ac2035-tfstate-ci
```

(`storage.tf` then manages the CI bucket's lifecycle rule + IAM on subsequent
applies. The prod/dev state buckets stay bootstrap-managed.)

## Live Verification Checklist (Linux + GCP)
Requires: `gcloud auth application-default login`, a project with billing, and
`terraform >= 1.5`.

**1. Offline sanity — safe anywhere, no GCP needed** (this is all the build ran):

```bash
cd infra
terraform fmt -check -recursive
terraform init -backend=false      # skip GCS backend config
terraform validate
```

**2. Provision the prod stack from zero:**

```bash
export TF_VAR_project_id=<your-project>
terraform init -backend-config=backends/prod.gcs.tfbackend
terraform plan
terraform apply
```

**3. Confirm the audit bucket is immutable (Object Lock):**

```bash
gsutil retention get gs://ac2035-audit-<project>          # 7d, locked
gsutil rm gs://ac2035-audit-<project>/<some-object>       # expect: 403 (retained)
```

**4. Confirm CI-state isolation + auto-cleanup:**

```bash
gsutil lifecycle get gs://ac2035-tfstate-ci               # age:1 Delete rule
# per-run isolation (as CI does it):
terraform init -backend-config=backends/ci.gcs.tfbackend \
               -backend-config="prefix=run-${GITHUB_SHA}"
```

**5. Tear down** (the audit bucket is retained: `force_destroy=false` + locked):

```bash
terraform destroy
```
