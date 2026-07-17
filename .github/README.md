# AC-2035 CI

Two tracks. **Track A blocks every merge; Track B blocks merges when it runs.**

## Track A — `.github/workflows/ci-unit.yml` (real)
Runs on GitHub-hosted runners: Python 3.11 → `pip install -r requirements-dev.txt`
→ `pytest tests/ -v`. No cluster, eBPF, or cloud credentials, and never
simulation mode for the logic under test. This is the suite verified locally
(26 tests) and the always-on merge gate.

## Track B — `.github/workflows/ci-integration.yml` + `infra/cloudbuild.yaml` (ARTIFACT-ONLY)
> Written to spec, **not run** from this repo. Requires a GCP project, billing,
> Workload Identity Federation, and (Research tier) the U8 scenarios + U9
> evaluator that `infra/cloudbuild.yaml` step 4 invokes.

On a PR labeled `run-integration`, GitHub authenticates to GCP via WIF and
submits `infra/cloudbuild.yaml` to Cloud Build, which:
1. `terraform init` with the CI backend + a per-run prefix `run-$GITHUB_SHA`,
2. applies an ephemeral GKE cluster,
3. deploys honeytokens + loads real eBPF LSM hooks,
4. runs the attack scenarios and **fails if backtrace accuracy ≤ 90%**,
5. `terraform destroy` + `gsutil rm -r gs://ac2035-tfstate-ci/run-$GITHUB_SHA/`
   (belt-and-braces over the CI bucket's 24h lifecycle rule from `infra/storage.tf`).

## Live verification checklist
1. **Track A** — open a PR; the `ci-unit` check runs `pytest tests/`. Nothing else needed.
2. **Bootstrap GCP once** (see `infra/README.md`): the tfstate buckets, a
   Workload Identity Federation pool/provider for this repo, and the `ac2035-ci`
   service account (`infra/storage.tf`).
3. **Set repo Actions variables** (Settings → Secrets and variables → Actions → Variables):
   - `GCP_PROJECT_ID`
   - `GCP_WIF_PROVIDER` — `projects/<N>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`
   - `GCP_CI_SERVICE_ACCOUNT` — `ac2035-ci@<project>.iam.gserviceaccount.com`
4. **Enable Track B** — add the `run-integration` label to a PR; follow the Cloud Build logs.
5. **Make both required** — Settings → Branches → protect `main` → require the
   `ci-unit` and `ci-integration` status checks. PRs are then blocked if either fails.
