# AC-2035

Open-source honeytoken forensic attribution system on GCP/GKE.

## Project Overview

AC-2035 deploys and monitors honeytokens (decoy credentials, API keys, and
files) across cloud infrastructure. When a honeytoken is touched, the system
captures the trigger, runs a forensic backtrace over historical telemetry
(VPC Flow Logs, Cloud Logging, Pub/Sub events) to reconstruct the access
chain, builds an attribution graph in Neo4j, and can trip a killswitch to
revoke the offending principal's access.

## Architecture Summary

| Component    | Role                                                              |
|--------------|--------------------------------------------------------------------|
| `detector/`  | eBPF probes + telemetry agent — low-level trigger/event capture     |
| `deployer/`  | Generates, injects, and rotates honeytokens (GCP Secret Manager)    |
| `collector/` | Subscribes to Pub/Sub, reads historical logs for T-30min backtrace  |
| `graph/`     | Neo4j schema + writers — attribution graph construction             |
| `backtrace/` | Forensic reconstruction logic over collected telemetry               |
| `killswitch/`| Revokes compromised principals/access on confirmed attribution       |
| `api/`       | FastAPI service exposing system state and control endpoints         |
| `dashboard/` | Frontend for viewing triggers, graphs, and attribution results       |
| `infra/`     | Terraform for GKE, VPC, Pub/Sub, and IAM                             |

Identity for the dashboard/API is provided by **Zitadel**; local dev runs
Neo4j, Zitadel (+ Postgres), and the API via Docker Compose. Production runs
on GKE (VPC-native, Workload Identity) provisioned by the Terraform in
`infra/`.

## Prerequisites

- Python 3.11+
- Docker + Docker Compose v2 (`docker compose ...`)
- Terraform ~> 1.5, `hashicorp/google` provider ~> 5.0
- A GCP project with billing enabled (for `infra/` deployment)
- `gcloud` CLI authenticated (`gcloud auth application-default login`)

## Local Dev Setup

```bash
cp .env.example .env      # fill in real values — never commit .env
docker compose up -d
```

This starts:

| Service   | URL                          | Notes                          |
|-----------|-------------------------------|---------------------------------|
| Neo4j     | http://localhost:7474         | Browser UI; Bolt on `:7687`     |
| Zitadel   | http://localhost:8081          | Identity provider (+ Postgres)  |
| API       | http://localhost:8000/health   | Returns `{"status": "ok"}`      |

Python deps for local scripting/tooling outside the containers:

```bash
python -m venv .venv
.venv/Scripts/activate     # Windows
pip install -r requirements.txt
```

## GCP Deployment

```bash
cd infra
terraform init
terraform plan  -var="project_id=<your-project-id>"
terraform apply -var="project_id=<your-project-id>"
```

This provisions: a custom VPC + subnet (Flow Logs enabled), a VPC-native GKE
cluster with Workload Identity, the `honeytoken-triggers` and
`telemetry-raw` Pub/Sub topics/subscriptions, and least-privilege service
accounts for `collector`, `deployer`, and `killswitch` (each bound to a
matching Kubernetes service account via Workload Identity).

## Honeytoken Deployer

`deployer/` generates fake credentials, injects them into GKE workloads and
GCP Secret Manager, tracks them in a local SQLite registry, and auto-rotates
them on a schedule.

```bash
python deployer/main.py deploy --pod <name> --namespace <ns> --types gcp_key,gcp_api_key,db_connection,api_token
python deployer/main.py status
python deployer/main.py rotate --all
python deployer/main.py serve       # run the auto-rotation scheduler in the foreground
```

- Token types: `gcp_key` (fake service-account JSON), `gcp_api_key` (`AIza...`),
  `db_connection` (`postgresql://`/`mysql://`), `api_token` (`Bearer` + 256-bit hex).
  None are live, functioning credentials.
- GKE injection resolves the target pod up to its owning Deployment and
  patches the pod template (triggers a rolling update), not the live pod —
  Pod specs are immutable post-creation on a real cluster.
- Works without GCP credentials or a live cluster: with `GCP_PROJECT_ID`
  unset or no kubeconfig/in-cluster config found, each injector logs a
  warning and skips — tokens still get generated and registered.
- Registry lives at `deployer/registry.db` (gitignored); rotation interval
  is `ROTATION_INTERVAL_HOURS` in `.env` (default 24h).
- Token values are never logged — only `token_id` and target locations.

## Telemetry Collector

`collector/` reacts to a honeytoken trigger by pulling the 30 minutes of
telemetry leading up to it from every available source and merging it into
one sorted JSON timeline.

- `pubsub_listener.py` — subscribes to the `honeytoken-triggers` Pub/Sub topic,
  parses each message as a `TriggerEvent`, and runs it through the pipeline.
- `gcp_logs.py` — pulls GCP Cloud Logging entries (`k8s_container` resource,
  matching namespace) for the 30-minute window before the trigger.
- `vpc_flow.py` — pulls VPC Flow Log entries for the same window and extracts
  src/dst IP and port.
- `cloudflare_logs.py` — pulls Cloudflare access logs via the Logpull API for
  the same window, tagging each event with its CF-Ray ID for later correlation.
- `normalizer.py` — merges all sources into a timestamp-sorted list of
  `NormalizedEvent`s and saves it to `collector/timelines/{token_id}_{timestamp}.json`.

Run the local simulation (no GCP/Cloudflare required):

```bash
python collector/simulate_trigger.py
```

This fabricates a `TriggerEvent` plus 20-30 realistic mixed events
(`k8s_log` / `vpc_flow` / `cloudflare_access`), merges and sorts them, saves
the timeline JSON, and prints it to the console.

`pubsub_listener.py` follows the same local-first pattern as the deployer:
with `GCP_PROJECT_ID` empty it drops into simulation mode, reading
`TriggerEvent` JSON lines from stdin instead of subscribing to Pub/Sub.

Partial timelines are expected and fine — if GCP or Cloudflare credentials
are missing (or a source's request fails), that fetcher logs a warning and
returns an empty list rather than aborting the run, so the timeline is just
built from whichever sources succeeded.

## Neo4j Graph Ingestor

`graph/` loads a Phase 2 timeline into Neo4j as a queryable attribution
graph — nodes for every actor/resource, edges for every interaction.

- `schema.py` — applies uniqueness constraints (`ExternalIP`, `Pod`,
  `Service`, `Identity`, `Honeytoken`, `Technique`) and indexes, and owns
  the singleton `get_driver()` every other module connects through. Every
  statement is `IF NOT EXISTS` — safe to run any number of times.
- `ingestor.py` — writes a timeline in batches of up to 100 events per
  transaction. Nodes are always `MERGE`d (re-ingesting a timeline never
  creates duplicates); edges are always `CREATE`d (each event is a
  distinct occurrence in time).
- `queries.py` — the Cypher query library Phase 4 (Backtrace Engine) calls
  directly: `find_paths_to_token`, `find_cf_ray_chain`,
  `find_vpc_flow_chain`, `get_full_graph` (Cytoscape.js-shaped, for
  Phase 7), and `clear_graph`.

Run the end-to-end demo (loads the most recent `collector/timelines/`
file, applies the schema, ingests it, then runs a path query):

```bash
python collector/simulate_trigger.py   # produces a timeline first, if you don't have one
python graph/demo_ingest.py
```

Open the Neo4j browser at http://localhost:7474 to see the resulting
graph. Because node writes go through `MERGE` on each node's unique key,
re-running the demo against the same timeline is safe — it never
duplicates `ExternalIP`/`Pod`/`Honeytoken` nodes, only adds the new edges.

## Forensic Backtrace Engine

**This is the novel contribution of AC-2035.** `backtrace/` takes a
honeytoken trigger and reconstructs the attacker's full path — from
external entry point through every hop to the stolen token — by
correlating the Neo4j graph on **CF-Ray headers and VPC Flow chains as
deterministic keys**, scoring each hop by confidence, and tagging MITRE
ATT&CK techniques. It emits a single structured `AttackObject`.

- `engine.py` — orchestrator; `run_backtrace(trigger_event)` runs the full
  load → ingest → correlate → find paths → score → MITRE-tag flow and
  returns the `AttackObject`.
- `correlator.py` — the deterministic correlation core: `find_cf_ray`
  (which CF-Ray reached the trigger pod), `trace_entry` (external IP behind
  a CF-Ray), `find_vpc_chain` (VPC Flow lateral chain).
- `path_finder.py` — wraps `graph/queries.py`; finds candidate paths from
  the entry IP to the token and extracts them into scored `PathHop`s.
- `scorer.py` — grades each hop HIGH (CF-Ray + VPC match) / MEDIUM (one
  match) / LOW (temporal only); a path is only as strong as its weakest hop.
- `mitre_tagger.py` — maps hops to ATT&CK techniques (T1190, T1021, T1552,
  T1083), validating IDs with mitreattack-python when its STIX bundle is
  present and falling back to hardcoded metadata otherwise.

**CF-Ray is the primary correlation key**; when no CF-Ray can be tied to
the trigger pod, the engine **falls back to temporal proximity** scoring
(and never crashes — it returns an empty, low-confidence `AttackObject`
when no path can be reconstructed).

Run the end-to-end demo (no live GCP needed):

```bash
python backtrace/demo_backtrace.py
```

It runs the Phase 2 collector simulation, lays down one coherent attack
scenario (external IP → pod → honeytoken), backtraces it, and prints the
full `AttackObject` JSON plus a human-readable attack summary with per-hop
confidence and MITRE techniques.

## Kill-Switch Orchestrator

`killswitch/` takes a Phase 4 `AttackObject` and fires containment actions
**in parallel** across a **pluggable set of providers** — revoke the
compromised identity's GCP IAM roles, block the attacker IP at Cloudflare, and
terminate its Zitadel sessions — **verifying** each action and writing a full
JSON audit trail for every attempt.

- `orchestrator.py` — coordinator; `execute(attack, mode)` and
  `approve(pending_id)` load the enabled providers from `config.yaml`, fire
  them via a `ThreadPoolExecutor`, verify each, and write the audit log.
- `config.yaml` — the provider registry + `verify_actions` / `rollback_on_partial`
  toggles. Enabling a control plane is one line here (U2).
- `providers/base.py` — the `Provider` interface: `available()`, `execute()`,
  `verify()`, `rollback()`.
- `providers/gcp.py` / `cloudflare.py` / `zitadel.py` — the three built-in
  providers. `providers/aws.py` / `azure.py` — disabled stubs (U10).

**Provider abstraction (U2):** providers are discovered dynamically from
`config.yaml` via `importlib` — drop in a `Provider` subclass and add a YAML
line to wire up AWS, Okta, etc., with no orchestrator edit.

**Action verification (U3):** after each action fires, the orchestrator
re-fetches the control plane to confirm it took effect (IAM member absent,
firewall rule present, sessions gone). A fired-but-unverified action downgrades
the run to `partial`.

**Compensating rollback (U2) — OFF by default:** when `rollback_on_partial: true`
and a run is `partial`, the orchestrator undoes the actions that *did* succeed.
This is **opt-in** because rolling back a successful containment action can
re-expose the attacker (e.g. un-blocking their IP because the Zitadel call
failed) — AC-2035 keeps containment **sticky** and leaves rollback to an
explicit analyst decision. (Zitadel session-kill is irreversible; its rollback
is a documented no-op.)

**Auto vs manual mode:** `mode="auto"` fires immediately; `mode="manual"`
stashes the attack and returns a `pending_id` for an analyst to `approve()`
(recorded as `triggered_by: analyst`).

**Status:** `executed` (all actions fully ok), `partial` (some), or `failed`
(none) — one failing provider never sinks the others. Every provider degrades
gracefully and **loudly** (a clear `ERROR` with the remedy) when its
credentials are missing — the expected result in local dev — returning an
`ActionResult` instead of crashing. Audit logs are saved to
`killswitch/audit/{token_id}_{timestamp}.json`.

Run the end-to-end demo (no live GCP/Cloudflare/Zitadel needed):

```bash
python killswitch/demo_killswitch.py
```

It obtains an `AttackObject` (reusing the Phase 4 engine), fires the
kill-switch in auto mode, prints the `KillSwitchResult` JSON + an audit
summary, verifies the audit file was written, and demonstrates the
manual → approve flow.

## Custom eBPF Detector

`detector/` is a kernel-space honeytoken watcher that replaces Falco. A
custom eBPF C program hooks the Linux Security Module layer at the GKE node
level; when any process touches a deployed honeytoken file, it emits a fully
attributed event (PID/UID/comm/inode/pod identity/timestamp) to userspace,
which a Python agent ships to Pub/Sub as a Phase 2 `TriggerEvent`.

- `ebpf/honeytoken_watch.c` — the eBPF C program (4 hooks, ring-buffer output).
- `ebpf/Makefile` — clang + libbpf CO-RE build (`make vmlinux`, `make all`).
- `ebpf/loader.py` — loads the `.o` via libbpf (ctypes), attaches the hooks,
  and populates/updates the `watched_inodes` map at runtime.
- `telemetry_agent/agent.py` — reads ring-buffer events, resolves
  `token_id_hash` → `token_id` against the registry, builds `TriggerEvent`s,
  and publishes to Pub/Sub.
- `telemetry_agent/struct_defs.py` — byte-exact ctypes mirror of the C
  structs (self-checked layout assertions) + the FNV-1a hash.

**The four kernel hooks:**

| Hook | Catches |
|------|---------|
| `lsm/file_open` | a process `open()`-ing a watched honeytoken inode |
| `lsm/file_permission` | `read()` / `mmap()` access that bypasses a fresh `file_open` |
| `kprobe/sys_execve` | process-execution lineage in honeytoken pods |
| `tp/sched/sched_process_exit` | process exit (a process exiting right after touching a token is a strong signal) |

**LSM hooks observe only — they always return 0 (allow) and never block
access.** The detector attributes access; it doesn't prevent it.

**Kernel requirements:** Linux, root, and kernel **5.7+** with BPF LSM
enabled (`lsm=...,bpf`). The C program requires clang + libbpf + bpftool to
build. Off-Linux (or without those), everything falls back to simulation.

Simulation mode (works on Windows, no root/kernel needed):

```bash
python detector/demo_detector.py --simulate
```

This fabricates a honeytoken event and runs it through the real decode →
`TriggerEvent` → Pub/Sub pipeline, printing the result.

Real mode (Linux + root + kernel 5.7+):

```bash
sudo python detector/demo_detector.py --real
```

This compiles the eBPF object, loads it, watches a test file's inode,
touches the file to trigger detection, prints the captured event, and unloads.

**Deployer integration:** `deployer/injector.register_inodes_with_detector()`
stats each file-based honeytoken for its inode and adds it to the eBPF
`watched_inodes` map — closing the loop *deploy → inject → register inode →
eBPF watches → trigger → Pub/Sub → collector → backtrace → kill-switch*.

## FastAPI Backend

`api/` is the control plane that ties every phase together — the Phase 8
dashboard talks exclusively to it. Interactive API docs are auto-generated
at **http://localhost:8000/docs**.

**Route groups:**

- `/api/graph` — the Neo4j graph as Cytoscape.js JSON: `GET /full`,
  `GET /attack/{token_id}` (highlighted attack path, 404 if none),
  `GET /stats` (node/edge/type counts), `POST /clear`.
- `/api/alerts` — `GET /` (kill-switch audit history, `?limit=N`),
  `GET /{token_id}`, and `POST /trigger` — the **full pipeline end-to-end**.
- `/api/tokens` — `GET /` (registry, `?status=`), `GET /{token_id}`,
  `POST /rotate`. `token_value` is never exposed.
- `/api/killswitch` — `GET /pending`, `POST /approve/{pending_id}`,
  `POST /execute` (auto-fire against a supplied AttackObject).
- `/ws` — WebSocket alert stream (see below).
- `GET /health` — liveness probe, `{"status": "ok"}`.

**The trigger pipeline** — `POST /api/alerts/trigger` accepts a
`TriggerEvent`, runs `backtrace.engine.run_backtrace()` to reconstruct the
attack, fires (or stages) the kill-switch via
`orchestrator.execute(mode=KILLSWITCH_MODE)`, broadcasts a live alert, and
returns the `AttackObject` + `KillSwitchResult`. This is the whole system in
one call: detect → backtrace → contain.

**WebSocket alert streaming** — connect to `/ws`; on connect you get
`{"type": "connected", ...}`, then keepalive pings every 30s and live alerts
as they fire. Alert schema:

```json
{
  "type": "honeytoken_trigger | killswitch_fired | token_rotated | system_info",
  "token_id": "…or null",
  "timestamp": "ISO-8601",
  "data": { }
}
```

**Neo4j → Cytoscape.js** — `api/serializers.py` reshapes
`graph.queries.get_full_graph()` into typed `{nodes, edges}` Cytoscape
elements; `attack_object_to_cytoscape()` renders a single reconstructed path
with every element flagged `attack_path: true` for highlighting.

**`KILLSWITCH_MODE`** (`.env`) controls how `POST /api/alerts/trigger` fires
the kill-switch: `manual` (default, safer — stages for analyst approval via
`/api/killswitch/approve/{id}`) or `auto` (fires immediately). `CORS_ORIGINS`
(default `*`) sets allowed dashboard origins.

The API comes up with `docker compose up -d`; if Neo4j is unreachable at
startup it logs a warning and continues (routes return 500 until it's back).

## React Dashboard

`dashboard/` is the operator UI — a single-page React + TypeScript + Vite
app with a bespoke **Hyprland-meets-cyber-deception-ops** look (deep-space
navy base, cyan/purple/green/red/amber accents, a CRT scanline overlay, a
subtle 40px grid background, angular tech-corner brackets on every card, and
glow borders + pulsing status dots). No component library — every component
is custom; graph rendering is Cytoscape.js with the dagre layout.

**Five views** (persistent sidebar, collapsible to icons):

1. **Attack Graph** — the full Neo4j graph in Cytoscape.js (dagre layout,
   typed node shapes/colors); load an attack path by token_id to highlight
   it; click a node for a slide-in detail panel.
2. **Alert Feed** — terminal-style live stream over WebSocket; new alerts
   slide in from the top; filter by type; expand any alert to raw JSON.
3. **Token Board** — a card per honeytoken with a status-glow border
   (active=green pulse, triggered=red, rotated=amber); Rotate-All + filters.
4. **Attack Timeline** — a horizontal timeline of a token's reconstructed
   interactions with a hover tooltip and an event table.
5. **Kill-Switch Panel** — pending approvals (Approve/Dismiss) on the left,
   the kill-switch audit log with per-action ✓/✗ results on the right.

Run it:

```bash
cd dashboard
npm install
npm run dev          # http://localhost:5173
```

**Environment** (`dashboard/.env`, copy from `.env.example`):

- `VITE_API_URL` (default `http://localhost:8000`) — HTTP API base.
- `VITE_WS_URL` (default `ws://localhost:8000/ws`) — the alert stream URL.
  It **must** use `ws://` explicitly and is **never proxied through Vite**
  (only `/api` is proxied) — this avoids ws:// vs http:// protocol confusion.

The WebSocket **auto-reconnects with exponential backoff** (1s → 2s → … capped
at 30s) and drops a "WebSocket reconnected" system alert into the feed when it
recovers. **`token_value` is never rendered anywhere** — the UI always shows
`••••••••`.

## Production Upgrades — Critical Tier

Beyond the 8 build phases, AC-2035 is hardening into a deployable system. The
**Critical tier** (U0–U3, U12) is complete:

- **U0 — External alerting** (`notifier/`): honeytoken triggers and kill-switch
  fires fan out to Slack / Discord / PagerDuty with a per-channel **circuit
  breaker**. If a webhook fails (404/403/timeout), the notifier logs `CRITICAL`
  and writes a local `.alert` file the dashboard surfaces (`GET /api/notifications`)
  — a dead webhook can't silence alerts. It is best-effort and **never blocks or
  crashes** the kill-switch. Set `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` /
  `PAGERDUTY_ROUTING_KEY` in `.env` (all optional).
- **U1 — No silent simulation**: simulation is opt-in only. The collector
  listener runs on Pub/Sub with a real `GCP_PROJECT_ID`, or refuses to start
  (loud `CRITICAL`) unless you pass `--simulate` (or set `AC2035_SIMULATE=1`).
  It never silently fabricates telemetry.
- **U2 / U3 — Pluggable providers, verification, opt-in rollback**: see the
  Kill-Switch Orchestrator section above.
- **U12 — Immutable audit + isolated CI state** (`infra/`, **artifact-only**):
  a GCS Object-Lock audit bucket and per-environment (`prod`/`dev`/`ci`) remote
  state backends. Written to spec but **not deployed** from the repo — see
  `infra/README.md` for the live-verification checklist.

Run the logic tests (no cloud or kernel needed):

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Production Upgrades — Important Tier

The **Important tier** (U4–U7, U11, U13) hardens detection + attribution and adds
research / CI scaffolding.

- **U4 — eBPF tamper detection** (`detector/`): a watchdog thread periodically
  verifies the eBPF programs are still attached and their maps still pinned under
  `/sys/fs/bpf/ac2035/`; if a hook disappears it publishes a `CRITICAL` Pub/Sub
  alert (+ notifier) and reloads the program. *Locally verified:* the watchdog
  logic (mocked loader). *Artifact-only:* the kernel attach / pin / reload
  (Linux + root).
- **U5 — Confidence calibration** (`backtrace/calibrator.py`): runs labeled
  scenarios through the engine and reports **precision + recall per confidence
  tier** (paper-ready markdown / JSON), so HIGH/MEDIUM/LOW actually mean
  something. *Locally verified* with a mocked engine.
- **U6 — Neo4j tuning + pruning** (`docker-compose.yml`, `graph/pruner.py`):
  bounded heap (128m/512m) + 256m page cache; a pruner deletes relationships and
  the nodes they orphan older than 7 days and raises a `CRITICAL` alert past
  10,000 nodes. *Locally verified* (pruner logic + compose config).
- **U7 — Correlation hardening** (`backtrace/correlator.py`): a priority
  strategy chain — CF-Ray → VPC-Flow source IP → temporal clustering + eBPF
  process lineage → **unattributed**. An unattributed trigger is a first-class
  state now, not a forced low-confidence path. *Locally verified* with mocked
  timelines. (Feeding real eBPF process events into the timeline is a follow-up.)
- **U11 — Immutable audit sink** (`research/immutable_sink.py`): streams raw
  telemetry first, processed results second, to the U12 GCS Object-Lock bucket —
  before backtrace runs. Degrades to a local mirror without GCS. *Locally
  verified* (sink logic + ordering, mocked client). *Artifact-only:* live
  Object-Lock writes.
- **U13 — Two-track CI** (`.github/workflows/`): **Track A** (`ci-unit.yml`,
  real) runs `pytest tests/` as the merge gate; **Track B** (`ci-integration.yml`
  + `infra/cloudbuild.yaml`, artifact-only) spins up ephemeral GKE with real
  eBPF, runs the scenarios, and gates on backtrace accuracy > 90%. See
  `.github/README.md`.

The full suite (26 tests) runs on any box — no cloud, kernel, or Docker needed:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Build Phases

- [x] **Phase 0** — Environment setup (repo structure, Docker Compose, Terraform foundation)
- [x] **Phase 1** — Honeytoken deployer (generation, injection, rotation)
- [x] **Phase 2** — Telemetry Collector (Pub/Sub listener, GCP logs, VPC Flow, Cloudflare, normalizer)
- [x] **Phase 3** — Neo4j Graph Ingestor (timeline → graph nodes and edges)
- [x] **Phase 4** — Forensic Backtrace Engine (CF-Ray + VPC Flow correlation, Cypher path reconstruction, confidence scoring, MITRE tagging)
- [x] **Phase 5** — Kill-Switch Orchestrator (GCP IAM revocation, Cloudflare IP block, Zitadel session termination)
- [x] **Phase 6** — Custom eBPF Detector (replaces Falco, kernel-space honeytoken watcher)
- [x] **Phase 7** — FastAPI Backend (REST + WebSocket + Neo4j→Cytoscape serializer)
- [x] **Phase 8** — React Dashboard (Cytoscape.js graph, live alerts, timeline replay, kill-switch controls)

## Running the Complete System

The full AC-2035 stack, end to end:

```bash
# 1. Backend stack — Neo4j, Zitadel (+ Postgres), and the FastAPI API
docker compose up -d
#    API at http://localhost:8000  (docs at /docs), Neo4j at http://localhost:7474

# 2. Dashboard
cd dashboard && npm install && npm run dev
#    UI at http://localhost:5173

# 3. Generate a telemetry timeline (no GCP needed)
python collector/simulate_trigger.py

# 4. Fire the full pipeline for that token — backtrace + kill-switch —
#    which also broadcasts a live alert to the dashboard:
curl -X POST http://localhost:8000/api/alerts/trigger \
  -H "Content-Type: application/json" \
  -d '{"token_id":"<token from step 3>","token_type":"api_token",
       "trigger_time":"2026-07-12T00:00:00+00:00","pod_name":"checkout-api",
       "pod_namespace":"prod","process_name":"python3","pid":4242,"source":"ebpf"}'

# 5. Open the dashboard and watch it land
open http://localhost:5173
```

Everything runs locally with graceful degradation — no live GCP, Cloudflare,
or Zitadel credentials are required for the local demo flow. External alerting
(Slack/Discord/PagerDuty) is optional; without it, alerts fall back to local
`.alert` files surfaced at `GET /api/notifications`.
