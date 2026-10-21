# scanner-manager API — How to use it

`scanner-manager` is a REST control plane for running [Nuclei](https://github.com/projectdiscovery/nuclei)
vulnerability scans. It stores what to scan (scope, targets, profiles, tasks),
queues runs, executes Nuclei in a worker, and exposes the results.

- **Base URL:** `http://127.0.0.1:8080/api/v1`
- **Swagger UI:** `http://127.0.0.1:8080/swagger/index.html`
- **OpenAPI JSON:** `http://127.0.0.1:8080/swagger/doc.json`
- **Health:** `GET /healthz` → `{"status":"ok"}` (database check)
- **Auth:** none — keep the API bound to localhost or behind your own gateway.

---

## 1. Start the service

```bash
cp .env.example .env          # edit SM_DB_DSN / SM_NUCLEI_BIN as needed
make db-up                    # MariaDB
make lab-up                   # optional: Juice Shop target on 127.0.0.1:3000
make run                      # API + worker on 127.0.0.1:8080
```

`nuclei` must be in `PATH` (or set `SM_NUCLEI_BIN`). On startup the service
probes the binary, runs migrations, seeds built-in profiles and starts the worker.

Open the Swagger UI to explore and call every endpoint interactively.

---

## 2. Conventions

- Requests and responses are JSON (`Content-Type: application/json`).
- Unknown request fields are rejected.
- Every error uses the same envelope:

  ```json
  { "error": "validation failed: name is required" }
  ```

- Status codes:

  | Code | Meaning |
  |------|---------|
  | 200 | OK |
  | 201 | Created |
  | 202 | Accepted (a run was queued / stop requested) |
  | 204 | Deleted |
  | 400 | Validation error (bad JSON, missing/unknown field, bad id) |
  | 404 | Not found |
  | 409 | Conflict (duplicate, in use, read-only, already active) |
  | 422 | Target is outside the allowed scope |
  | 500 | Internal error |

---

## 3. Resources

### Scope — the allowlist

Targets are only accepted if **every host** is inside the scope. An empty scope
rejects everything (fail-closed).

`POST /api/v1/scope`

```json
{ "kind": "domain", "value": "example.com", "comment": "corp" }
```

- `kind`: `domain` (e.g. `example.com`, subdomains included), `cidr`
  (e.g. `10.0.0.0/24`), or `ip` (e.g. `10.1.2.3`).
- Values are normalized: domains are lowercased, CIDRs/IPs are canonicalized.
- Overly broad CIDRs are rejected (IPv4 `/8` or wider, IPv6 `/16` or wider).

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/scope` | list entries |
| POST | `/api/v1/scope` | create entry |
| DELETE | `/api/v1/scope/:id` | remove entry |

### Targets — what to scan

`POST /api/v1/targets`

```json
{
  "name": "staging-web",
  "hosts": ["https://app.example.com", "api.example.com:8443"],
  "exclude": ["10.0.0.0/8"],
  "tags": ["staging"],
  "probe_first": true
}
```

- `name` is unique; `hosts` requires at least one entry.
- Every host is checked against the scope → `422` if any host is out of scope.
- `exclude` lists hosts/IPs/CIDRs to skip during a run.

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/targets` | list |
| POST | `/api/v1/targets` | create (scope-checked) |
| GET | `/api/v1/targets/:id` | fetch |
| PUT | `/api/v1/targets/:id` | full replace (scope-checked) |
| DELETE | `/api/v1/targets/:id` | `409` if a task uses it |

### Profiles — how to scan

A profile selects templates (tags, severity, protocols, template IDs) and tunes
Nuclei (rate limit, concurrency, timeout, retries). Zero-valued numbers get
sensible defaults. Built-in profiles are seeded at startup and are read-only.

`POST /api/v1/profiles`

```json
{
  "name": "external-only",
  "custom_set": "smoke",
  "severity": ["medium", "high", "critical"],
  "exclude_tags": ["dos", "intrusive"],
  "rate_limit": 50,
  "concurrency": 25,
  "timeout_sec": 10
}
```

- `custom_set` names a folder under the custom templates directory (`./custom-templates`, e.g. `smoke`)
  → `./custom-templates/smoke`). When set, **only** that folder is scanned.

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/profiles` | list (includes built-ins) |
| POST | `/api/v1/profiles` | create custom profile |
| GET | `/api/v1/profiles/:id` | fetch |
| PUT | `/api/v1/profiles/:id` | full replace; `409` for built-ins |
| DELETE | `/api/v1/profiles/:id` | `409` for built-ins or if in use |

### Tasks — bind a target to a profile

`POST /api/v1/tasks`

```json
{
  "name": "nightly-staging",
  "target_id": 1,
  "profile_id": 2,
  "schedule_type": "cron",
  "cron_expr": "0 2 * * *",
  "timezone": "UTC",
  "min_severity": "medium",
  "retention_keep_last": 20
}
```

- `target_id` and `profile_id` must already exist.
- `schedule_type`: `once` (default) or `cron`; `cron_expr` is required for cron.
- `min_severity` defaults to `medium`.

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/tasks` | list |
| POST | `/api/v1/tasks` | create |
| GET | `/api/v1/tasks/:id` | fetch |
| PUT | `/api/v1/tasks/:id` | full replace |
| DELETE | `/api/v1/tasks/:id` | `409` if it has an active run |

### Runs — execute and inspect

Trigger a run:

```bash
POST /api/v1/tasks/1/run          # 202 Accepted, returns the queued Run
```

A task may have only one active (queued/running) run at a time → `409`.
The worker picks it up, re-checks the scope, builds the Nuclei command, runs it,
and stores counters and raw output.

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/v1/tasks/:id/run` | queue a run (`202`) |
| GET | `/api/v1/runs` | list; filters `task_id`, `status`, `limit` (≤200, default 50) |
| GET | `/api/v1/runs/:id` | fetch run (status, timings, counters) |
| POST | `/api/v1/runs/:id/stop` | cancel queued run (`200`) or stop running run (`202`) |
| GET | `/api/v1/runs/:id/log` | tail the supervisor log; `offset`, `limit` query params |
| GET | `/api/v1/runs/:id/output` | download raw Nuclei JSONL (`application/x-ndjson`) |

Run statuses: `queued`, `running`, `processing`, `completed`, `failed`,
`timed_out`, `stopped`, `cancelled`.

---

## 4. End-to-end example

```bash
B=http://127.0.0.1:8080

# allow the local lab host
curl -s -X POST $B/api/v1/scope -H 'Content-Type: application/json' \
  -d '{"kind":"ip","value":"127.0.0.1"}'

# target the lab
curl -s -X POST $B/api/v1/targets -H 'Content-Type: application/json' \
  -d '{"name":"demo","hosts":["http://127.0.0.1:3000"]}'

# profile that runs only the bundled smoke template
curl -s -X POST $B/api/v1/profiles -H 'Content-Type: application/json' \
  -d '{"name":"demo","custom_set":"smoke","rate_limit":20,"max_duration_min":5}'

# task
curl -s -X POST $B/api/v1/tasks -H 'Content-Type: application/json' \
  -d '{"name":"demo","target_id":1,"profile_id":1,"min_severity":"info"}'

# run it
curl -s -X POST $B/api/v1/tasks/1/run          # -> {"id":1,...,"status":"queued"}

# wait, then inspect
curl -s $B/api/v1/runs/1                        # status, results_total, findings_*
curl -s $B/api/v1/runs/1/output | jq .         # the raw finding
curl -s "$B/api/v1/runs/1/log" | jq -r .data   # supervisor log
```

The bundled `make smoke-run` runs exactly this flow against the Juice Shop lab
and asserts the finding, counters and output.

---

## 5. Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `SM_HTTP_ADDR` | `127.0.0.1:8080` | API listen address |
| `SM_GIN_MODE` | `release` | Gin mode |
| `SM_DB_DSN` | *(required)* | MariaDB DSN |
| `SM_DATA_DIR` | `./data` | Run logs/output directory |
| `SM_NUCLEI_BIN` | `nuclei` | Path/name of the nuclei binary |
| `SM_NUCLEI_TEMPLATES_DIR` | (empty) | Directory of the official Nuclei templates |
| `SM_MAX_CONCURRENT_RUNS` | `2` | Worker pool size (1–16) |
| `SM_WORKER_POLL` | `2s` | Worker poll interval (≥ 500ms) |
| `SM_SWAGGER_HOST` | `localhost` | Swagger "Try it out" host (default `localhost:<port>`) |
| `SM_SWAGGER_BASE_PATH` | `/api/v1` | Swagger "Try it out" base path |
