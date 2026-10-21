# scanner-manager

A Nuclei vulnerability scan management service.

## Phase 1 (done)
Domain models (scope entries, targets, profiles, tasks, runs, findings, custom templates, suppressions), MariaDB store via GORM, scope allowlist matcher, Gin REST API for scope/targets/profiles/tasks CRUD.

## Phase 2 (done)
- Nuclei command builder (`internal/scanner/nuclei/args.go`) — builds args slices, blocks forbidden flags (`-code`, `-headless`, `-dast`, `-fuzz`, `-lfa`, `-env-vars`, `-update*`, `-reset`, `-sandbox`).
- JSONL result parser (`internal/scanner/nuclei/result.go`) — extracts events, counts severities.
- Binary probe (`internal/scanner/nuclei/probe.go`) — verifies nuclei binary has all required flags, parses version.
- Process runner (`internal/scanner/nuclei/runner.go`) — `exec.CommandContext` with its own process group; stop = SIGTERM to group → grace → SIGKILL; 16 MiB stdout line cap.
- Run queue + worker pool (`internal/runs/service.go`, `internal/worker/worker.go`) — `SELECT FOR UPDATE SKIP LOCKED` claiming, one active run per task, config snapshot at queue time, scope re-check before execute, graceful shutdown.
- Run API (`internal/api/run_handler.go`) — start, list, get, stop, log, raw output.

## Requirements

- Go 1.27+
- MariaDB 11 (docker compose provided)
- `nuclei` binary in PATH (or set `SM_NUCLEI_BIN`)
- `jq` and `curl` for smoke tests

## Local setup

```bash
cp .env.example .env
# edit .env if needed (SM_DB_DSN, SM_HTTP_ADDR, SM_GIN_MODE, SM_NUCLEI_BIN, SM_DATA_DIR, SM_NUCLEI_TEMPLATES_DIR)

make db-up   # start MariaDB via docker compose
make lab-up  # start Juice Shop at 127.0.0.1:3000
make run     # start the API (binds to 127.0.0.1:8080 by default)
```

In another terminal:

```bash
make smoke      # Phase 1 CRUD smoke test
make smoke-run  # Phase 2 run smoke test (needs nuclei + lab)
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SM_HTTP_ADDR` | `127.0.0.1:8080` | API listen address |
| `SM_GIN_MODE` | `release` | Gin mode (`debug`, `release`, `test`) |
| `SM_DB_DSN` | **required** | MariaDB DSN |
| `SM_DATA_DIR` | `./data` | Directory for run logs/output |
| `SM_NUCLEI_BIN` | `nuclei` | Path/name of nuclei binary |
| | `SM_NUCLEI_TEMPLATES_DIR` | (empty) | Directory of the official Nuclei templates (e.g. `/home/space/nuclei-templates`) |
| `SM_MAX_CONCURRENT_RUNS` | `2` | Worker pool size (1–16) |
| `SM_WORKER_POLL` | `2s` | Worker poll interval (≥ 500ms) |
| `SM_SWAGGER_HOST` | `localhost` | Host shown in Swagger UI for "Try it out" requests. Defaults to `localhost:<SM_HTTP_ADDR port>`; set e.g. `scan.example.com:8443` for a deployment. |
| `SM_SWAGGER_BASE_PATH` | `/api/v1` | Base path used by Swagger UI requests. |

## Endpoints

- `GET /healthz` — database health check
- Scope: `GET /api/v1/scope`, `POST /api/v1/scope`, `DELETE /api/v1/scope/:id`
- Targets: `GET /api/v1/targets`, `POST /api/v1/targets`, `GET /api/v1/targets/:id`, `PUT /api/v1/targets/:id`, `DELETE /api/v1/targets/:id`
- Profiles: `GET /api/v1/profiles`, `POST /api/v1/profiles`, `GET /api/v1/profiles/:id`, `PUT /api/v1/profiles/:id`, `DELETE /api/v1/profiles/:id`
- Tasks: `GET /api/v1/tasks`, `POST /api/v1/tasks`, `GET /api/v1/tasks/:id`, `PUT /api/v1/tasks/:id`, `DELETE /api/v1/tasks/:id`
- Runs: `POST /api/v1/tasks/:id/run`, `GET /api/v1/runs`, `GET /api/v1/runs/:id`, `POST /api/v1/runs/:id/stop`, `GET /api/v1/runs/:id/log`, `GET /api/v1/runs/:id/output`

No auth; keep the API bound to localhost.

## API documentation (Swagger UI)

The OpenAPI spec is generated from the source annotations (`swag init`) and served
live by the API:

- Swagger UI: `http://127.0.0.1:8080/swagger/index.html`
- OpenAPI JSON: `http://127.0.0.1:8080/swagger/doc.json`
- OpenAPI YAML: `http://127.0.0.1:8080/swagger/doc.yaml`
- Static copies: `docs/swagger.json`, `docs/swagger.yaml`

The host used by the UI for **Try it out** requests is configurable. By default it
is `localhost` plus the `SM_HTTP_ADDR` port (e.g. `localhost:8080`); set
`SM_SWAGGER_HOST` to a full `host:port` to override it (e.g. `scan.example.com:8443`).

Regenerate the spec after changing annotations:

```bash
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g cmd/scanner-manager/main.go -o docs --parseInternal --parseDependency
```

## Makefile targets

`make check` (fmt, vet, test, build), `make test`, `make test-race`, `make vet`, `make fmt`, `make tidy`, `make build`, `make run`, `make db-up`, `make db-down`, `make lab-up`, `make lab-down`, `make smoke`, `make smoke-run`.

## Known limits (Phase 2)

- Single service instance only.
- After a hard crash, a scanner process may keep running until its container stops (no PID tracking).
- No log rotation or run retention yet.
- `custom_set` profiles run **only** that template folder (official templates are not included).
- `probe_first` target field is ignored.
- Raw output keeps request/response so files can be large.
- No findings dedup/diff/status logic yet (Phase 3).
- No scheduler/cron (Phase 3).