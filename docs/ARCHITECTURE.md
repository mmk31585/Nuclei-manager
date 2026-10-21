# scanner-manager — Architecture

This document explains how the service is put together and how a request flows
through it, from HTTP handler to a running Nuclei process.

## 1. What it is

`scanner-manager` is the control plane for Nuclei scans. It owns the database of
scan configuration and a worker that executes Nuclei. It does **not** embed
Nuclei — it shells out to the `nuclei` binary and parses its JSONL output.

```
                 +---------------------------------------------------+
   HTTP  ------> |  Gin router  ->  handlers  ->  repositories  -> DB |
                 +---------------------------------------------------+
                                     |  POST /tasks/:id/run
                                     v
                             +----------------+
                             |  runs.Service  |  (snapshot + queue)
                             +----------------+
                                     |  queued Run row
                                     v
                             +----------------+
                             |    Worker      |  (claim loop)
                             +----------------+
                                     |  exec
                                     v
                             +----------------+
                             |  nuclei binary |  --jsonl  -> output.jsonl
                             +----------------+
                                     |
                                     v
                             Run counters + raw output stored in DB
```

## 2. Layers

| Package | Responsibility |
|---------|----------------|
| `internal/domain` | Entities, validation, repository interfaces, run model, severity helpers |
| `internal/store` | GORM/MariaDB repositories, migrations, built-in profile seeding, error mapping |
| `internal/scope` | Allowlist matcher (domain / CIDR / IP) |
| `internal/scanner/nuclei` | Safe argument builder, JSONL parser, binary probe, process runner |
| `internal/runs` | Run creation: validate, snapshot config, queue, wake worker |
| `internal/worker` | Claim loop, prepare command, execute, progress, finalize |
| `internal/api` | Gin handlers, request/response schemas, error envelope, Swagger |
| `internal/config` | Environment configuration |

Dependencies point inward: `api -> runs/worker -> domain`, `store -> domain`,
`worker -> nuclei/scope/domain`.

## 3. Data model

| Table | Key fields | Notes |
|-------|-----------|-------|
| `scope_entries` | `kind`, `value` (unique) | allowlist: domain / cidr / ip |
| `targets` | `name` (unique), `hosts`, `exclude`, `tags` | hosts are scope-checked |
| `profiles` | `name` (unique), `tags`, `severity`, `custom_set`, tuning ints, `builtin` | built-ins are read-only |
| `tasks` | `name` (unique), `target_id`, `profile_id`, schedule, `min_severity` | binds target+profile |
| `runs` | `task_id`, `status`, `command_line`, counters, `config_snapshot` | one active run per task |
| `findings`, `run_findings` | — | defined for the findings phase (unused yet) |
| `custom_templates`, `suppressions` | — | defined for later phases |

`StringList` fields (e.g. `hosts`, `tags`) are JSON arrays persisted in `TEXT`
columns. Every list is trimmed, de-duplicated and emptied on write.

## 4. Request lifecycle (CRUD)

1. Gin binds JSON with `DisallowUnknownFields` and a 1 MiB body limit.
2. The handler validates via the domain method (`Target.Validate`, etc.).
3. Targets additionally pass `scope.Service.CheckAll` — any host outside the
   allowlist yields `422`.
4. The repository translates driver errors (`1062` duplicate → `409`,
   not-found → `404`) and persists.
5. The handler writes the standard JSON envelope.

## 5. Scope enforcement

`scope.Service.CheckAll` loads the current allowlist and builds a `Matcher`:

- `domain` entries match the host and any `*.domain` subdomain (by name only —
  no DNS resolution in this phase);
- `cidr`/`ip` entries are stored as `netip.Prefix` and matched by containment.

An **empty** allowlist rejects every target (fail-closed). The scope is re-checked
again at run execution time, because the allowlist may have changed since the run
was queued.

## 6. Run pipeline

1. `POST /api/v1/tasks/:id/run` → `runs.Service.Create`:
   - loads task, target, profile; validates severities; re-checks scope;
   - encodes a `ConfigSnapshot` (task+target+profile) so the run is frozen;
   - inserts a `queued` Run inside a transaction that locks the task row, so two
     concurrent requests cannot both queue an active run;
   - signals the worker via a wake channel.
2. `worker.Worker.loop` polls the DB (and wakes on the channel) and claims runs
   with `SELECT ... FOR UPDATE SKIP LOCKED`, up to `SM_MAX_CONCURRENT_RUNS`.
3. `worker.execute`:
   - re-checks scope, writes `targets.txt`, resolves `custom_set`;
   - computes effective severities (profile filter ∩ task floor);
   - builds the Nuclei argument list (`nuclei.BuildArgs`);
   - records the command line, versions and target count;
   - runs Nuclei under a per-run context with a `max_duration_min` timeout;
   - streams progress counters to the DB every 5s;
   - finalizes with a status and exit code.

Run statuses: `queued → running → completed | failed | timed_out | stopped | cancelled`.

## 7. Nuclei safety

- `nuclei.BuildArgs` whitelists every value with regexes and only emits known
  flags. A blocklist of dangerous flags (`-code`, `-headless`, `-dast`, `-fuzz`,
  `-lfa`, `-allow-local-file-access`, `-env-vars`, `-update*`, `-reset`,
  `-sandbox`) is enforced as defense in depth.
- `nuclei.Runner` starts Nuclei in its **own process group**. Stop = `SIGTERM`
  to the group, then a grace period, then `SIGKILL` to the group, so child
  processes are reaped.
- The child environment drops all `SM_*` variables (so the DB DSN never leaks to
  the scanner).
- Stdout lines are capped at 16 MiB; oversized lines are dropped and counted as
  parse errors.
- The binary is probed at startup: `nuclei -version` and `-h` are checked for all
  required flags.

## 8. Configuration

Loaded once from the environment in `internal/config` (see
[API.md](API.md#5-configuration) for the full table). `SM_DB_DSN` is required;
all other values have defaults.

## 9. Error mapping

`store.mapErr` converts driver errors to domain errors, and `api.writeError`
maps them to HTTP status codes:

| Domain error | HTTP |
|--------------|------|
| `ErrValidation` | 400 |
| `scope.ErrOutOfScope` | 422 |
| `ErrNotFound` | 404 |
| `ErrConflict` | 409 |
| anything else | 500 |

## 10. Project layout

```
cmd/scanner-manager/     main entrypoint (config, migrations, worker, HTTP server)
internal/
  api/                   Gin handlers, schemas, error envelope, Swagger UI
  config/                environment configuration
  domain/                entities, validation, repository interfaces
  runs/                  run creation service
  scanner/nuclei/        arg builder, parser, probe, process runner
  scope/                 allowlist matcher
  store/                 GORM repositories, migrations, seeding
  worker/                claim loop + execution
docs/                    generated OpenAPI spec + guides
custom-templates/        custom Nuclei template folders (e.g. smoke/)
scripts/                 smoke.sh, smoke_run.sh
```

## 11. Known limits (current phase)

- Single service instance (no leader election).
- After a hard crash a scanner process may keep running until its container stops
  (no PID tracking).
- No log rotation / run retention yet.
- `custom_set` profiles run only that template folder (official templates are not
  included).
- `probe_first` is stored but not yet acted on.
- No findings dedup/diff/status logic and no cron scheduler yet.
