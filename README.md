# scanner-manager

Foundation phase of a Nuclei vulnerability scan management service. It
scaffolds the domain models (scope entries, targets, profiles, tasks plus
placeholders for runs, findings, custom templates and suppressions), a
MariaDB store via GORM, a scope allowlist matcher, and a Gin REST API for
scope / targets / profiles / tasks CRUD.

No Nuclei execution, workers, scheduler, queue, findings logic, auth, or
frontend exists yet.

## Requirements

- Go 1.27+
- MariaDB 11 (docker compose provided)
- `jq` and `curl` for the smoke test

## Local setup

```bash
cp .env.example .env
# edit .env if needed (SM_DB_DSN, SM_HTTP_ADDR, SM_GIN_MODE)

make db-up   # start MariaDB via docker compose
make run     # start the API (binds to 127.0.0.1:8080 by default)
```

In another terminal:

```bash
make smoke   # end-to-end smoke test against the running API
```

## Endpoints

- `GET /healthz` — database health check
- `GET    /api/v1/scope` — list scope entries
- `POST   /api/v1/scope` — create scope entry `{kind, value, comment}`
- `DELETE /api/v1/scope/:id`
- `GET    /api/v1/targets` — list targets
- `POST   /api/v1/targets` — create target (hosts are checked against scope)
- `GET    /api/v1/targets/:id`
- `PUT    /api/v1/targets/:id` — full replacement
- `DELETE /api/v1/targets/:id` — 409 if a task uses it
- `GET    /api/v1/profiles` — list profiles (built-in profiles seeded)
- `POST   /api/v1/profiles` — create profile
- `GET    /api/v1/profiles/:id`
- `PUT    /api/v1/profiles/:id` — 409 for built-in profiles
- `DELETE /api/v1/profiles/:id` — 409 for built-in profiles or if in use
- `GET    /api/v1/tasks` — list tasks
- `POST   /api/v1/tasks` — create task (target/profile must exist)
- `GET    /api/v1/tasks/:id`
- `PUT    /api/v1/tasks/:id` — full replacement
- `DELETE /api/v1/tasks/:id`

Configuration is via environment variables only (`SM_HTTP_ADDR`, `SM_GIN_MODE`,
`SM_DB_DSN`). The API has no auth; keep it bound to localhost.

## Makefile targets

`make check` (fmt, vet, test, build), `make test`, `make vet`,
`make fmt`, `make tidy`, `make build`, `make run`,
`make db-up`, `make db-down`, `make smoke`.
