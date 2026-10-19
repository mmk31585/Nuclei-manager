-include .env
export

BIN := bin/scanner-manager

.PHONY: run build test test-race vet fmt fmt-check tidy check db-up db-down smoke lab-up lab-down smoke-run

run:
	go run ./cmd/scanner-manager

build:
	go build -o $(BIN) ./cmd/scanner-manager

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

tidy:
	go mod tidy

check: fmt-check vet test build

db-up:
	docker compose -f docker-compose.dev.yml up -d --wait

db-down:
	docker compose -f docker-compose.dev.yml down

smoke:
	./scripts/smoke.sh

test-race:
	go test -race ./internal/...

lab-up:
	docker compose -f docker-compose.lab.yml up -d

lab-down:
	docker compose -f docker-compose.lab.yml down

smoke-run:
	./scripts/smoke_run.sh
