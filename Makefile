-include .env
export

BIN := bin/scanner-manager

.PHONY: run build test vet fmt fmt-check tidy check db-up db-down smoke

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
