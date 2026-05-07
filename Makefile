SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help run build test fmt tidy clean compose-up compose-down compose-logs compose-up-integration compose-down-integration compose-logs-integration sqlc db-status db-up db-down db-status-integration db-up-integration db-down-integration test-integration

help: ## Show available make targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-15s %s\n", $$1, $$2}'

run: ## Run the app with variables from .env
	@set -a; source .env; set +a; go run ./cmd

build: ## Build the app binary
	@go build -o bin/app ./cmd

test: ## Run all tests
	@go test -short ./...

fmt: ## Format Go files
	@go fmt ./...

tidy: ## Tidy Go modules
	@go mod tidy

clean: ## Remove local build artifacts
	@rm -rf bin
	@rm -f coverage.out

compose-up: ## Start app and integration postgres via docker compose
	@docker compose up -d postgres postgres_integration_test

compose-down: ## Stop docker compose services
	@docker compose down

compose-logs: ## Tail postgres logs
	@docker compose logs -f postgres

sqlc: ## Generate SQLC code
	@sqlc generate

db-status: ## Show goose migration status
	@set -a; source .env; set +a; goose -dir "$${GOOSE_MIGRATION_DIR}" status

db-up: ## Apply all goose migrations
	@set -a; source .env; set +a; goose -dir "$${GOOSE_MIGRATION_DIR}" up

db-down: ## Roll back one goose migration
	@set -a; source .env; set +a; goose -dir "$${GOOSE_MIGRATION_DIR}" down

test-integration: ## Run integration tests against integration DB
	go test -p 1 ./internal/integration/...

debug-integration: ## Runs integration tests via dlv debugger.
	dlv test ./internal/integration -- -test.v
