# Makefile — Invariant
# Skeleton targets only; implementations land as the corresponding pieces
# (CLI, sqlc, migrations) are built.

.PHONY: build run test sqlc-generate migrate-up

build: ## Build the invariant binary.
	go build ./...

run: ## Run the CLI (e.g. make run ARGS="fetch cis").
	go run ./cmd/invariant $(ARGS)

test: ## Run the test suite.
	go test ./...

sqlc-generate: ## Regenerate Go code from sql/queries and sql/schema.
	sqlc generate

migrate-up: ## Apply pending PostgreSQL migrations.
	@echo "TODO: wire the chosen Go migration tool here"
