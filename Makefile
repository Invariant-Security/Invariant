# Makefile — Invariant
# Skeleton targets only; implementations land as the corresponding pieces
# (API, CLI, storage, migrations) are built.

.PHONY: install run-api run-cli test migrate-up

install: ## Install the project and its dependencies (editable, with dev extras).
	pip install -e ".[dev]"

run-api: ## Run the REST API with auto-reload.
	uvicorn invariant.api.main:app --reload

run-cli: ## Run the CLI (e.g. make run-cli ARGS="fetch cis").
	python -m invariant.cli.main $(ARGS)

test: ## Run the test suite.
	pytest

migrate-up: ## Apply pending PostgreSQL migrations.
	@echo "TODO: wire Alembic (chosen migration tool) once sql/schema is finalized"
