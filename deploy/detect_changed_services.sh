#!/usr/bin/env bash
# Decides which of the 2 deploy stack services (api/web) actually need a
# rebuild for this deploy, so deploy.yml/deploy-dev.yml stop rebuilding
# both together on every push -- api and web are already independent
# containers (no `depends_on` between them in either compose file), the
# only coupling left was the deploy step itself always running
# `docker compose ... --build` on the whole file regardless of what
# changed. A frontend-only change no longer touches the backend build (and
# a broken backend build no longer blocks an unrelated frontend deploy).
#
# Usage: detect_changed_services.sh <old_sha> <new_sha>
# Prints a space-separated list of service names to stdout: "api", "web",
# "api web", or nothing at all (nothing relevant changed -- caller should
# skip the deploy step entirely, not treat empty as "build nothing" being
# wrong).
set -euo pipefail

old_sha="${1:-}"
new_sha="${2:?usage: detect_changed_services.sh <old_sha> <new_sha>}"

# No previous SHA (fresh checkout, this deploy directory's first ever
# run) -- can't diff against nothing, build both to be safe.
if [ -z "$old_sha" ]; then
    echo "api web"
    exit 0
fi

# Same SHA (workflow re-run, or a push that didn't move this branch) --
# nothing changed, nothing to rebuild.
if [ "$old_sha" = "$new_sha" ]; then
    exit 0
fi

changed="$(git diff --name-only "$old_sha" "$new_sha")"

services=()
# deploy/docker-compose.*.yml itself changing (network config, healthcheck,
# volumes, ...) can affect either service's runtime shape, not just its
# image -- rebuild both rather than guess which one the edit was about.
if echo "$changed" | grep -qE '^(src/|deploy/Dockerfile\.api$|pyproject\.toml$|deploy/docker-compose\.(dev|prod)\.yml$)'; then
    services+=(api)
fi
if echo "$changed" | grep -qE '^(frontend/|deploy/docker-compose\.(dev|prod)\.yml$)'; then
    services+=(web)
fi

echo "${services[*]-}"
