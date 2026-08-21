#!/usr/bin/env bash
# quickdemo.sh -- one-button, fully offline live demo for an in-person
# event. Everything it needs must already be checked into the repo or
# built into local Docker images ahead of time (see the preflight checks
# below) -- no internet, no AI, nothing auto-installed live.
#
# What it does, in order:
#   1. Preflight: docker + invariant CLI + alembic + the two hardened
#      images must already be available. Aborts with a clear message
#      rather than trying to fix anything live.
#   2. Brings up postgres + adminer only from the *existing*
#      infra/docker-compose.yml (never touched by this script) -- the 6
#      dev/test containers stay stopped, they're not part of the demo.
#   3. Brings up the 5 quickdemo containers from the isolated
#      infra/docker-compose.quickdemo.yml, force-recreating the 4
#      "problem" containers so every run starts from a clean image.
#   4. Waits (short retry loop, no long sleep) until all 5 respond to
#      `docker exec ... true`.
#   5. Randomly applies 2-3 misconfigs to each of the 4 problem containers
#      (scripts/quickdemo/apply_misconfigs.py) and saves the manifest.
#   6. `alembic upgrade head` (idempotent, local DB only).
#   7. `invariant extract`/`invariant import_document` for the two demo CIS
#      documents (reads local PDFs under data/raw/, no network).
#   8. `invariant assess --target ...` for the 5 demo containers -- the
#      actual pipeline command, run live.
#   9. A final summary that reprints the manifest next to the assess
#      results, splitting every FAIL into "environmental" (a structural gap
#      documented in docs/architecture/checks.md, same on every container)
#      vs "today's story" (matches a misconfig actually applied this run).
#
# Repeatable: re-running resets the 4 problem containers and draws a fresh
# random misconfig set. No network required after the first image build.
#
# Usage: ./quickdemo.sh [--seed N]
#   --seed N   Seed apply_misconfigs.py's random draw for a reproducible
#              manifest (default: a fresh random draw every run).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SEED_ARGS=()
SEED_VALUE=""
if [[ "${1:-}" == "--seed" ]]; then
    if [[ -z "${2:-}" ]]; then
        echo "ERROR: --seed requires a value" >&2
        exit 1
    fi
    SEED_ARGS=(--seed "$2")
    SEED_VALUE="$2"
fi

DEMO_COMPOSE="infra/docker-compose.quickdemo.yml"
DEV_COMPOSE="infra/docker-compose.yml"

HARDENED_CONTAINER="invariant-demo-ubuntu-hardened"
PROBLEM_CONTAINERS=(invariant-demo-debian-1 invariant-demo-debian-2 invariant-demo-ubuntu-1 invariant-demo-ubuntu-2)
PROBLEM_SERVICES=(demo-debian-1 demo-debian-2 demo-ubuntu-1 demo-ubuntu-2)
ALL_DEMO_CONTAINERS=("$HARDENED_CONTAINER" "${PROBLEM_CONTAINERS[@]}")

MANIFEST_DIR="data/quickdemo"
MANIFEST_JSON="$MANIFEST_DIR/manifest.json"
MANIFEST_LOG="$MANIFEST_DIR/manifest_output.txt"
REPORT_JSON="$MANIFEST_DIR/last_report.json"
STATUS_JSON="$MANIFEST_DIR/status.json"
RUNS_JSONL="$MANIFEST_DIR/runs.jsonl"

# One run_id + started_at per invocation (a plain timestamp+PID is enough
# uniqueness for a single-operator local demo tool; a real UUID would be a
# new dependency for no real benefit here). A single `date` call each is
# fine -- unlike the per-step timing above, these aren't on a hot path and
# don't need EPOCHREALTIME's sub-second precision.
RUN_ID="$(date -u +%Y%m%dT%H%M%S)-$$"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

# --- Timing/progress instrumentation -----------------------------------
# Wraps each of the 9 pipeline steps below with a start time (bash's own
# EPOCHREALTIME, no external `date` process needed) so that when the next
# step starts (or the script finishes) the previous one prints as a
# completed, timed line -- and so every step's duration can be tallied into
# a final summary table. Purely presentational: none of the actual pipeline
# logic/order is touched by this.

declare -a STEP_NAMES=()
declare -a STEP_DURATIONS_US=()
CURRENT_STEP_NAME=""
CURRENT_STEP_START=""

COLOR_GREEN=""
COLOR_RESET=""
if [[ -t 1 ]]; then
    COLOR_GREEN=$'\033[0;32m'
    COLOR_RESET=$'\033[0m'
fi

# Formats an integer microsecond count as a plain "N.T" number (one decimal
# place), using only bash integer arithmetic -- no bc/awk/date needed.
format_duration_number() {
    local us="$1"
    local whole=$(( us / 1000000 ))
    local frac=$(( (us / 100000) % 10 ))
    printf '%d.%d' "$whole" "$frac"
}

# Same, but as a human-readable "N.Ts" string for terminal output.
format_duration() {
    printf '%ss' "$(format_duration_number "$1")"
}

# Overwrites data/quickdemo/status.json with the run's live state: which
# step is currently running (empty when finished), every step completed so
# far with its duration, run_id, and started_at. This is what a future
# live-progress UI (Phase C/D) polls -- Phase B just needs it to exist and
# be accurate at every point in the run.
write_status_json() {
    local current="$1"
    local finished="$2"
    mkdir -p "$MANIFEST_DIR"
    {
        printf '{\n'
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "started_at": "%s",\n' "$STARTED_AT"
        if [[ -n "$current" ]]; then
            printf '  "current_step": "%s",\n' "$current"
        else
            printf '  "current_step": null,\n'
        fi
        printf '  "finished": %s,\n' "$finished"
        printf '  "completed_steps": [\n'
        local i n=${#STEP_NAMES[@]}
        for i in "${!STEP_NAMES[@]}"; do
            local sep=","
            [[ "$i" -eq $((n - 1)) ]] && sep=""
            printf '    {"name": "%s", "duration_seconds": %s}%s\n' \
                "${STEP_NAMES[$i]}" "$(format_duration_number "${STEP_DURATIONS_US[$i]}")" "$sep"
        done
        printf '  ]\n'
        printf '}\n'
    } > "$STATUS_JSON"
}

# Closes out whichever step is currently running (if any): records its
# duration and prints a green checkmark + elapsed time. Called both when
# the next section() starts and once more at the very end of the script.
finish_current_step() {
    if [[ -n "$CURRENT_STEP_NAME" ]]; then
        local end="$EPOCHREALTIME"
        local start_us="${CURRENT_STEP_START/./}"
        local end_us="${end/./}"
        local diff_us=$(( 10#$end_us - 10#$start_us ))

        STEP_NAMES+=("$CURRENT_STEP_NAME")
        STEP_DURATIONS_US+=("$diff_us")

        local dur
        dur=$(format_duration "$diff_us")
        printf '%s\xe2\x9c\x94 %-38s%s%s\n' "$COLOR_GREEN" "$CURRENT_STEP_NAME" "$COLOR_RESET" "$dur"
    fi
    return 0
}

# Prints the final "every step + total" timing table -- makes it obvious
# where the script spent the most time, independent of anything else.
print_timing_summary() {
    echo
    echo "Timing summary"
    echo "------------------------------------------------------------"
    local total_us=0
    local i
    for i in "${!STEP_NAMES[@]}"; do
        printf '%-45s %8s\n' "${STEP_NAMES[$i]}" "$(format_duration "${STEP_DURATIONS_US[$i]}")"
        total_us=$(( total_us + STEP_DURATIONS_US[i] ))
    done
    echo "------------------------------------------------------------"
    printf '%-45s %8s\n' "Total" "$(format_duration "$total_us")"
}

section() {
    finish_current_step
    CURRENT_STEP_NAME="$1"
    CURRENT_STEP_START="$EPOCHREALTIME"
    write_status_json "$CURRENT_STEP_NAME" false
    echo
    echo "==> $1"
}

# --- 1. Preflight -----------------------------------------------------
section "Preflight checks"

docker info >/dev/null 2>&1 \
    || fail "docker is not available/running. Prepare this before the event -- can't be fixed live without internet."

command -v invariant >/dev/null 2>&1 \
    || fail "'invariant' CLI not found on PATH. Activate the project venv (see README) before the event."

command -v alembic >/dev/null 2>&1 \
    || fail "'alembic' not found on PATH. Activate the project venv (see README) before the event."

for image in quickdemo-debian-hardened:latest quickdemo-ubuntu-hardened:latest; do
    docker image inspect "$image" >/dev/null 2>&1 \
        || fail "Docker image '$image' not built locally. Build it ahead of time: docker compose -f $DEMO_COMPOSE build (needs network once, before the event)."
done

for doc_pdf_glob in "data/raw/cis/debian/cis_debian_linux_11_"*.pdf "data/raw/cis/ubuntu/cis_ubuntu_20_04_"*.pdf; do
    [[ -f "$doc_pdf_glob" ]] \
        || fail "Missing local CIS PDF: $doc_pdf_glob -- prepare this before the event, extract/import need it."
done

echo "OK: docker, invariant, alembic, both hardened images, both demo PDFs all present."

# --- 2. Dev-stack DB only (leave the 6 dev/test containers stopped) ---
section "Starting postgres + adminer (infra/docker-compose.yml, DB only)"
docker compose -f "$DEV_COMPOSE" up -d postgres adminer

# --- 3. Quickdemo containers (isolated compose file) -------------------
section "Starting the 5 quickdemo containers ($DEMO_COMPOSE)"
docker compose -f "$DEMO_COMPOSE" up -d
# Idempotent rehearsal: reset just the 4 "problem" containers to a clean
# image every run, regardless of whatever misconfigs a previous run left.
docker compose -f "$DEMO_COMPOSE" up -d --force-recreate "${PROBLEM_SERVICES[@]}"

# --- 4. Active wait (no long sleep) ------------------------------------
section "Waiting for all 5 demo containers to respond"
wait_for_container() {
    local name="$1"
    local max_attempts=30
    local attempt=0
    until docker exec "$name" true >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [[ "$attempt" -ge "$max_attempts" ]]; then
            fail "container $name did not become ready after ${max_attempts}s"
        fi
        sleep 1
    done
    echo "  $name: ready"
}
for c in "${ALL_DEMO_CONTAINERS[@]}"; do
    wait_for_container "$c"
done

# --- 5. Apply random misconfigs to the 4 problem containers -------------
section "Applying misconfigurations (scripts/quickdemo/apply_misconfigs.py)"
mkdir -p "$MANIFEST_DIR"
python scripts/quickdemo/apply_misconfigs.py "${SEED_ARGS[@]}" | tee "$MANIFEST_LOG"

# --- 6. Migrate DB (idempotent) -----------------------------------------
section "Applying database migrations (alembic upgrade head)"
alembic upgrade head

# --- 7. Extract + import the two demo CIS documents (local PDFs only) --
section "Extracting + importing the two demo CIS documents"
for doc in cis-debian-linux-11 cis-ubuntu-linux-20-04; do
    echo "-- $doc --"
    invariant extract "$doc"
    invariant import_document "$doc"
done

# --- 8. Assess the 5 demo containers -------------------------------------
section "Assessing the 5 demo containers (invariant assess)"
invariant assess \
    --target "$HARDENED_CONTAINER" \
    --target "${PROBLEM_CONTAINERS[0]}" \
    --target "${PROBLEM_CONTAINERS[1]}" \
    --target "${PROBLEM_CONTAINERS[2]}" \
    --target "${PROBLEM_CONTAINERS[3]}"

# --- 9. Final summary: manifest + environmental vs today's story --------
section "Final summary: misconfig manifest vs assess results"
echo "--- Misconfig manifest (from step 5) ---"
cat "$MANIFEST_LOG"

echo "--- FAIL breakdown: environmental vs today's story ---"
python scripts/quickdemo/report.py \
    "$HARDENED_CONTAINER" "${PROBLEM_CONTAINERS[@]}" \
    --manifest "$MANIFEST_JSON" \
    --json-out "$REPORT_JSON"

finish_current_step
write_status_json "" true

echo
echo "==> Done"
echo "quickdemo.sh finished. Re-run any time -- the 4 problem containers reset and redraw misconfigs automatically."

# Appends one line to runs.jsonl for this completed run: run_id, timing
# (per-step + total), seed (if any), and the full build_report() output
# already written to $REPORT_JSON above. Kept as a small inline script
# (not a report.py function) since this is pure JSON-file plumbing over
# data both files already have -- it isn't part of the FAIL-classification
# logic Phase B asked to extract, so there's nothing here worth unit-testing
# beyond what test_report.py already covers for build_report() itself.
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python - "$STATUS_JSON" "$REPORT_JSON" "$RUNS_JSONL" "$FINISHED_AT" "$SEED_VALUE" <<'PYEOF'
import json
import sys
from pathlib import Path

status_path, report_path, runs_path, finished_at, seed = sys.argv[1:6]

status = json.loads(Path(status_path).read_text())
report = json.loads(Path(report_path).read_text())

steps = status["completed_steps"]
total_duration = round(sum(s["duration_seconds"] for s in steps), 1)

record = {
    "run_id": status["run_id"],
    "started_at": status["started_at"],
    "finished_at": finished_at,
    "seed": int(seed) if seed else None,
    "steps": steps,
    "total_duration_seconds": total_duration,
    "report": report,
}

with open(runs_path, "a") as f:
    f.write(json.dumps(record) + "\n")
PYEOF

print_timing_summary
