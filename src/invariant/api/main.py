"""FastAPI application entrypoint.

Deliberately narrow for now: 3 read-only routes over what quickdemo.sh
already writes to data/quickdemo/ (see scripts/quickdemo/report.py for
build_report()'s shape, and quickdemo.sh's status.json/runs.jsonl writers)
so a future React page (Phase D of the quickdemo terminal/UI work) can show
live progress + run history without talking to Postgres or duplicating any
pipeline logic. Sources/documents/controls/diff routes are out of scope
here -- see CLAUDE.md's "small increments" rule; those are a separate,
later task once the storage layer's read APIs are designed.
"""

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from invariant.config import load_dotenv

load_dotenv()

# src/invariant/api/main.py -> repo root is 4 parents up.
QUICKDEMO_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "quickdemo"
STATUS_PATH = QUICKDEMO_DATA_DIR / "status.json"
RUNS_PATH = QUICKDEMO_DATA_DIR / "runs.jsonl"

app = FastAPI(title="Invariant quickdemo API")

# Vite's default dev server port (and its 127.0.0.1 equivalent) are the
# default -- a full remote deploy (frontend + API on the same prod server,
# not just a local demo) sets INVARIANT_API_CORS_ORIGINS to the real
# frontend origin instead, e.g. "https://demo.example.com". Comma-separated
# to allow more than one (e.g. staging + prod) without code changes.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
allow_origins = [
    origin.strip()
    for origin in os.environ.get("INVARIANT_API_CORS_ORIGINS", _default_origins).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    """Liveness check for the deploy's Docker healthcheck -- doesn't touch
    quickdemo data, just confirms the process is up.
    """
    return {"status": "ok"}


def _read_runs() -> list[dict]:
    """Parses runs.jsonl into a list of run records, oldest first (the
    order they were appended in) -- callers reverse when "most recent
    first" is what's wanted. Returns [] if the file doesn't exist yet
    (before quickdemo.sh's first run), same "don't crash on missing demo
    data" posture as the rest of this module.
    """
    if not RUNS_PATH.exists():
        return []
    runs = []
    with open(RUNS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            runs.append(json.loads(line))
    return runs


@app.get("/api/quickdemo/status")
def get_status():
    """Live state of the current (or most recently finished) quickdemo.sh
    run: current_step, completed_steps so far, run_id, started_at,
    finished. See quickdemo.sh's write_status_json().
    """
    if not STATUS_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="No quickdemo run has started yet -- run ./quickdemo.sh first.",
        )
    return json.loads(STATUS_PATH.read_text())


@app.get("/api/quickdemo/runs")
def get_runs():
    """Every completed run recorded in runs.jsonl, most recent first, each
    with its per-step and total durations plus its full report. Returns an
    empty list rather than 404 -- "no history yet" is a normal, expected
    state for a history endpoint, not an error.
    """
    return list(reversed(_read_runs()))


@app.get("/api/quickdemo/runs/latest")
def get_latest_run():
    """The full build_report()-shaped report from the most recently
    completed run (same "report" value each runs.jsonl line carries).
    """
    runs = _read_runs()
    if not runs:
        raise HTTPException(
            status_code=404,
            detail="No completed quickdemo run yet -- run ./quickdemo.sh first.",
        )
    return runs[-1]["report"]
