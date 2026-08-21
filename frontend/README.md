# Invariant quickdemo frontend

A single-page React app (plain JS, no router, no UI/chart library) that
shows live progress and run history for `./quickdemo.sh` (repo root). It
talks only to the 3 read-only endpoints under `invariant.api` (see
`src/invariant/api/main.py`) -- no direct database access, per this
project's frontend/API split (see the repo root `CLAUDE.md`).

## Running it

You need three things running at once, each in its own terminal, from the
repo root unless noted:

```bash
# 1. The API (reads data/quickdemo/status.json + runs.jsonl)
uvicorn invariant.api.main:app --reload

# 2. This dev server
cd frontend
npm install   # first time only
npm run dev

# 3. The actual demo pipeline
./quickdemo.sh
```

Open the URL Vite prints (default `http://localhost:5173`). While
`quickdemo.sh` step 3-9 runs, the page polls `/api/quickdemo/status` every
second and shows a step checklist (done/in-progress/pending, with elapsed
time). Once a run finishes, it shows the FAIL breakdown for all 5 demo
containers as cards, plus a run history table below (bar-per-run total
time) built from every past run recorded in `data/quickdemo/runs.jsonl`.

## Notes

- The API base URL (`http://127.0.0.1:8000`, uvicorn's default) is a plain
  constant in `src/App.jsx` -- no env-var setup, to keep this simple for a
  local demo tool.
- The ordered list of the 9 pipeline step names in `src/App.jsx`
  (`QUICKDEMO_STEPS`) is copied from `quickdemo.sh`'s `section(...)` calls,
  since the API only reports steps completed so far plus the current one,
  not the full step list ahead of time. If a step name changes in
  `quickdemo.sh`, update it here too.
- No new npm dependencies beyond the Vite React template's own
  (react/react-dom + Vite/oxlint tooling) -- charts are plain CSS bars,
  not a charting library.
