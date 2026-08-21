# quickdemo run history: plain JSON files, not a Postgres table

`quickdemo.sh` now writes `data/quickdemo/status.json` (overwritten live,
current-step + completed-steps-so-far for a running demo) and
`data/quickdemo/runs.jsonl` (one JSON line appended per completed run: run_id,
timestamps, seed, per-step durations, total duration, and the full
`build_report()` output). Both live under `data/quickdemo/`, which is already
gitignored -- this data is local-only, same as `manifest.json` next to it.

The alternative considered was a real schema-backed store: a `quickdemo_runs`
table (or similar) under `sql/schema/`, migrated with Alembic like everything
else `invariant.storage.postgres` owns. That was rejected for now, for one
reason: this data isn't part of the core domain model. PRD sec. 21's
`sources` / `documents` / `document_versions` / `extracted_items` /
`controls` / `references` / `scores` schema exists to make CIS benchmark
*knowledge* reproducible and traceable -- `invariant.assess`'s own findings
already read that schema (via `db.select_control_by_title`), so assessment
results are already anchored to a real control/source/document version. What
`quickdemo.sh` additionally wants to persist is meta-data about *demo runs
themselves* -- how long each of the 9 pipeline steps took, which random
misconfig seed was drawn -- which has nothing to do with document versioning
or diffing and would sit awkwardly next to that schema. Time-boxed demo
tooling (a `--seed`-driven rehearsal script, not a pipeline stage) shouldn't
force a migration onto the one schema this project treats as
reproducibility-critical.

Plain JSON also matches what the two consumers actually need: `status.json`
is polled by a future live-progress UI (Phase C/D) as a single small blob, not
queried or joined; `runs.jsonl` is read start-to-finish and reversed
(newest-first) by a "history" view -- an append-only log is the natural shape
for that, and `jsonlines` is trivial to produce (`open(path, "a")`) and parse
(`json.loads` per line) with the standard library alone, no new dependency.
A Postgres table would add connection/session handling, a migration, and
query code for a access pattern that's currently "read the whole small file."

If this data proves worth keeping permanently (e.g. tracking demo/pipeline
performance over months, or querying across many runs), a schema-backed
version is a reasonable follow-up -- but that's a decision for when the data
has actually proven useful, not before.
