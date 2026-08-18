# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Invariant is a Python/PostgreSQL pipeline for ingesting, versioning, and tracking security
guidance documents (starting with the CIS AWS Foundations Benchmark, later FIRST/CVSS,
AWS Security Pillar, OWASP) as a trustworthy, reproducible knowledge base. It is
explicitly **not** a scanner yet — the roadmap treats knowledge ingestion (V0–V1) as a
prerequisite to any future assessment engine (V1+). All business logic lives in Python and
is delivered to consumers through a REST API (FastAPI), consumed by a React web frontend —
the frontend holds no business logic of its own. `INVARIANT_PRD.md` (repo root) is the
single source of truth for architecture and decisions; when a design question comes up,
check it before improvising — most answers already exist there (it is ~1950 lines but
organized into ~50 numbered sections, e.g. "section 21" = Suggested Domain Model).

**Current state: the entire codebase is a skeleton.** Every module in `src/invariant/` is
a docstring plus `# TODO:` — there is no working logic, no FastAPI/Typer wiring, no
schema, and no tests yet. The `frontend/` React app has not been scaffolded yet either. Do
not assume any described behavior (fetch, extract, diff, notify, API endpoints...)
actually runs; treat PRD descriptions as the intended design, not the current
implementation.

The project pivoted from an initial Go skeleton to Python (see PRD section 34,
"Language Decision: Python") — if you see stale references to Go, Cobra, or sqlc anywhere
outside that historical section, they're leftover and should be corrected.

## Project philosophy (non-negotiable, read before generating non-trivial code)

This project's stated rule is **Human First**: AI may propose and accelerate
implementation, but the human must understand, question, decide, review, test, and
document. Concretely, this means:

- Before a significant implementation, be able to answer: what/why/how/where/when, what
  alternatives and trade-offs exist, what can fail, how it'll be tested, what proves
  success (PRD section 4).
- No blind dependency additions — every new dependency needs an understood reason (PRD
  section 35, Rule 3). Don't introduce security tools (SAST/DAST/SBOM/etc.) without the
  human understanding what they scan, where they run, and what output looks like.
- Small increments: one problem → one focused, testable change, not large multi-feature
  sessions (PRD section 6.4). Don't jump ahead to later roadmap steps (e.g. don't build
  extraction/diff/notification while `fetch` is still unimplemented).
- Non-obvious architectural decisions belong in `docs/decisions/` or as a Study Note in
  `docs/study-notes/` (organized by topic: `python/`, `security/`, `architecture/`) —
  these are treated as first-class project artifacts, not optional.
- The project is also an explicit Python learning exercise for the author; prefer
  idiomatic standard-library solutions and explain non-obvious choices rather than
  pulling in frameworks reflexively.

## Common commands

```bash
pip install -e ".[dev]"                          # install deps (make install)
uvicorn invariant.api.main:app --reload           # run the REST API (make run-api)
python -m invariant.cli.main $ARGS                # run the CLI, e.g. ARGS="fetch cis" (make run-cli ARGS="fetch cis")
pytest                                            # run all tests (make test)
pytest tests/collector/                           # run tests for a single package
pytest tests/collector/test_foo.py::test_name -v  # run a single test
```

There is no migration tool wired up yet (`make migrate-up` is a TODO placeholder). Alembic
is the chosen tool (PRD section 33) but not yet configured — don't assume migrations
already run.

## Architecture

### Pipeline shape

The core mental model (PRD sections 7, 14, 21) is a pipeline of source-agnostic stages,
each its own package under `src/invariant/`:

```
Source (adapter) → Collector → Raw Artifact (+ SHA-256 hash) → Extractor
  → Normalizer → Storage (PostgreSQL) → Versioning / Diff → Notification
```

- `invariant.source` — the adapter interface that isolates source-specific complexity
  (CIS, AWS, FIRST/CVSS, OWASP...). The architecture must think in terms of `Source /
  Document / Version / Artifact`, never in terms of "CIS parser" / "AWS parser" — one
  adapter per source, not one parser mentality per source.
- `invariant.collector` — downloads raw artifacts and preserves them (dev: `data/raw/`,
  gitignored except `.gitkeep`; future: S3-compatible storage), computing a content hash.
- `invariant.extractor` — turns a raw artifact into structured `extracted_items`.
- `invariant.normalizer` — converts extracted items into normalized `controls`.
- `invariant.versioning` — tracks three **independent** version axes per document
  version: publisher version (e.g. "CIS AWS Foundations 7.0.0"), parser version (owned
  by Invariant), and application version. A document can stay the same while the parser
  changes, so these must never be conflated.
- `invariant.diff` — compares document versions and classifies changes (NEW, CHANGED,
  REMOVED, UNCHANGED, RENAMED, MOVED, SEVERITY_CHANGED, REFERENCE_ADDED/REMOVED). Change
  detection is a hierarchy, cheapest first: raw content hash → extracted content hash →
  normalized controls diff → semantic classification — don't rely solely on a raw page
  hash, since incidental page noise (timestamps, nav, tracking) causes false positives.
- `invariant.notification` — sends change notifications (Telegram first; future: email,
  Discord, Slack, webhooks, GitHub Issues/Discussions).
- `invariant.storage` — persistence interfaces backed by PostgreSQL, implemented in
  `invariant.storage.postgres` via hand-written SQL + psycopg (no ORM — see PRD section
  20).
- `invariant.domain` — the shared entity types: Source, Document, Document Version, Raw
  Artifact, Extracted Item, Control, Reference, Score.

### Reproducibility invariant

The project's namesake guarantee (PRD section 47): every extracted fact must be
traceable to its source, document version, raw artifact, content hash, parser version,
and collection event/timestamp. Keep this traceability intact in any change that touches
extraction, normalization, or storage — it's the foundation the rest of the design
(diffing, versioning, notifications) depends on.

### Delivery: REST API + React (PRD section 31)

The Python core has two consumers, both calling into the same packages rather than
duplicating logic:

- `invariant.cli` (Typer) — operator tooling that *drives* the pipeline: `fetch <source>`,
  `extract <document>`, `import <document>` (normalize + persist), `diff <document>`,
  `check-updates`, `notify`, `source list`, `document list`, `control list`. The first
  working milestone the codebase is building toward is `python -m invariant.cli.main
  fetch cis` (download → save raw artifact → SHA-256 → persist metadata) — see PRD
  section 41 for that command's Definition of Done before considering it complete.
- `invariant.api` (FastAPI) — *reads/exposes* pipeline results (sources, documents,
  document versions, controls, diffs) as a REST API. This is the only way the React SPA
  (`frontend/`, not yet scaffolded) talks to the system — the frontend has no direct DB
  or business-logic access.

### Data layer

PostgreSQL, accessed via hand-written SQL + psycopg (deliberately not an ORM — see PRD
section 20). Schema lives in `sql/schema/` (currently just a placeholder — the real
schema, roughly `sources` / `documents` / `document_versions` / `extracted_items` /
`controls` / `references` / `scores`, is intentionally deferred until the first real CIS
parser informs it; see PRD section 21), queries in `sql/queries/`, wired into
`invariant.storage.postgres` by hand (no code-generation step).

## Repository layout notes

- `src/invariant/` — the Python package: pipeline packages, `api/` (FastAPI), `cli/`
  (Typer).
- `frontend/` — planned home for the React SPA; does not exist yet.
- `data/raw/` — downloaded source artifacts; gitignored, never commit contents.
- `docs/study-notes/` — the "lab notebook": Python, security, and architecture notes
  written as the code is understood. Code is meant to be a product of what's documented
  here. Note: `docs/study-notes/go/` still holds notes from the earlier Go phase — that's
  historical record, not stale content to "fix".
- `docs/decisions/`, `docs/architecture/`, `docs/sources/` — currently empty
  (`.gitkeep`-only) but are the intended homes for ADRs, architecture docs, and
  per-source documentation respectively.
- `to-do.md` — gitignored, local-only onboarding roadmap for reaching the V0 milestone
  (`fetch cis` working end-to-end); kept in sync with the Python stack.
