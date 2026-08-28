# Deploying the demo pipeline to a production server

This is a runbook for Claude Code to follow **on the prod server**, after this repo has
been cloned/pushed there. It assumes you (Claude Code, reading this fresh, with no memory
of how this file was written) have shell access to that machine.

**Read this whole file before running anything.** Follow CLAUDE.md's "Human First"
philosophy for this repo: where a step below has an explicit question for the human
(domain name, TLS, which port is free, etc.), stop and ask — don't guess and don't pick a
default silently. Where a step is mechanical (installing a known dependency, starting a
service that's clearly supposed to be running), just do it and report what you did.

## What "deployed" means here

The user's decision (2026-08-21): this is **not** a static status page pointing at a
pipeline that runs elsewhere. The whole thing — Docker, Postgres, the `invariant` CLI, the
FastAPI app, and the built React frontend — runs on this one server. Nothing here talks to
any other machine.

`demo.sh` itself (repo root) is unchanged for this — it already assumes
Docker/Postgres/the CLI are all on the same box it runs on. Deploying "to prod" means
standing up that same one-box setup on a real server instead of a dev sandbox, then
serving the frontend+API so people can reach it over the network during the event instead
of on localhost.

## 1. Prerequisites — check, don't assume

Check each of these actually works before moving on. If any is missing, install it for
real (see `docs/study-notes/` and prior memory for the pattern this project follows: don't
declare something "not possible" from a shallow check — actually try installing it).

```bash
docker ps                      # Docker daemon must be running
docker compose version         # v2 plugin, not the standalone docker-compose v1
python3 --version              # 3.11+ (pyproject.toml's requires-python)
node --version && npm --version
git -C /path/to/this/repo status   # confirm you're in a clean clone of THIS repo
```

If `dockerd` isn't running and there's no systemd unit for it, start it directly:
`sudo dockerd > /tmp/dockerd.log 2>&1 &` (disown it) — same as the dev sandbox.

## 2. Python environment

```bash
cd /path/to/this/repo
python3 -m venv venv            # or reuse an existing venv/ if already cloned with one — don't assume, check first
source venv/bin/activate
pip install -e ".[dev]"
```

## 3. `.env`

Copy `.env.example` to `.env` and fill in real values (it already lists every var this
project uses, including the two new ones below). At minimum:

```
DATABASE_URL=postgresql://invariant:invariant_dev@localhost:5432/invariant
```

CIS_EMAIL/CIS_USERNAME/CIS_PASSWORD are only needed if you intend to re-fetch benchmark
PDFs live on this server (unlikely for an offline event demo — the PDFs under `data/raw/`
should already be in the repo/artifact you deployed). Don't fetch live from prod unless
the human explicitly asks for that.

**Two new vars added for this deploy** (2026-08-21 session, see `frontend/README.md`'s
"Deploying" section for full detail):

```
INVARIANT_API_CORS_ORIGINS=https://<the-real-frontend-origin>
```

Set this to wherever the built frontend is actually served from (step 6). If frontend and
API end up served from the same origin behind one reverse proxy (recommended, see step 7),
this can be narrowed to just that one origin — ask the human what the final public URL is
before setting it, don't guess a placeholder into production.

## 4. Postgres — via Docker Compose, NOT a native/apt install

Known gotcha from the dev sandbox: a native `postgresql` service and the Docker Compose
one both want host port 5432 from the same `DATABASE_URL`. Only run ONE. This project's
canonical one is the Docker Compose one:

```bash
docker compose -f infra/docker-compose.yml up -d postgres adminer
```

If port 5432 is already bound by something else on this server, that's the first thing to
ask the human about — don't silently pick a different port without updating
`DATABASE_URL` to match everywhere it's used.

**Security note:** on a real internet-facing server, don't let Postgres's 5432 (or
Adminer's 8080) be reachable from outside this box — only the frontend's static origin and
the API's port should be public (step 7). If `infra/docker-compose.yml`'s `ports:` mapping
publishes to `0.0.0.0` by default, either bind it to `127.0.0.1:5432:5432` instead or lock
it down with the server's firewall — ask the human which they'd rather do before changing
the compose file, since it's shared with local dev too.

Then apply migrations:

```bash
alembic upgrade head
```

## 5. Populate real data

Two options, ask the human which applies here if it's not obvious from context:

- **Full demo pipeline** (steps 2-9 of `demo.sh`, repo root — read that script's
  header comment for the full list): brings up the 6 demo containers, applies random
  misconfigs, extracts/imports the two demo CIS documents, runs `invariant assess`. This
  is what actually produces `data/demo/status.json` + `runs.jsonl`, which is what the
  frontend/API show. Just run `./demo.sh` once things above are up — it's designed to
  be one-button and idempotent (safe to re-run).
- If the demo Docker images (`demo-debian-hardened`, `demo-ubuntu-hardened`,
  the 5 "problem" ones reuse those two) aren't built yet on this server, build them first:
  `docker compose -f infra/docker-compose.demo.yml build`. This needs network access
  once, for base image pulls — after that `demo.sh` is offline. `demo.sh`'s own
  preflight check aborts early with a clear message if these aren't built, so just run it
  and follow what it says.

## 6. Build the frontend

```bash
cd frontend
npm install
echo "VITE_API_BASE=https://<the-real-api-origin>" > .env.production   # ask the human for the real value first
npm run build
```

This produces `frontend/dist/` — a static bundle, no Node server needed to serve it.

## 7. Serve it — ask the human before choosing

There's no reverse proxy / TLS config in this repo yet — that decision was deliberately
left for this step, not made in advance (CLAUDE.md: no blind dependency additions, human
decides non-obvious things). Before installing or configuring anything here, ask:

- Is there already a reverse proxy (nginx, Caddy, Traefik...) on this server, or does one
  need to be installed?
- What's the public domain/URL this should be reachable at? (needed for `VITE_API_BASE`
  and `INVARIANT_API_CORS_ORIGINS` above, and for TLS)
- Does this server already have a TLS/cert workflow (e.g. certbot, an existing wildcard
  cert), or does that need setting up too?

Once those are answered, the shape of the config is: serve `frontend/dist/` as static
files at the public origin, reverse-proxy `/api/*` (or however it's split) to the FastAPI
app. Run the API itself with:

```bash
uvicorn invariant.api.main:app --host 127.0.0.1 --port 8000
```

(bind to `127.0.0.1`, not `0.0.0.0`, if it's sitting behind a reverse proxy on the same
box — ask if that assumption doesn't hold). For it to survive a server reboot or SSH
disconnect, it needs a real process supervisor (systemd unit, or whatever this server
already uses) rather than a bare `nohup ... &` — check what's already used for other
services on this box before introducing a new pattern.

## 8. Verify before calling it done

Don't report success from config alone — actually check:

```bash
curl -s https://<the-real-api-origin>/api/demo/status | head -c 300
```

And load the real public frontend URL in a browser (or via Playwright, same as the
2026-08-21 dev-sandbox verification) to confirm it renders live data, not just a blank
page or a CORS error in the console.

## Known facts from the last working dev-sandbox state (2026-08-21, may drift)

- All 428 tests passed with Postgres via Docker Compose (not native), and the 6
  `infra/docker-compose.yml` dev/test containers + Docker daemon up.
- `frontend/README.md` has the full local dev + deploy instructions this file summarizes
  — read it too if anything here is ambiguous.
- `docs/architecture/checks.md` explains why every demo container (even the
  "hardened" baseline) shows some FAILs — that's documented/expected, not a bug to chase
  during deploy verification.
