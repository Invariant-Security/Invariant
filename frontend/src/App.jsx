import { Fragment, useEffect, useRef, useState } from 'react'
import './App.css'

// Default `uvicorn invariant.api.main:app --reload` address -- see the
// frontend README for how to run both the API and this dev server
// together. Overridable via VITE_API_BASE (see .env.example) for a real
// deploy where the API isn't on localhost:8000, without touching code.
const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000'

// The 9 pipeline steps quickdemo.sh's section() calls announce, in order.
// The API only reports which steps are *done so far* (status.completed_steps)
// plus the *current* one (status.current_step) -- it doesn't know the full
// step list ahead of time, so this page hardcodes the same names used in
// quickdemo.sh to render "pending" steps in the checklist below. If a step
// name in quickdemo.sh ever changes, update this list to match.
const QUICKDEMO_STEPS = [
  'Preflight checks',
  'Starting postgres + adminer (infra/docker-compose.yml, DB only)',
  'Starting the 5 quickdemo containers (infra/docker-compose.quickdemo.yml)',
  'Waiting for all 5 demo containers to respond',
  'Applying misconfigurations (scripts/quickdemo/apply_misconfigs.py)',
  'Applying database migrations (alembic upgrade head)',
  'Extracting + importing the two demo CIS documents',
  'Assessing the 5 demo containers (invariant assess)',
  'Final summary: misconfig manifest vs assess results',
]

// Real roles, not guesses -- see infra/docker-compose.quickdemo.yml and
// quickdemo.sh's HARDENED_CONTAINER/PROBLEM_CONTAINERS.
const ENDPOINT_INFO = {
  'invariant-demo-ubuntu-hardened':
    'Hardened Ubuntu baseline -- reference image, never gets a misconfig applied.',
  'invariant-demo-debian-1': 'Hardened Debian image, 2-3 misconfigs applied this run.',
  'invariant-demo-debian-2': 'Hardened Debian image, 2-3 misconfigs applied this run.',
  'invariant-demo-ubuntu-1': 'Hardened Ubuntu image, 2-3 misconfigs applied this run.',
  'invariant-demo-ubuntu-2': 'Hardened Ubuntu image, 2-3 misconfigs applied this run.',
}

const ENVIRONMENTAL_EXPLANATION =
  "Same 15 checks fail on every demo container, including the hardened baseline. Not a " +
  "misconfig -- these images are minimal Docker containers, so they never have sudo, " +
  "cron.{hourly,weekly,monthly}, auditd, or libpam-pwquality installed, and never have a " +
  "journald.conf or bootloader config file at all. Confirmed empirically against both " +
  "hardened images (see misconfig_catalog.py's STRUCTURAL_GAP_TITLES)."

function formatSeconds(value) {
  if (value === null || value === undefined) return '–'
  return `${value.toFixed(1)}s`
}

function formatTimestamp(iso) {
  if (!iso) return '–'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

async function fetchJson(path) {
  const response = await fetch(`${API_BASE}${path}`)
  if (response.status === 404) return null
  if (!response.ok) throw new Error(`${path} -> HTTP ${response.status}`)
  return response.json()
}

function useTicker(enabled) {
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!enabled) return undefined
    const id = setInterval(() => setTick((n) => n + 1), 1000)
    return () => clearInterval(id)
  }, [enabled])
}

function StepChecklist({ status }) {
  const completed = new Map((status?.completed_steps ?? []).map((s) => [s.name, s.duration_seconds]))
  const currentStartRef = useRef(null)
  const currentNameRef = useRef(null)

  if (status?.current_step !== currentNameRef.current) {
    currentNameRef.current = status?.current_step ?? null
    currentStartRef.current = Date.now()
  }

  useTicker(Boolean(status && !status.finished))

  return (
    <ol className="step-list">
      {QUICKDEMO_STEPS.map((name) => {
        let state = 'pending'
        let duration = null
        if (completed.has(name)) {
          state = 'done'
          duration = completed.get(name)
        } else if (name === status?.current_step) {
          state = 'in-progress'
          duration = (Date.now() - currentStartRef.current) / 1000
        }
        return (
          <li key={name} className={`step step--${state}`}>
            <span className="step__icon" aria-hidden="true">
              {state === 'done' ? '✔' : state === 'in-progress' ? '▶' : '○'}
            </span>
            <span className="step__name">{name}</span>
            <span className="step__duration">{formatSeconds(duration)}</span>
          </li>
        )
      })}
    </ol>
  )
}

function ContainerCard({ name, data }) {
  const isClean = data.fail_count === 0
  return (
    <div className={`card ${isClean ? 'card--pass' : 'card--fail'}`}>
      <div className="card__title">{name}</div>
      <div className="card__counts">
        <span className="badge badge--pass">{data.pass_count} PASS</span>
        <span className="badge badge--fail">{data.fail_count} FAIL</span>
      </div>
      <div className="card__breakdown">
        <div className="card__row">
          <span>
            Environmental (structural gap){' '}
            <span className="info-icon" title={ENVIRONMENTAL_EXPLANATION} aria-label={ENVIRONMENTAL_EXPLANATION}>
              ⓘ
            </span>
          </span>
          <strong>{data.environmental.length}</strong>
        </div>
        <div className="card__row">
          <span>Today's story (misconfig applied)</span>
          <strong>{data.story.length}</strong>
        </div>
        {data.unexplained.length > 0 && (
          <div className="card__row card__row--warning">
            <span>Unexplained</span>
            <strong>{data.unexplained.length}</strong>
          </div>
        )}
      </div>
    </div>
  )
}

function ReportCards({ report }) {
  if (!report) return null
  return (
    <section>
      <h2>Latest run: FAIL breakdown</h2>
      <div className="card-grid">
        {report.targets.map((name) => (
          <ContainerCard key={name} name={name} data={report.containers[name]} />
        ))}
      </div>
    </section>
  )
}

function FindingRow({ finding }) {
  return (
    <li className="finding">
      <div className="finding__head">
        <span className="mono">{finding.external_id}</span>
        <span>{finding.control_title}</span>
      </div>
      <div className="finding__meta">
        {finding.source_name}/{finding.document_name} v{finding.document_version}
      </div>
      <div className="finding__evidence">{finding.evidence_output}</div>
      {finding.remediation && (
        <details className="finding-remediation">
          <summary>How to fix</summary>
          <p>{finding.remediation}</p>
        </details>
      )}
    </li>
  )
}

function ContainerDetail({ name, data }) {
  return (
    <div className="container-detail">
      <div className="container-detail__title">{name}</div>
      {ENDPOINT_INFO[name] && <p className="hint container-detail__role">{ENDPOINT_INFO[name]}</p>}
      <div className="card__counts">
        <span className="badge badge--pass">{data.pass_count} PASS</span>
        <span className="badge badge--fail">{data.fail_count} FAIL</span>
      </div>

      {data.unexplained.length > 0 && (
        <>
          <h4 className="finding-group finding-group--warning">Unexplained ({data.unexplained.length})</h4>
          <ul className="finding-list">
            {data.unexplained.map((f) => (
              <FindingRow key={f.external_id} finding={f} />
            ))}
          </ul>
        </>
      )}

      {data.story.length > 0 && (
        <>
          <h4 className="finding-group">Today&apos;s story ({data.story.length})</h4>
          <ul className="finding-list">
            {data.story.map((f) => (
              <FindingRow key={f.external_id} finding={f} />
            ))}
          </ul>
        </>
      )}

      {data.environmental.length > 0 && (
        <details className="finding-details">
          <summary>Environmental ({data.environmental.length})</summary>
          <ul className="finding-list">
            {data.environmental.map((f) => (
              <FindingRow key={f.external_id} finding={f} />
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}

function RunDetail({ report }) {
  return (
    <div className="run-detail">
      {report.targets.map((name) => (
        <ContainerDetail key={name} name={name} data={report.containers[name]} />
      ))}
    </div>
  )
}

function RunHistory({ runs }) {
  const [expandedRunId, setExpandedRunId] = useState(null)
  if (runs.length === 0) {
    return (
      <section>
        <h2>Run history</h2>
        <p className="hint">
          No runs recorded yet. Run <code>./quickdemo.sh</code> from the repo root to produce one.
        </p>
      </section>
    )
  }

  const maxDuration = Math.max(...runs.map((r) => r.total_duration_seconds))

  return (
    <section>
      <h2>Run history ({runs.length})</h2>
      <table className="history-table">
        <thead>
          <tr>
            <th>Run</th>
            <th>Started</th>
            <th>Seed</th>
            <th>Total time</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => {
            const isExpanded = expandedRunId === run.run_id
            return (
              <Fragment key={run.run_id}>
                <tr
                  className="history-row--clickable"
                  onClick={() => setExpandedRunId(isExpanded ? null : run.run_id)}
                  aria-expanded={isExpanded}
                >
                  <td className="mono">
                    <span className="disclosure">{isExpanded ? '▾' : '▸'}</span> {run.run_id}
                  </td>
                  <td>{formatTimestamp(run.started_at)}</td>
                  <td className="mono">{run.seed ?? '–'}</td>
                  <td>
                    <div className="duration-bar-wrap">
                      <div
                        className="duration-bar"
                        style={{ width: `${(run.total_duration_seconds / maxDuration) * 100}%` }}
                      />
                      <span>{formatSeconds(run.total_duration_seconds)}</span>
                    </div>
                  </td>
                </tr>
                {isExpanded && (
                  <tr>
                    <td colSpan={4} className="history-row__detail">
                      <RunDetail report={run.report} />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </section>
  )
}

export default function App() {
  const [status, setStatus] = useState(null)
  const [statusChecked, setStatusChecked] = useState(false)
  const [runs, setRuns] = useState([])
  const [latestReport, setLatestReport] = useState(null)
  const [error, setError] = useState(null)

  const isRunning = Boolean(status && !status.finished)

  useEffect(() => {
    let cancelled = false

    async function poll() {
      try {
        const nextStatus = await fetchJson('/api/quickdemo/status')
        if (cancelled) return
        setStatus(nextStatus)
        setStatusChecked(true)
        setError(null)
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    poll()
    const id = setInterval(poll, 1000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  useEffect(() => {
    if (isRunning) return
    let cancelled = false

    async function loadIdleData() {
      try {
        const [nextRuns, nextLatest] = await Promise.all([
          fetchJson('/api/quickdemo/runs'),
          fetchJson('/api/quickdemo/runs/latest'),
        ])
        if (cancelled) return
        setRuns(nextRuns ?? [])
        setLatestReport(nextLatest)
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    loadIdleData()
    return () => {
      cancelled = true
    }
    // Re-fetch whenever a run finishes (status.finished flips) or on load.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isRunning, status?.run_id, status?.finished])

  return (
    <div className="page">
      <header>
        <h1>Invariant &mdash; quickdemo</h1>
        <p className="subtitle">Live progress and run history for the CIS benchmark assessment demo.</p>
      </header>

      {error && <p className="error">API error: {error}</p>}

      {!statusChecked && <p className="hint">Connecting to the API&hellip;</p>}

      {statusChecked && !status && (
        <p className="hint">
          No quickdemo run has started yet. Run <code>./quickdemo.sh</code> from the repo root to begin.
        </p>
      )}

      {isRunning && (
        <section>
          <h2>Run in progress</h2>
          <StepChecklist status={status} />
        </section>
      )}

      {!isRunning && statusChecked && status && <ReportCards report={latestReport} />}
      {!isRunning && statusChecked && <RunHistory runs={runs} />}
    </div>
  )
}
