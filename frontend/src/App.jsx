import { Fragment, useEffect, useRef, useState } from 'react'
import './App.css'

// Default `uvicorn invariant.api.main:app --reload` address -- see the
// frontend README for how to run both the API and this dev server
// together. Overridable via VITE_API_BASE (see .env.example) for a real
// deploy where the API isn't on localhost:8000, without touching code.
const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000'

// The 9 pipeline steps demo.sh's section() calls announce, in order --
// values here are an exact copy of demo.sh's own strings (translated to
// Portuguese along with the rest of that script's printed narrative), not
// just labels: the checklist below matches these against status.json's
// current_step/completed_steps by exact string equality. If a step name in
// demo.sh ever changes, update this list to match or the checklist will
// silently show every step as "pending" forever.
// The API only reports which steps are *done so far* (status.completed_steps)
// plus the *current* one (status.current_step) -- it doesn't know the full
// step list ahead of time, so this page hardcodes the same names used in
// demo.sh to render "pending" steps in the checklist below.
const DEMO_STEPS = [
  'Verificações iniciais',
  'Subindo postgres + adminer (infra/docker-compose.yml, só banco)',
  'Subindo os 6 containers da demo (infra/docker-compose.demo.yml)',
  'Esperando os 6 containers da demo responderem',
  'Aplicando misconfigurações (scripts/demo/apply_misconfigs.py)',
  'Aplicando migrações do banco (alembic upgrade head)',
  'Extraindo + importando os dois documentos CIS da demo',
  'Avaliando os 6 containers da demo (invariant assess)',
  'Resumo final: manifesto de misconfigurações vs resultado do assess',
]

// The 5-stage pipeline this page's "PipelineStrip" shows, distinct from the
// 9 concrete demo.sh steps above -- this is the conceptual data pipeline
// (ingest -> ... -> evidence), always shown as one static row.
const PIPELINE_STAGES = ['Ingest', 'Extract', 'Normalize', 'Assess', 'Evidence']

// Real roles, not guesses -- see infra/docker-compose.demo.yml and
// demo.sh's HARDENED_CONTAINER/PROBLEM_CONTAINERS.
const ENDPOINT_INFO = {
  'invariant-demo-ubuntu-hardened':
    'Hardened Ubuntu baseline -- reference image, never gets a misconfig applied.',
  'invariant-demo-debian-1': 'Hardened Debian image, 2-3 misconfigs applied this run.',
  'invariant-demo-debian-2': 'Hardened Debian image, 2-3 misconfigs applied this run.',
  'invariant-demo-debian-3': 'Hardened Debian image, 2-3 misconfigs applied this run.',
  'invariant-demo-ubuntu-1': 'Hardened Ubuntu image, 2-3 misconfigs applied this run.',
  'invariant-demo-ubuntu-2': 'Hardened Ubuntu image, 2-3 misconfigs applied this run.',
}

// Why "NOT ASSESSED" exists at all: the assessment engine only ever returns
// PASS/FAIL (every Check.evaluate() is a plain bool) -- there's no native
// third status. What this page labels NOT ASSESSED is a FAIL that
// report.py's build_report() already recognizes as a container-impossible
// gap (the control's title matches misconfig_catalog.py's
// CONTAINER_IMPOSSIBLE_TITLES, and the target was detected as a container:
// the same 5 checks fail identically on every demo container, including
// the hardened baseline, because no bootloader/systemd/functional audit
// subsystem exists inside an unprivileged container). Real FAILs (a
// misconfig recipe actually applied this run) stay FAIL; only the
// container-impossible ones are relabeled here, in presentation only --
// nothing in the data model changes.
const STRUCTURAL_GAP_EXPLANATION =
  'The target environment is a minimal container and may not provide all services, ' +
  'packages or system interfaces required by the benchmark.'

const CONTACT_EMAIL = 'victord.goncalves@outlook.com'
const CONTACT_WHATSAPP_HREF = 'https://wa.me/5511970599016'
const CONTACT_GITHUB_HREF = 'https://github.com/VictorDG00'

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

// Sums a report's per-container PASS/FAIL/NOT ASSESSED into the totals the
// Hero and Assessment History rows show -- FAIL only counts real
// misconfigurations (data.story), never structural gaps. `controls` reuses
// total_findings from any one target, since every target runs the same
// check set (report.py's build_report() confirms this: one CHECKS list,
// looked up per target's detected document).
function aggregateReport(report) {
  let pass = 0
  let fail = 0
  let notAssessed = 0
  let unexplainedTotal = 0
  const documents = new Map()

  for (const name of report.targets) {
    const data = report.containers[name]
    pass += data.pass_count
    fail += data.story.length
    notAssessed += data.environmental.length + data.unexplained.length
    unexplainedTotal += data.unexplained.length
    for (const f of [...data.story, ...data.environmental, ...data.unexplained]) {
      documents.set(`${f.document_name}@${f.document_version}`, {
        name: f.document_name,
        version: f.document_version,
      })
    }
  }

  const controls = report.targets.length > 0 ? report.containers[report.targets[0]].total_findings : 0

  return { pass, fail, notAssessed, targets: report.targets.length, controls, unexplainedTotal, documents: [...documents.values()] }
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
      {DEMO_STEPS.map((name) => {
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

function Header({ view, onNavigate }) {
  return (
    <header className="site-header">
      <div className="brand">
        <img className="brand__logo" src="/logo.svg" alt="" aria-hidden="true" />
        INVARIANT
      </div>
      <nav className="site-nav">
        {[
          ['overview', 'Overview'],
          ['assessments', 'Assessments'],
          ['evidence', 'Evidence'],
        ].map(([key, label]) => (
          <button
            key={key}
            type="button"
            className={`nav-link ${view === key ? 'nav-link--active' : ''}`}
            onClick={() => onNavigate(key)}
          >
            {label}
          </button>
        ))}
      </nav>
      <a className="nav-github" href={CONTACT_GITHUB_HREF} target="_blank" rel="noopener noreferrer">
        ⎇ GitHub <span className="nav-github__badge">Open Source</span>
      </a>
    </header>
  )
}

function AboutBlurb() {
  return (
    <p className="about">
      Invariant ingests security benchmark documents, extracts each recommendation, and
      normalizes it into a versioned, traceable Control &mdash; every result here traces back
      to a real source document and version, never an assumption. The roadmap adds{' '}
      <strong>FIRST/CVSS, the AWS Well-Architected Security Pillar, and OWASP</strong> as
      further trusted sources, so future assessments can be checked against more than one
      authority.
    </p>
  )
}

function StatChip({ label, value, tone }) {
  return (
    <div className={`stat stat--${tone}`}>
      <div className="stat__value">{value}</div>
      <div className="stat__label">{label}</div>
    </div>
  )
}

function HeroAssessment({ run }) {
  if (!run) return null
  const agg = aggregateReport(run.report)
  return (
    <section className="hero">
      <div className="hero__head">
        <h2>Latest Assessment</h2>
        <span className="hero__meta">
          {formatTimestamp(run.started_at)} &middot; {formatSeconds(run.total_duration_seconds)}
        </span>
      </div>
      {agg.documents.length > 0 && (
        <p className="hero__source">
          Benchmark: {agg.documents.map((d) => `CIS ${d.name} v${d.version}`).join(', ')}
        </p>
      )}
      <div className="stat-row">
        <StatChip label="Controls Passing" value={agg.pass} tone="pass" />
        <StatChip label="Misconfigurations" value={agg.fail} tone="fail" />
        <StatChip label="Not Assessed" value={agg.notAssessed} tone="na" />
        <StatChip label="Targets" value={agg.targets} tone="neutral" />
        <StatChip label="Controls" value={agg.controls} tone="neutral" />
      </div>
      {agg.unexplainedTotal > 0 && (
        <p className="hero__warning">
          ⚠ {agg.unexplainedTotal} unexplained result(s) &mdash; neither a known structural gap
          nor a demo misconfiguration. Worth a look.
        </p>
      )}
    </section>
  )
}

function StatusLegend() {
  return (
    <section className="legend">
      <div className="legend__item">
        <span className="legend__dot legend__dot--pass" aria-hidden="true" />
        <strong>PASS</strong>
        <span className="legend__desc">Control evaluated successfully</span>
      </div>
      <div className="legend__item">
        <span className="legend__dot legend__dot--fail" aria-hidden="true" />
        <strong>FAIL</strong>
        <span className="legend__desc">Control evaluated and configuration violates the requirement</span>
      </div>
      <div className="legend__item">
        <span className="legend__dot legend__dot--na" aria-hidden="true" />
        <strong>NOT ASSESSED</strong>
        <span className="legend__desc">Control could not be evaluated in this environment</span>
        <span className="info-icon" title={STRUCTURAL_GAP_EXPLANATION} aria-label={STRUCTURAL_GAP_EXPLANATION}>
          ⓘ
        </span>
      </div>
    </section>
  )
}

function TargetCard({ name, data, onViewFindings }) {
  const isClean = data.story.length === 0
  const notAssessed = data.environmental.length + data.unexplained.length
  return (
    <div className={`target-card ${isClean ? 'target-card--clean' : 'target-card--flagged'}`}>
      <div className="target-card__title mono">{name}</div>
      <div className="card__counts">
        <span className="badge badge--pass">{data.pass_count} PASS</span>
        <span className="badge badge--fail">{data.story.length} FAIL</span>
        <span className="badge badge--na">{notAssessed} NOT ASSESSED</span>
      </div>
      <div className="card__breakdown">
        <div className="card__row">
          <span>Structural gaps</span>
          <strong>{data.environmental.length}</strong>
        </div>
        <div className="card__row">
          <span>Misconfigurations</span>
          <strong>{data.story.length}</strong>
        </div>
        {data.unexplained.length > 0 && (
          <div className="card__row card__row--warning">
            <span>Unexplained</span>
            <strong>{data.unexplained.length}</strong>
          </div>
        )}
      </div>
      {data.story.length > 0 && (
        <p className="target-card__flag">
          ⚠ {data.story.length} intentional demo finding{data.story.length === 1 ? '' : 's'}
        </p>
      )}
      <button type="button" className="link-btn" onClick={() => onViewFindings(name)}>
        View findings →
      </button>
    </div>
  )
}

function TargetGrid({ report, onViewFindings }) {
  if (!report) return null
  return (
    <div className="card-grid">
      {report.targets.map((name) => (
        <TargetCard key={name} name={name} data={report.containers[name]} onViewFindings={onViewFindings} />
      ))}
    </div>
  )
}

function FindingListItem({ finding, onSelect }) {
  return (
    <li className="finding">
      <div className="finding__head">
        <span className="mono">{finding.external_id}</span>
        <span>{finding.control_title}</span>
      </div>
      <div className="finding__meta">
        {finding.source_name}/{finding.document_name} v{finding.document_version}
      </div>
      <div className="finding__evidence mono">{finding.evidence_output}</div>
      <button type="button" className="link-btn" onClick={() => onSelect(finding)}>
        View evidence →
      </button>
    </li>
  )
}

function TargetDetail({ name, data, onSelectFinding, onBack }) {
  const notAssessed = data.environmental.length + data.unexplained.length
  return (
    <div className="target-detail">
      <button type="button" className="link-btn" onClick={onBack}>
        ← Back
      </button>
      <div className="container-detail__title mono">{name}</div>
      {ENDPOINT_INFO[name] && <p className="hint container-detail__role">{ENDPOINT_INFO[name]}</p>}
      <div className="card__counts">
        <span className="badge badge--pass">{data.pass_count} PASS</span>
        <span className="badge badge--fail">{data.story.length} FAIL</span>
        <span className="badge badge--na">{notAssessed} NOT ASSESSED</span>
      </div>

      {data.unexplained.length > 0 && (
        <>
          <h4 className="finding-group finding-group--warning">Unexplained ({data.unexplained.length})</h4>
          <ul className="finding-list">
            {data.unexplained.map((f) => (
              <FindingListItem key={f.external_id} finding={f} onSelect={onSelectFinding} />
            ))}
          </ul>
        </>
      )}

      {data.story.length > 0 && (
        <>
          <h4 className="finding-group">Misconfigurations ({data.story.length})</h4>
          <ul className="finding-list">
            {data.story.map((f) => (
              <FindingListItem key={f.external_id} finding={f} onSelect={onSelectFinding} />
            ))}
          </ul>
        </>
      )}

      {data.environmental.length > 0 && (
        <details className="finding-details">
          <summary>
            Not assessed ({data.environmental.length}){' '}
            <span className="info-icon" title={STRUCTURAL_GAP_EXPLANATION} aria-label={STRUCTURAL_GAP_EXPLANATION}>
              ⓘ
            </span>
          </summary>
          <ul className="finding-list">
            {data.environmental.map((f) => (
              <FindingListItem key={f.external_id} finding={f} onSelect={onSelectFinding} />
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}

function RecentFindings({ report, onSelectFinding }) {
  if (!report) return null
  const findings = report.targets.flatMap((name) => report.containers[name].story)
  if (findings.length === 0) {
    return (
      <section>
        <h2>Recent Findings</h2>
        <p className="hint">No misconfigurations in this run &mdash; every intentional demo finding was clean.</p>
      </section>
    )
  }
  return (
    <section>
      <h2>Recent Findings</h2>
      <ul className="recent-findings">
        {findings.map((f) => (
          <li key={`${f.target}-${f.external_id}`} className="recent-finding" onClick={() => onSelectFinding(f)}>
            <span className="recent-finding__mark" aria-hidden="true">✗</span>
            <span className="mono">{f.target}</span>
            <span className="mono">
              {f.source_name.toUpperCase()} {f.external_id}
            </span>
            <span className="recent-finding__title">{f.control_title}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function EvidenceChain({ finding }) {
  const steps = [
    { label: 'Finding', value: `${finding.external_id} — ${finding.status}` },
    { label: 'Control', value: finding.control_title },
    { label: 'Security Source', value: finding.source_name },
    { label: 'Document', value: finding.document_name },
    { label: 'Document Version', value: `v${finding.document_version}` },
  ]
  if (finding.raw_artifact_path) {
    steps.push({
      label: 'Original evidence',
      value: finding.raw_artifact_path,
      mono: true,
      sub: finding.content_hash ? `sha256:${finding.content_hash.slice(0, 16)}…` : null,
    })
  }
  return (
    <ol className="evidence-chain">
      {steps.map((s) => (
        <li key={s.label} className="evidence-chain__step">
          <div className="evidence-chain__label">{s.label}</div>
          <div className={`evidence-chain__value ${s.mono ? 'mono' : ''}`}>{s.value}</div>
          {s.sub && <div className="evidence-chain__sub mono">{s.sub}</div>}
        </li>
      ))}
    </ol>
  )
}

function FindingDetail({ finding, onBack }) {
  return (
    <section className="finding-detail">
      <button type="button" className="link-btn" onClick={onBack}>
        ← Back
      </button>
      <span className="finding-detail__eyebrow">FINDING</span>
      <h2>{finding.control_title}</h2>

      <div className="finding-detail__grid">
        <div>
          <div className="finding-detail__label">Target</div>
          <div className="mono">{finding.target}</div>
        </div>
        <div>
          <div className="finding-detail__label">Observed</div>
          <div className="mono">{finding.evidence_output}</div>
        </div>
      </div>

      {finding.remediation && (
        <div className="finding-detail__remediation">
          <h3>How to fix</h3>
          <p>{finding.remediation}</p>
        </div>
      )}

      <h3>Evidence Chain</h3>
      <EvidenceChain finding={finding} />
    </section>
  )
}

function AssessmentHistory({ runs, onOpenRun }) {
  if (runs.length === 0) {
    return (
      <section>
        <h2>Assessment History</h2>
        <p className="hint">
          No runs recorded yet. Run <code>./demo.sh</code> from the repo root to produce one.
        </p>
      </section>
    )
  }

  const maxDuration = Math.max(...runs.map((r) => r.total_duration_seconds))

  return (
    <section>
      <h2>Assessment History ({runs.length})</h2>
      <table className="history-table">
        <thead>
          <tr>
            <th>Run</th>
            <th>Started</th>
            <th>Targets</th>
            <th>PASS</th>
            <th>FAIL</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => {
            const agg = aggregateReport(run.report)
            return (
              <tr key={run.run_id} className="history-row--clickable" onClick={() => onOpenRun(run)}>
                <td className="mono">{run.run_id}</td>
                <td>{formatTimestamp(run.started_at)}</td>
                <td>{agg.targets}</td>
                <td className="history-table__pass">{agg.pass}</td>
                <td className="history-table__fail">{agg.fail}</td>
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
            )
          })}
        </tbody>
      </table>
    </section>
  )
}

function PipelineStrip({ complete }) {
  return (
    <div className="pipeline-strip">
      {PIPELINE_STAGES.map((stage, i) => (
        <Fragment key={stage}>
          <span className={`pipeline-stage ${complete ? 'pipeline-stage--done' : ''}`}>
            {complete && '✔ '}
            {stage}
          </span>
          {i < PIPELINE_STAGES.length - 1 && (
            <span className="pipeline-arrow" aria-hidden="true">
              →
            </span>
          )}
        </Fragment>
      ))}
    </div>
  )
}

function Footer() {
  return (
    <footer className="site-footer">
      <div className="site-footer__brand">Invariant</div>
      <p className="site-footer__tagline">Security evidence &amp; assessment laboratory.</p>
      <p className="site-footer__prompt">Questions, feedback or want to contribute?</p>
      <div className="contact">
        <a className="btn" href={CONTACT_GITHUB_HREF} target="_blank" rel="noopener noreferrer">
          ⎇ GitHub
        </a>
        <a className="btn" href={`mailto:${CONTACT_EMAIL}`}>
          ✉ Email
        </a>
        <a className="btn" href={CONTACT_WHATSAPP_HREF} target="_blank" rel="noopener noreferrer">
          ✆ WhatsApp
        </a>
      </div>
      <p className="site-footer__principles">Human First &middot; Evidence over assumptions &middot; Small increments</p>
      <p className="site-footer__copyright">&copy; 2026 Invariant</p>
    </footer>
  )
}

export default function App() {
  const [status, setStatus] = useState(null)
  const [statusChecked, setStatusChecked] = useState(false)
  const [runs, setRuns] = useState([])
  const [error, setError] = useState(null)

  const [view, setView] = useState('overview')
  const [selectedRun, setSelectedRun] = useState(null)
  const [selectedTarget, setSelectedTarget] = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)

  const isRunning = Boolean(status && !status.finished)
  const latestRun = runs[0] ?? null
  const latestReport = latestRun?.report ?? null

  useEffect(() => {
    let cancelled = false

    async function poll() {
      try {
        const nextStatus = await fetchJson('/api/demo/status')
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
        const nextRuns = await fetchJson('/api/demo/runs')
        if (cancelled) return
        setRuns(nextRuns ?? [])
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

  function navigate(next) {
    setView(next)
    setSelectedFinding(null)
    setSelectedTarget(null)
    setSelectedRun(null)
  }

  function openFinding(finding) {
    setSelectedFinding(finding)
    setView('evidence')
  }

  function openTarget(name, report) {
    setSelectedTarget({ name, report })
  }

  function backToTargets() {
    setSelectedTarget(null)
  }

  function backFromEvidence() {
    setSelectedFinding(null)
    setView(selectedRun ? 'assessments' : 'overview')
  }

  return (
    <div className="page">
      <Header view={view} onNavigate={navigate} />
      {view === 'overview' && (
        <>
          <p className="page-subtitle">Live progress and run history for the CIS benchmark assessment demo.</p>
          <AboutBlurb />
        </>
      )}

      {error && <p className="error">API error: {error}</p>}

      {!statusChecked && <p className="hint">Connecting to the API&hellip;</p>}

      {statusChecked && !status && (
        <p className="hint">
          No demo run has started yet. Run <code>./demo.sh</code> from the repo root to begin.
        </p>
      )}

      {isRunning && (
        <section>
          <h2>Run in progress</h2>
          <StepChecklist status={status} />
        </section>
      )}

      {!isRunning && statusChecked && status && view === 'overview' && (
        <>
          <HeroAssessment run={latestRun} />
          <StatusLegend />
          {selectedTarget ? (
            <TargetDetail
              name={selectedTarget.name}
              data={selectedTarget.report.containers[selectedTarget.name]}
              onSelectFinding={openFinding}
              onBack={backToTargets}
            />
          ) : (
            <>
              <section>
                <h2>Targets</h2>
                <p className="hint">Minimal demo environments may leave some controls unassessed.</p>
                <TargetGrid report={latestReport} onViewFindings={(name) => openTarget(name, latestReport)} />
              </section>
              <RecentFindings report={latestReport} onSelectFinding={openFinding} />
            </>
          )}
          <PipelineStrip complete={Boolean(latestReport)} />
        </>
      )}

      {statusChecked && view === 'assessments' &&
        (selectedRun ? (
          selectedTarget ? (
            <TargetDetail
              name={selectedTarget.name}
              data={selectedTarget.report.containers[selectedTarget.name]}
              onSelectFinding={openFinding}
              onBack={backToTargets}
            />
          ) : (
            <>
              <button type="button" className="link-btn" onClick={() => setSelectedRun(null)}>
                ← Back to history
              </button>
              <h2 className="mono">{selectedRun.run_id}</h2>
              <TargetGrid report={selectedRun.report} onViewFindings={(name) => openTarget(name, selectedRun.report)} />
            </>
          )
        ) : (
          <AssessmentHistory runs={runs} onOpenRun={setSelectedRun} />
        ))}

      {view === 'evidence' &&
        (selectedFinding ? (
          <FindingDetail finding={selectedFinding} onBack={backFromEvidence} />
        ) : (
          <section>
            <h2>Evidence</h2>
            {latestReport ? (
              <RecentFindings report={latestReport} onSelectFinding={openFinding} />
            ) : (
              <p className="hint">No findings yet.</p>
            )}
          </section>
        ))}

      <Footer />
    </div>
  )
}
