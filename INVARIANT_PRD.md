# Invariant — PRD, Architecture & Decision Dump

> **Status:** Pre-implementation / living document  
> **Project:** Invariant  
> **Core philosophy:** Human First  
> **Primary implementation:** Python, exposing a REST API (FastAPI) consumed by a React web frontend  
> **Initial database:** PostgreSQL  
> **First knowledge source:** CIS AWS Foundations Benchmark

---

## 1. Executive Summary

Invariant is an open-source, continuously evolving security, infrastructure and reliability knowledge platform.

The project is intentionally designed to become a long-lived technical laboratory instead of another disposable portfolio project.

The initial goal is **not** to build an AWS scanner. The initial goal is to build a **versioned knowledge ingestion layer** capable of:

1. collecting authoritative security/infrastructure documents;
2. preserving the original artifacts;
3. identifying source and document versions;
4. extracting structured information;
5. normalizing that information;
6. persisting it in a database;
7. tracking changes between versions;
8. notifying maintainers when meaningful changes occur.

The future assessment engine will consume this knowledge layer to assess real environments.

### North-star question

> **What should be true, what is actually true, what changed, why does it matter, and what should be done next?**

---

# 2. Why Invariant Exists

The original motivation was to build a project that could grow continuously instead of being another one-shot portfolio project.

The project is intended to combine the user's study path with a real open-source codebase:

```text
Study
  ↓
Implement
  ↓
Understand
  ↓
Document
  ↓
Publish
  ↓
Receive feedback
  ↓
Improve
```

The project should become a practical laboratory for:

- Linux;
- Docker;
- AWS;
- Kubernetes;
- Terraform;
- observability;
- security;
- SRE;
- platform engineering.

AWS is intentionally not the architectural center because it is vendor-specific. Linux and Docker provide broader applicability across infrastructure roles.

---

# 3. Vision

```text
                         INVARIANT
                             │
             ┌───────────────┴────────────────┐
             │                                │
      Knowledge Layer                    Assessment Layer
             │                                │
             ▼                                ▼
       Authoritative                    Real Environment
          Sources                              │
             │                                │
             ▼                                ▼
       Versioned Data                  Assessment Engine
             │                                │
             └───────────────┬────────────────┘
                             ▼
                         Findings
```

Long-term:

```text
Linux
  +
Docker
  +
AWS
  +
Kubernetes
  +
Terraform
  +
Observability
  +
Security
  +
Reliability
  +
Platform Engineering
```

---

# 4. Human First

This is one of the project's core rules.

```text
╔══════════════════════════════════════════════════╗
║                   HUMAN FIRST                    ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║  UNDERSTAND                                      ║
║       ↓                                          ║
║  QUESTION                                        ║
║       ↓                                          ║
║  DECIDE                                          ║
║       ↓                                          ║
║  DELEGATE                                        ║
║       ↓                                          ║
║  REVIEW                                          ║
║       ↓                                          ║
║  TEST                                            ║
║       ↓                                          ║
║  DOCUMENT                                        ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

> **AI can accelerate implementation. It cannot replace understanding.**

Before significant implementation, answer:

1. What are we solving?
2. Why are we solving it this way?
3. How does it work?
4. Where does it belong?
5. When does it run?
6. What alternatives exist?
7. What are the trade-offs?
8. What can fail?
9. How will it be tested?
10. What evidence proves success?

The AI may propose and implement.

**The human decides.**

---

# 5. Study Notes

Study Notes are first-class project artifacts.

A new technology, security concept, architectural decision or important implementation concept should produce a Study Note when appropriate.

Suggested structure:

```text
docs/study-notes/

python/
├── http-client.md
├── concurrency.md
├── interfaces.md
└── error-handling.md

security/
├── cvss.md
├── cis-benchmarks.md
└── vulnerability-lifecycle.md

architecture/
├── raw-artifacts.md
├── document-versioning.md
└── change-detection.md
```

Preferred development loop:

```text
Issue
  ↓
Study Note
  ↓
Architecture Decision
  ↓
Implementation
  ↓
Tests
  ↓
Documentation
  ↓
Pull Request
```

The objective is to turn implementation into durable knowledge.

---

# 6. Core Principles

## 6.1 Build until you understand

> **Do not build to appear that you know. Build until you know.**

## 6.2 AI is an accelerator, not an authority

AI can be used for pair programming, research assistance, implementation, debugging, documentation, tests and code review. Generated code must be understood before it becomes project knowledge.

## 6.3 Evidence over assumptions

Do not fabricate security findings, performance numbers, business impact, technology expertise or claims about tools actually running.

## 6.4 Small increments

Prefer:

```text
one problem
→ one focused change
→ one testable result
```

over giant implementation sessions.

---

# 7. Source Strategy

> **Do not make the architecture depend on the organization of a website.**

Each source gets an adapter.

The system should think in terms of:

```text
Source
Document
Version
Artifact
Extracted Item
Normalized Control
Reference
Score
```

not:

```text
CIS parser
AWS parser
OWASP parser
NIST parser
```

The adapter pattern isolates source-specific complexity.

---

# 8. Initial Source: CIS

The first source selected is CIS.

Initial target:

> **CIS Amazon Web Services Foundations Benchmark**

The first implementation should **not** crawl all CIS material. Start with one benchmark.

Initial workflow:

```text
CIS
 ↓
AWS Foundations
 ↓
Download
 ↓
Save raw PDF
 ↓
Calculate SHA-256
 ↓
Record version
 ↓
Extract controls
 ↓
Normalize
 ↓
Store
```

References:

- https://downloads.cisecurity.org/#/
- https://www.cisecurity.org/cis-benchmarks
- https://www.cisecurity.org/benchmark/amazon_web_services
- https://workbench.cisecurity.org/

---

# 9. OWASP

OWASP was identified as confusing because it contains many projects and publications.

Decision:

> **Do not consume "all OWASP".**

A future implementation should explicitly select one project/document.

Potential starting point:

> OWASP API Security Top 10.

References:

- https://owasp.org/API-Security/
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://owasp.org/API-Security/editions/2023/en/0x00-toc/
- https://github.com/OWASP/API-Security

Do not treat the OWASP GitHub repository as the only source of truth.

---

# 10. NIST / NVD

Decision:

> **Deferred.**

NIST is a broad ecosystem rather than simply a severity database. It should not be added without a concrete data requirement.

Possible future topics:

- vulnerability records;
- CVE data;
- configuration guidance;
- security frameworks;
- mappings.

Do not add NIST merely because it is famous.

---

# 11. FIRST / CVSS

References:

- https://www.first.org/cvss/
- https://www.first.org/cvss/v4.0/specification-document
- https://www.first.org/cvss/user-guide.html

Architectural decision:

> **CVSS is a scoring system, not the universal severity model for Invariant.**

A misconfiguration does not necessarily have a CVSS score.

The data model separates:

```text
severity
severity_source
scoring_system
score
score_vector
```

Example:

```yaml
severity: HIGH
severity_source: CIS
scoring_system: null
score: null
score_vector: null
```

Another finding could be:

```yaml
severity: HIGH
severity_source: FIRST
scoring_system: CVSS
score: 8.8
score_vector: "CVSS:4.0/..."
```

Future scoring systems should coexist.

---

# 12. AWS

AWS is valuable but vendor-specific.

Decision:

> AWS should be a source/domain, not the architecture of Invariant.

References:

- https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html
- https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html

```text
AWS guidance
≠
universal vulnerability severity database
```

---

# 13. Domain Expansion Strategy

Planned future assessment order:

```text
Linux
  ↓
Docker
  ↓
AWS
  ↓
Kubernetes
  ↓
Terraform
  ↓
Observability
  ↓
Platform / SRE
```

Rationale: Linux and Docker are broadly applicable; AWS adds cloud/security depth; Kubernetes extends platform engineering; Terraform adds IaC; observability and SRE complete the platform/reliability direction.

---

# 14. Version Roadmap

## V0 — Knowledge Ingestion Foundation

Objective: prove the core pipeline in Python.

```text
Authoritative Source
        ↓
Collector
        ↓
Raw Artifact
        ↓
Metadata + Hash
        ↓
Extractor
        ↓
Normalizer
        ↓
PostgreSQL
        ↓
Version Tracking
```

## V0.1 — CIS

Target: **CIS AWS Foundations Benchmark**.

```text
Download
  ↓
Preserve raw artifact
  ↓
Calculate SHA-256
  ↓
Store metadata
  ↓
Identify publisher version
  ↓
Extract controls
  ↓
Normalize controls
  ↓
Persist in PostgreSQL
```

## V0.2 — Versioning & Change Tracking

Make the knowledge base living.

```text
Document
   │
   ├── Version 1
   ├── Version 2
   ├── Version 3
   └── Version N
```

Track original artifact, content hash, source URL, retrieval timestamp, publisher version, parser version, collector version and normalized output.

Possible classifications:

```text
NEW
CHANGED
REMOVED
UNCHANGED
RENAMED
MOVED
SEVERITY_CHANGED
REFERENCE_ADDED
REFERENCE_REMOVED
```

A document can remain the same while the parser changes. Document version and parser version must therefore be independent.

## V0.3 — Notifications

Initial mechanism: **Telegram**.

```text
Scheduled Check
      ↓
Download
      ↓
Hash
      │
 ┌────┴─────┐
 │          │
same      changed
 │          │
stop       version
            ↓
         extract
            ↓
          diff
            ↓
        Telegram
```

Future targets: email, Discord, Slack, generic webhooks, GitHub Issues, GitHub Discussions.

## V0.4 — Multiple Sources

```text
Source Adapter
      ↓
Document
      ↓
Document Version
      ↓
Raw Artifact
      ↓
Extraction
      ↓
Normalization
      ↓
Knowledge DB
```

Planned source order:

1. CIS
2. AWS Security guidance
3. FIRST/CVSS
4. one explicit OWASP project/document
5. NIST/NVD later

## V1 — Knowledge Platform

V1 means the knowledge layer is mature enough to become the foundation for the assessment engine.

Minimum V1:

```text
✓ Multiple source adapters
✓ Raw artifact preservation
✓ Source/version tracking
✓ Parser version tracking
✓ Normalized controls
✓ Historical versions
✓ Meaningful change detection
✓ Severity/scoring metadata
✓ Cross-reference relationships
✓ Reproducible extraction
✓ Automated tests
✓ CI/CD
✓ Documentation
✓ Study Notes
✓ Notifications
✓ Stable CLI
✓ Public contribution workflow
```

Only after this should the assessment engine become the central development priority.

---

# 15. Versioning Model

Invariant tracks three different versions.

### Publisher document version

Controlled by the source.

Example: `CIS AWS Foundations 7.0.0`

### Parser version

Controlled by Invariant.

Example: `parser_version = 0.2.0`

### Application version

Controlled by Invariant releases.

Example: `Invariant = 0.1.0`

These are independent.

Every extraction should be traceable to all relevant versions.

---

# 16. Reproducibility

Every extracted fact should be traceable to:

```text
Source
+
Document Version
+
Raw Artifact
+
Content Hash
+
Parser Version
+
Collector Version
+
Extraction Timestamp
```

Future capability:

```text
old artifact
     +
old parser
     ↓
reproduce old result
```

This permits comparisons such as `Document v1 + Parser v1` versus `Document v1 + Parser v2`.

---

# 17. Change Detection

Do not rely exclusively on raw page hashes because timestamps, navigation, tracking, dynamic UI, unrelated text and formatting can change.

Preferred hierarchy:

```text
Level 1
Raw content hash
      ↓
Level 2
Extracted content hash
      ↓
Level 3
Normalized controls diff
      ↓
Level 4
Semantic change classification
```

Goal:

> Detect meaningful changes to the knowledge represented by the source.

---

# 18. Database Decision

## PostgreSQL

Decision: **Use PostgreSQL.**

Reasons:

- already familiar;
- relational model fits source/version/control relationships;
- strong transactions;
- JSONB supports source-specific metadata;
- mature indexing;
- native full-text search can cover early needs;
- good long-term fit;
- avoids prematurely introducing multiple databases.

References:

- https://www.postgresql.org/docs/current/
- https://www.postgresql.org/docs/current/datatype-json.html
- https://www.postgresql.org/docs/current/textsearch-controls.html

---

# 19. Raw Artifact Storage

Do not put large PDFs/HTML artifacts directly into PostgreSQL without a reason.

Preferred:

```text
                 Source
                   │
                   ▼
               Downloader
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
     Raw Storage          PostgreSQL
         │                   │
         ▼                   ├── metadata
      original               ├── versions
      artifact               ├── hashes
                             ├── extracted data
                             └── relationships
```

Development: `data/raw/`.

Future: S3 or S3-compatible object storage.

---

# 20. DB Access Decision

The project author normally uses ORMs, but this project is also a learning opportunity.

Provisional:

```text
Python
 │
 └── SQL + psycopg (no ORM)
       │
       ▼
  PostgreSQL
```

Reasons:

- the project is data-oriented;
- version/history queries matter;
- explicit SQL improves understanding;
- hand-written queries, mapped to dataclasses/Pydantic models, keep the application layer manageable without hiding the SQL behind an ORM.

This remains provisional until V0 validates it.

---

# 21. Suggested Domain Model

```text
Source
  ↓
Document
  ↓
Document Version
  ↓
Raw Artifact
  ↓
Extracted Item
  ↓
Normalized Control
  ↓
Reference
  ↓
Score / Severity
```

Suggested tables:

### `sources`

```text
id
name
type
base_url
created_at
```

### `documents`

```text
id
source_id
name
document_type
```

### `document_versions`

```text
id
document_id
publisher_version
content_hash
retrieved_at
raw_artifact_path
parser_version
collector_version
```

### `extracted_items`

```text
id
document_version_id
external_id
title
description
category
raw_data JSONB
```

### `controls`

```text
id
document_version_id
external_id
title
description
category
normalized_data JSONB
```

### `references`

```text
id
control_id
reference_type
external_id
url
```

### `scores`

```text
id
control_id
severity
severity_source
scoring_system
score
score_vector
```

This schema is intentionally provisional. The first real CIS parser should inform the final schema.

---

# 22. Future Finding Model

```text
Finding
├── ID
├── Title
├── Category
├── Description
├── Evidence
├── Impact
├── Recommendation
├── Severity
├── Severity Source
├── Scoring System
├── Score
├── Score Vector
├── References
└── Remediation
```

A finding may have a source-specific severity without a CVSS score.

---

# 23. Future Assessment Architecture

The knowledge database answers:

> **What should be checked?**

Collectors answer:

> **What exists?**

The rule engine answers:

> **Does the evidence satisfy the control?**

```text
                    Assessment Engine
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
             Knowledge DB        Environment
                │                     │
                ▼                     ▼
             Controls             Collector
                │                     │
                └──────────┬──────────┘
                           ▼
                       Rule Engine
                           │
                           ▼
                        Evidence
                           │
                           ▼
                        Finding
```

---

# 24. Linux Direction

Potential areas:

- users/groups;
- permissions;
- services;
- processes;
- SSH;
- filesystem;
- packages;
- networking;
- logging;
- hardening.

Potential checks:

```text
LINUX-001
Unnecessary service

LINUX-002
Insecure SSH configuration

LINUX-003
Insecure filesystem permissions

LINUX-004
Outdated packages

LINUX-005
Incorrect user/group configuration
```

---

# 25. Docker Direction

Potential areas:

- images;
- containers;
- volumes;
- networks;
- capabilities;
- namespaces;
- rootless mode;
- secrets;
- Docker socket;
- image pinning.

Potential checks:

```text
DOCKER-001
Container running as root

DOCKER-002
Image tag/version not pinned

DOCKER-003
Secrets exposed

DOCKER-004
Docker socket exposed

DOCKER-005
Excessive capabilities
```

References:

- https://docs.docker.com/engine/security/
- https://docs.docker.com/engine/security/rootless/

---

# 26. AWS Assessment Direction

Potential areas:

- IAM;
- S3;
- EC2;
- Security Groups;
- CloudTrail;
- logging;
- encryption;
- secrets;
- networking.

Future model:

```text
Knowledge DB
    │
    ▼
Control
    │
    ▼
Assessment Rule
    │
    ▼
AWS API
    │
    ▼
Evidence
    │
    ▼
Finding
```

---

# 27. Kubernetes Direction

Potential areas:

- Pods;
- Deployments;
- Services;
- Ingress;
- RBAC;
- NetworkPolicy;
- Secrets;
- Security Context;
- capabilities;
- resources;
- workload configuration.

Potential checks:

```text
K8S-001
Privileged container

K8S-002
Container running as root

K8S-003
Excessive capabilities

K8S-004
Excessive RBAC permissions

K8S-005
Exposed secrets/configuration

K8S-006
Missing NetworkPolicy

K8S-007
Image configuration issue
```

References:

- https://kubernetes.io/docs/
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/

---

# 28. Terraform / IaC Direction

References:

- https://developer.hashicorp.com/terraform/docs
- https://developer.hashicorp.com/terraform/language

Study areas:

- state;
- providers;
- modules;
- variables;
- outputs;
- remote state;
- environments;
- plan/apply;
- drift;
- CI/CD.

---

# 29. Observability / SRE Direction

```text
                 Application
                      │
             ┌────────┼────────┐
             ▼        ▼        ▼
           Logs     Metrics   Traces
             │        │        │
             └────────┼────────┘
                      ▼
               Observability
                      │
             ┌────────┴────────┐
             ▼                 ▼
        Prometheus           Grafana
             │
             ▼
          Alerts
```

Future areas:

- logs;
- metrics;
- traces;
- dashboards;
- health checks;
- SLIs;
- SLOs;
- error budgets;
- alerting;
- incident response.

---

# 30. Reliability Direction

The project may evolve from **Security Assessment** into **Infrastructure Security & Reliability Assessment**.

Potential reliability findings:

```text
REL-001
Missing health check

REL-002
No restart/recovery strategy

REL-003
Missing backup strategy

REL-004
Missing monitoring

REL-005
Missing alerting

REL-006
Insufficient observability

REL-007
Single Point of Failure
```

---

# 31. CLI, API & Frontend Direction

## CLI (internal / operator tooling)

The CLI remains the operator-facing tool for running the ingestion pipeline
(fetch, extract, normalize, diff, notify). It is not the primary way end
users consume the knowledge base — that is the REST API described below.

Candidate commands:

```text
invariant fetch <source>
invariant extract <document>
invariant import <document>
invariant diff <document>
invariant check-updates
invariant notify
invariant source list
invariant document list
invariant control list
```

First milestone:

```text
python -m invariant.cli.main fetch cis
```

Expected:

```text
Download
   ↓
Raw artifact saved
   ↓
SHA-256 calculated
   ↓
Metadata persisted
```

## Delivery Model: REST API + React

Invariant's logic (collector, extractor, normalizer, versioning, diff,
notification, storage) lives entirely in Python. That logic is exposed to
consumers through a REST API, not through the CLI:

```text
Python core (domain, pipeline, storage)
        ↓
   REST API (FastAPI)
        ↓
  React SPA (web only)
```

- The API is the single place that serves knowledge-base data (sources,
  documents, document versions, controls, diffs) to clients.
- The frontend is a React single-page application, focused exclusively on
  the web (no mobile/native target). It consumes the REST API and holds no
  business logic of its own — that stays in the Python core.
- The CLI and the API both call into the same Python core packages
  (`invariant.collector`, `invariant.extractor`, ...) instead of duplicating
  logic; the CLI drives the pipeline, the API reads/exposes its results.

---

# 32. Initial Repository Structure

```text
invariant/
│
├── src/
│   └── invariant/
│       ├── domain/
│       ├── source/
│       ├── collector/
│       ├── extractor/
│       ├── normalizer/
│       ├── versioning/
│       ├── diff/
│       ├── notification/
│       ├── storage/
│       │   └── postgres/
│       ├── api/          (REST API — FastAPI)
│       └── cli/          (operator CLI — Typer)
│
├── frontend/              (React SPA, web only — to be created)
│
├── sql/
│   ├── schema/
│   └── queries/
│
├── docs/
│   ├── architecture/
│   ├── study-notes/
│   ├── decisions/
│   └── sources/
│
├── data/
│   └── raw/
│
├── tests/
│
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── LICENSE
└── CHANGELOG.md
```

This is a starting point, not a rigid constraint.

---

# 33. Initial Stack

Provisional:

```text
Language:
Python

API framework:
FastAPI

ASGI server:
Uvicorn

Frontend:
React (web only)

CLI:
Typer

HTTP client:
httpx

Database:
PostgreSQL

DB access:
SQL + psycopg (no ORM)

Migrations:
Alembic

Logging:
Python `logging` (stdlib)

Tests:
pytest

CI:
GitHub Actions

Container:
Docker

Notifications:
Telegram

Raw storage:
Filesystem first
S3-compatible later
```

Python references:

- https://docs.python.org/3/
- https://fastapi.tiangolo.com/
- https://react.dev/

---

# 34. Language Decision: Python

Invariant's initial implementation plan (see the earlier drafts of this
PRD) treated Go as an experiment, with Python as an explicit fallback if
Go became a disproportionate bottleneck. That fallback has been invoked:
the project now builds its logic entirely in Python, exposed through a
REST API (FastAPI) consumed by a React web frontend (see section 31).

Reasons for the switch:

- all business logic (pipeline, storage, versioning, diff, notification)
  should live in one language, reducing context-switching;
- a REST API + SPA delivery model fits Python's web ecosystem (FastAPI,
  Pydantic) more directly than it fit the Go skeleton;
- Python remains educational for this project across HTTP, file handling,
  hashing, parsing, database interaction, migrations, CLI design,
  concurrency, testing, structured logging and error handling — the same
  learning goals V0 originally set for Go.

Do not let the language choice destroy momentum.

---

# 35. AI Guardrails

## Rule 1 — Understand before implementing

AI should not jump directly from vague requirements to large code changes.

## Rule 2 — Explain before significant implementation

Ask the agent to explain:

- what;
- why;
- how;
- where;
- when;
- alternatives;
- trade-offs;
- failure modes;
- test plan.

## Rule 3 — No blind dependency installation

Every dependency needs a reason.

## Rule 4 — No fake expertise

If AI introduces SAST, DAST, SBOM, OPA, Falco, Trivy, Semgrep or another tool, the human must understand:

- what it is;
- why it is there;
- what it scans;
- where it runs;
- what it outputs;
- how failures appear.

## Rule 5 — Review generated code

AI-generated code must be reviewed before becoming project knowledge.

## Rule 6 — Test generated code

Generated code is not considered correct because it compiles.

## Rule 7 — Document meaningful decisions

If AI introduces an architectural decision, document the decision and rationale.

---

# 36. AI Knowledge Model

Use three internal categories:

### Green — understood

Can explain and operate it.

### Yellow — functional knowledge

Can use it and explain the main concepts but lacks deep expertise.

### Red — AI-added / not understood

Cannot explain what it does or why it exists.

Do not present red technologies as expertise until studied.

---

# 37. Security Boundaries

Invariant should distinguish:

```text
Assessment
≠
Pentest
≠
Exploit Framework
```

The future assessment engine should initially favor:

- configuration analysis;
- passive assessment;
- evidence gathering;
- controlled local labs;
- authorized targets.

Testing third-party infrastructure requires authorization.

The system should not claim that an environment is absolutely secure.

---

# 38. Commercialization — Future

Potential future services:

```text
Open Source
      │
      ▼
Community
      │
      ▼
Services
      │
 ┌────┼───────────────┐
 ▼    ▼               ▼
Audit Hardening   Deployment
      │               │
      └──────┬────────┘
             ▼
         Consulting
```

Possible future revenue:

- AWS assessments;
- infrastructure assessments;
- hardening;
- deployment;
- observability;
- custom rules;
- customer-specific integrations;
- continuous assessment.

Commercialization is **not** a V0/V1 requirement.

---

# 39. Open Source Strategy

The project should be public from the beginning.

Goals:

- transparent development;
- reproducibility;
- learning;
- portfolio evidence;
- external review;
- community contributions;
- potential professional opportunities.

Expected repository documents:

```text
README.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
SECURITY.md
CHANGELOG.md
LICENSE
```

Potential future:

```text
AGENTS.md
CLAUDE.md
docs/adr/
```

The open-source nature is also intended to allow people met through technical events to contribute.

---

# 40. Definition of Done — General

```text
✓ Requirement understood
✓ Architecture decided
✓ Implementation complete
✓ Tests exist
✓ Error handling considered
✓ Documentation updated
✓ Study Note created when useful
✓ AI-generated code reviewed
✓ Security implications considered
✓ Reproducibility considered
```

---

# 41. Definition of Done — Source Adapter

```text
✓ Source URL known
✓ Usage/license understood
✓ Collector implemented
✓ Raw artifact preserved
✓ Hash calculated
✓ Source metadata stored
✓ Publisher version stored when available
✓ Parser version stored
✓ Extraction tested
✓ Normalization tested
✓ Change detection tested
✓ Documentation written
```

---

# 42. Definition of Done — Future Finding

```text
✓ Stable ID
✓ Title
✓ Description
✓ Evidence definition
✓ Impact
✓ Recommendation
✓ Severity/classification
✓ Severity source
✓ Scoring system if applicable
✓ References
✓ Test case
✓ Remediation guidance
```

---

# 43. Metrics

Focus on engineering quality rather than lines of code.

Useful future metrics:

- supported sources;
- versioned documents;
- normalized controls;
- meaningful changes detected;
- parser reliability;
- extractor test coverage;
- notification latency;
- reproducibility;
- false-positive rate;
- contributors;
- documentation quality.

Avoid vanity metrics.

---

# 44. What Invariant Must Not Become

Invariant should not become:

- an AI-generated code dump;
- a pile of unrelated scanners;
- an enormous crawler with no stable data model;
- an AWS-only project;
- a generic pentest framework;
- copied benchmark content without provenance;
- a UI-first project with weak internals;
- a project whose architecture is dictated by AI.

Core value:

> **A trustworthy, versioned knowledge layer feeding explainable infrastructure assessment.**

---

# 45. Current Decision Snapshot

| Area | Decision |
|---|---|
| Project name | **Invariant** |
| Philosophy | **Human First** |
| AI | Accelerator, not authority |
| Study Notes | First-class |
| Primary language | **Python** |
| API delivery | REST API (FastAPI) |
| Frontend | React (web only) |
| Database | **PostgreSQL** |
| DB access | SQL + psycopg, no ORM, provisional |
| Raw documents | Files/object storage |
| First source | **CIS** |
| First benchmark | **CIS AWS Foundations** |
| OWASP | Later, one explicit project/document |
| NIST | Deferred |
| CVSS | Separate scoring system |
| First notifications | Telegram |
| Future assessment order | Linux → Docker → AWS → Kubernetes |
| Later | Terraform → Observability → Platform/SRE |
| Repository | Open source |
| Commercialization | Future |
| First milestone | Download and preserve a CIS artifact |

---

# 46. First Implementation Plan

Do not implement the entire PRD at once.

```text
Step 1
Create repository

Step 2
Create Python project (pyproject.toml)

Step 3
Create CLI skeleton

Step 4
Create source abstraction

Step 5
Implement CIS source

Step 6
Download raw artifact

Step 7
Calculate SHA-256

Step 8
Persist metadata

Step 9
Add PostgreSQL

Step 10
Add extraction

Step 11
Add normalization

Step 12
Add version tracking

Step 13
Add diff

Step 14
Add Telegram notification
```

The first useful commit can be extremely small:

```text
python -m invariant.cli.main fetch cis
```

Expected result:

```text
CIS
 ↓
Download
 ↓
Raw artifact
 ↓
SHA-256
 ↓
Metadata
```

---

# 47. Architecture Invariant

The project name is **Invariant**.

The central architectural idea is that the project should preserve invariants of knowledge provenance and reproducibility even when source formats or implementation details change.

At minimum:

```text
Every extracted fact
must be traceable to
a source
a document version
a raw artifact
a content hash
a parser version
and a collection event.
```

This is the foundation of trust.

---

# 48. Roadmap

```text
                    ┌──────────────┐
                    │      V0      │
                    │ Knowledge    │
                    │ Ingestion    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │     V0.1     │
                    │     CIS      │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │     V0.2     │
                    │  Versioning  │
                    │ Change Track │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │     V0.3     │
                    │ Notifications│
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │     V0.4     │
                    │ Multi-Source │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │      V1      │
                    │ Knowledge    │
                    │ Platform     │
                    └──────┬───────┘
                           │
                           ▼
                    Assessment Engine
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
          Linux          Docker           AWS
            │              │              │
            └──────────────┼──────────────┘
                           ▼
                       Kubernetes
                           │
                           ▼
                       Terraform
                           │
                           ▼
                     Observability
                           │
                           ▼
                     Platform / SRE
```

---

# 49. Consolidated References

## CIS

- https://downloads.cisecurity.org/#/
- https://www.cisecurity.org/cis-benchmarks
- https://www.cisecurity.org/benchmark/amazon_web_services
- https://workbench.cisecurity.org/

## FIRST / CVSS

- https://www.first.org/cvss/
- https://www.first.org/cvss/v4.0/specification-document
- https://www.first.org/cvss/user-guide.html

## OWASP

- https://owasp.org/API-Security/
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://owasp.org/API-Security/editions/2023/en/0x00-toc/
- https://github.com/OWASP/API-Security

## AWS

- https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html
- https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html

## Docker

- https://docs.docker.com/engine/security/
- https://docs.docker.com/engine/security/rootless/

## Kubernetes

- https://kubernetes.io/docs/
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/

## Terraform

- https://developer.hashicorp.com/terraform/docs
- https://developer.hashicorp.com/terraform/language

## PostgreSQL

- https://www.postgresql.org/docs/current/
- https://www.postgresql.org/docs/current/datatype-json.html
- https://www.postgresql.org/docs/current/textsearch-controls.html

## Python

- https://docs.python.org/3/
- https://fastapi.tiangolo.com/
- https://typer.tiangolo.com/
- https://www.psycopg.org/psycopg3/docs/

## React

- https://react.dev/

## GitHub

- https://docs.github.com/actions
- https://docs.github.com/code-security

---

# 50. Document Status

This PRD is a **living document**.

It records the pre-implementation decisions and design direction discussed for Invariant.

When implementation disproves an assumption:

```text
Observation
   ↓
Discussion
   ↓
Decision
   ↓
Update PRD
   ↓
ADR if architectural
   ↓
Implementation
```

The PRD should evolve with the project rather than becoming a frozen specification.

---

# Final Principles

> **Human First.**

> **AI can accelerate implementation. It cannot replace understanding.**

> **Do not build to appear that you know. Build until you know.**

> **Evidence over assumptions.**

> **Version the knowledge, not only the code.**

> **Preserve the original artifact.**

> **Separate publisher version, parser version and application version.**

> **Start narrow, design for extension.**

> **Do not let AWS become the architecture.**

> **Do not consume OWASP blindly.**

> **Do not force CVSS onto findings where it does not apply.**

> **Do not build the assessment engine before building a trustworthy knowledge layer.**

> **Every feature should leave the project better documented, better tested and better understood.**
