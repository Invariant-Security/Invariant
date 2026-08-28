# invariant
Plataforma de ingestão, versionamento e rastreabilidade de diretrizes de segurança. Um laboratório de engenharia focado no pipeline de dados, unindo rigor técnico, aprendizado contínuo e a filosofia "Human First". Construído com Python, PostgreSQL e foco em evidências, entregando os dados via API REST para um frontend em React.

# Invariant 🛡️

![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-V0%20(WIP)-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

> Uma plataforma de ingestão de conhecimento de segurança, rastreabilidade e versionamento contínuo.

O **Invariant** não é apenas um scanner de segurança; é um pipeline de aquisição de dados focado em extrair, normalizar e versionar diretrizes de segurança (como CIS Benchmarks, CVSS, AWS Security Pillar) para garantir que o seu ambiente seja auditado contra uma "Fonte da Verdade" confiável e rastreável.

---

## 🧠 Filosofia e Princípios Essenciais

### A Filosofia Central: Human First
É a regra inegociável e a base de todo o projeto. A premissa é clara: **a IA pode propor e acelerar a implementação, mas o humano entende, questiona, decide, revisa, testa e documenta.**

### Core Principles
1. **Build until you understand:** *"Não construa para parecer que sabe. Construa até saber."*
2. **AI is an accelerator, not an authority:** A IA serve para *pair programming* e pesquisa, mas o código gerado deve ser compreendido pelo autor antes de ser aceito.
3. **Evidence over assumptions:** Não inventar vulnerabilidades, impactos de negócio ou fingir expertise sobre ferramentas que não rodam de verdade no ambiente.
4. **Small increments:** O desenvolvimento deve focar em resolver um problema por vez, gerando uma mudança focada e um resultado testável.

---

## 🛠️ Stack Tecnológico e Arquitetura

O projeto utiliza ferramentas robustas com foco em performance e aprendizado profundo de engenharia:
- **Linguagem:** Python
- **Banco de Dados:** PostgreSQL
- **Acesso a Dados:** SQL puro via psycopg (fugindo de ORMs para forçar o domínio de SQL real)
- **CLI Framework:** Typer (para comandos internos de pipeline como `fetch`, `diff`, etc.)
- **API:** REST API com FastAPI, responsável por entregar os dados ao frontend
- **Frontend:** React (SPA focado exclusivamente em web)

---

## 📏 Padrão de Código

O projeto segue [PEP 8](https://peps.python.org/pep-0008/), o guia de estilo oficial do Python, como fundação de nomenclatura e estilo:

- Módulos, pacotes, funções e variáveis: `snake_case`.
- Classes: `PascalCase`.
- Constantes: `UPPER_SNAKE_CASE`.

Essa convenção vale para o repositório inteiro, não só para arquivos `.py` (ex: nomes de arquivos dentro de `docs/`) — a única exceção é quando uma ferramenta específica exige um nome fixo diferente. Exemplos já presentes neste repositório:

- `README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md` — nomes reconhecidos pelo próprio GitHub (community health files) para render automático na UI.
- `Makefile`, `pyproject.toml` — nomes exigidos literalmente pelas ferramentas (`make`, `pip`/`hatchling`).

---

## 🗺️ Roadmap e Milestones

O desenvolvimento é incremental, garantindo a maturidade da camada de dados antes da construção do Assessment Engine (scanner):

* **V0 — Knowledge Ingestion Foundation:** Fundação da plataforma. Estabelecimento do pipeline básico de coleta, extração e normalização.
* **V0.1 — CIS:** Primeiro alvo do sistema, focado exclusivamente no *CIS AWS Foundations Benchmark*.
* **V0.2 — Versioning & Change Tracking:** Capacidade de preservar histórico, separando a versão do documento, do parser e da aplicação.
* **V0.3 — Notifications (Notificações):** Alertas (ex: Telegram) ao detectar alterações significativas na base de conhecimento.
* **V0.4 — Multiple Sources (Múltiplas Fontes):** Expansão do pipeline integrando FIRST/CVSS, AWS Security Pillar e relatórios OWASP.

---

## ⚙️ Pré-requisitos

Para rodar o Invariant localmente, você precisará de:
- [Python 3.11+](https://www.python.org/downloads/)
- [Docker](https://www.docker.com/) e Docker Compose (sobe o PostgreSQL local, o Adminer e os containers-alvo da demo bxsec)
- [Node.js](https://nodejs.org/) (para o frontend em React, quando ele existir)
- *Recomendado: `make` para os atalhos de comando.*

> A branch `bxsec` já tem um pipeline funcional (fetch → extract → import → assess) sobre benchmarks CIS Debian/Ubuntu — as instruções abaixo refletem esse estado. O restante do projeto (main) ainda é um esqueleto, ver seção "O que este projeto é" no `CLAUDE.md`.

---

## 🚀 Quickstart

1. **Clone o repositório e entre na branch de trabalho:**
   ```bash
   git clone https://github.com/VictorDG00/invariant.git
   cd invariant
   git checkout bxsec
   ```

2. **Baixe as dependências (ambiente virtual + extras de dev):**
   ```bash
   python -m venv venv && source venv/bin/activate
   make install          # == pip install -e ".[dev]"
   ```

3. **Configure as variáveis de ambiente:**
   ```bash
   cp .env.example .env
   ```
   `DATABASE_URL` já vem preenchido com as credenciais que batem com o `docker-compose.yml` local. `CIS_EMAIL`/`CIS_USERNAME`/`CIS_PASSWORD` só são necessários se for baixar benchmarks novos direto do CIS WorkBench.

4. **Suba a infra local (PostgreSQL + Adminer + containers-alvo da demo):**
   ```bash
   docker compose -f infra/docker-compose.yml up -d
   ```
   Adminer fica em http://localhost:8080 (System: PostgreSQL, Server: `postgres`, usuário/senha/DB conforme `.env`).

5. **Aplique as migrations do banco:**
   ```bash
   alembic upgrade head
   ```

6. **Rode o CLI:**
   ```bash
   invariant --help
   # ou, sem instalar o entry point:
   python -m invariant.cli.main --help
   ```

---

## 💻 Como Usar (Usage)

Pipeline completo para um documento CIS já baixado (ver `data/raw/cis/`) ou para baixar um novo:

```bash
invariant fetch cis-debian-linux-10        # baixa o PDF, calcula SHA-256, salva em data/raw/cis/debian/
invariant extract cis-debian-linux-10      # faz o parse do PDF e persiste extracted_items
invariant import_document cis-debian-linux-10   # normaliza extracted_items em controls
```

Para rastrear e baixar **todos os PDFs Debian e Ubuntu atualmente publicados** no catálogo público do CIS:

```bash
invariant fetch cis
```

O crawler descobre produtos, documentos e versões diretamente em `downloads.cisecurity.org`; não usa login nem depende das versões fixadas para a quickdemo. Os artefatos são preservados por SHA-256, portanto versões e conteúdos diferentes coexistem sem sobrescrever o histórico.

Também é possível buscar apenas a versão mais recente de um documento conhecido, por exemplo `invariant fetch cis-debian-linux-13`. As chaves compatíveis ficam em `source.KNOWN_CIS_DOCUMENTS` (`src/invariant/source/__init__.py`).

Rodar a avaliação (demo bxsec) contra os containers Docker-alvo:
```bash
invariant assess
```
Isso executa os controles importados contra os 6 containers definidos em `infra/docker-compose.yml` (baseline/ssh-bad/permissions-bad × debian/ubuntu) e imprime um resumo PASS/FAIL, com a cadeia completa de evidência (Finding → Control → Source → Document Version) para cada FAIL.

Rodar a API REST:
```bash
make run-api    # == uvicorn invariant.api.main:app --reload
```

Rodar os testes:
```bash
make test       # == pytest
pytest tests/collector/                          # um pacote específico
pytest tests/collector/test_collector.py::test_name -v  # um teste específico
```

---

## 📂 Estrutura de Diretórios (Destaques)

```text
invariant/
├── src/invariant/      # Lógica de negócio, API REST (FastAPI) e CLI (Typer)
├── sql/                # Queries SQL brutas, schema e migrations (Alembic)
├── infra/              # docker-compose.yml (Postgres, Adminer, containers-alvo da demo bxsec)
├── data/raw/cis/       # Artefatos brutos (PDF) baixados dos benchmarks CIS
│   ├── debian/         #   só os .pdf são versionados no git; o sidecar .json
│   └── ubuntu/         #   (metadata/hash/timestamp) é gerado e ignorado a cada fetch
├── frontend/           # SPA em React (a ser criado)
└── docs/
    └── study-notes/    # 🧪 Laboratório de estudos e notas de arquitetura. O código é produto do aprendizado documentado aqui.
```

---

## 🤝 Como Contribuir

Contribuições são bem-vindas, desde que respeitem a regra **Human First**. Pull Requests devem vir acompanhados de explicações claras sobre *por que* e *como* o código funciona. Códigos 100% gerados por IA sem curadoria humana não serão aceitos.

---

## 📄 Licença

Este projeto é licenciado sob a licença [MIT](LICENSE).