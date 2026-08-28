# Invariant: orientações para agentes

Última verificação: 2026-08-28. Se algo aqui divergir do código, dos testes
ou do histórico do Git, confie neles primeiro e corrija este arquivo.

## Estado atual

O projeto **não é mais um esqueleto**. Existe pipeline funcional, migrations
Alembic, assessment agentless via Docker, demo offline (`demo.sh`), API
FastAPI, SPA React e uma suite pytest ampla. Os pacotes `diff`, `versioning`
e `notification`, além de fontes AWS/FIRST/OWASP, ainda são futuros ou
placeholders. Se algum outro documento do repo (`CLAUDE.md` incluído)
disser o contrário, está desatualizado — confie no código.

## Princípios de trabalho

- Siga a filosofia Human First: explique decisões não óbvias, alternativas,
  riscos e como o resultado será provado.
- Prefira evidências do código, testes, manifests e histórico Git a
  afirmações antigas da documentação.
- Consulte `INVARIANT_PRD.md` para a visão e invariantes arquiteturais, mas
  confirme no código o que já está implementado.
- Trabalhe em incrementos pequenos, focados e testáveis. Não avance
  silenciosamente para etapas futuras do roadmap.
- Não adicione dependências sem justificar a necessidade e o trade-off.
- Preserve alterações preexistentes no worktree. Nunca descarte arquivos
  modificados pelo usuário.

## Invariantes de arquitetura

- Preserve a rastreabilidade completa: Source -> Document -> Document
  Version -> Raw Artifact/hash/timestamp -> Extracted Item -> Control ->
  Finding/Evidence.
- Mantenha separados publisher version, parser version e
  application/collector version.
- PostgreSQL usa SQL manual com psycopg; não introduza ORM sem uma decisão
  arquitetural explícita.
- `src/invariant/assessment/facts.py` é o único lugar que deve conversar
  com targets. Checks avaliam `SystemFacts` em Python e não executam
  comandos individualmente.
- Um check precisa corresponder a um controle CIS real e produzir evidência
  verificável. Nunca invente vulnerabilidades, resultados ou suporte que
  não existe.
- O frontend consome a API; não mova lógica de negócio para React nem
  acesse o banco diretamente.
- Decisões arquiteturais não óbvias devem ser registradas em
  `docs/decisions/` ou, quando forem aprendizado investigativo, em
  `docs/study-notes/`.

## Arquitetura implementada

```text
CIS source adapter
  -> collector (PDF + sidecar + SHA-256)
  -> extractor (recomendações CIS)
  -> PostgreSQL (sources/documents/versions/extracted_items)
  -> normalizer (controls)
  -> assessment (SystemFacts por docker exec + checks Python)
  -> demo report/status JSON
  -> FastAPI read-only
  -> React/Vite
```

Arquivos-chave:

- CLI e comandos: `src/invariant/cli/main.py`, `fetch.py`, `extract.py`,
  `import_document.py`, `assess.py`.
- Fonte CIS: `src/invariant/source/__init__.py`.
- Pipeline: `src/invariant/collector/__init__.py`, `extractor/__init__.py`,
  `normalizer/__init__.py`.
- Persistência: `src/invariant/storage/postgres/__init__.py`,
  `sql/queries/`, `sql/schema/`, `sql/migrations/`.
- Assessment: `src/invariant/assessment/__init__.py`, `facts.py`,
  `suggestions.py`.
- Demo: `demo.sh`, `scripts/demo/`, `infra/docker-compose.demo.yml`.
- API: `src/invariant/api/main.py`.
- Frontend: `frontend/src/App.jsx` e `frontend/src/App.css`.
- CI/CD: `.github/workflows/ci.yml`, `guard-main-source.yml`, `deploy.yml`.

## Entry points e limites atuais

- `invariant` chama `invariant.cli.main:main` via Typer.
- Comandos funcionais principais: `fetch`, `extract`, `import_document`,
  `assess`.
- `diff`, `check_updates` e `notify` estão registrados, mas ainda são
  stubs/TODO.
- A API atual expõe `/healthz`, `/api/demo/status`, `/api/demo/runs` e
  `/api/demo/runs/latest`.
- A API lê `data/demo/status.json` e `runs.jsonl`; ela não oferece ainda a
  API REST ampla descrita no PRD.
- Produção não inclui PostgreSQL no compose. A API lê `data/demo` montado
  como read-only; a atualização da demo ocorre separadamente no host.

## Setup e comandos

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e '.[dev]'
playwright install chromium
cp .env.example .env
docker compose -f infra/docker-compose.yml up -d postgres adminer
alembic upgrade head
make run-api
invariant --help
```

Frontend:

```bash
cd frontend
npm ci
npm run dev
npm run lint
npm run build
```

Testes:

```bash
pytest
pytest tests/collector/
pytest tests/assessment/test_evaluators.py -v
```

- Backend: `pytest` ou o menor subconjunto relevante. A suite completa de
  assessment pode exigir PostgreSQL, migrations, documentos CIS importados
  e containers Docker.
- Banco: o comando real é `alembic upgrade head`; `make migrate-up` ainda é
  placeholder.
- Não rode `fetch` CIS durante testes comuns: ele pode exigir credenciais e
  rede. Prefira os PDFs/sidecars locais versionados.

A CI usa Python 3.12, PostgreSQL 16, Chromium do Playwright, seis
containers reais de assessment e seis documentos CIS locais antes de
executar `pytest`. O job frontend usa Node 20, `npm ci`, lint e build.
Testes marcados `integration` podem exigir Docker e banco populado.

## Demo

`./demo.sh [--seed N]` executa uma demo offline em nove etapas. Ela exige
previamente Docker, CLI/Alembic, PDFs locais e imagens demo construídas. O
script sobe Postgres/Adminer e seis alvos (um baseline hardened + cinco
alvos problemáticos), recria os cinco alvos problemáticos, injeta
misconfigs, migra/importa, avalia e grava `data/demo/*`. A narrativa
impressa (nomes de etapa, resumo final) está em português, pensada pra ser
mostrada ao vivo num pitch.

O baseline hardened só falha nos poucos controles genuinamente impossíveis
dentro de um container Docker sem privilégios (ver
`scripts/demo/misconfig_catalog.py`'s `CONTAINER_IMPOSSIBLE_TITLES`);
`facts.py` tem um fato novo (`is_running_in_container`) que só aplica essa
desculpa "ambiental" quando o alvo é de fato detectado como container --
numa máquina real o mesmo título seria uma falha normal.

Ao alterar os nomes das etapas da demo, sincronize `demo.sh` e
`frontend/src/App.jsx` (`DEMO_STEPS` precisa bater exatamente com as
strings de `section()` em `demo.sh`).

Preparação que pode precisar de rede:

```bash
docker compose -f infra/docker-compose.demo.yml build
```

## Convenções

- Python >= 3.11, PEP 8, `snake_case` para módulos/funções/variáveis,
  `PascalCase` para classes e `UPPER_SNAKE_CASE` para constantes.
- Prefira biblioteca padrão e código explícito quando forem suficientes.
- Preserve e explique o comportamento fail-closed dos checks de segurança.
- Nunca exponha valores de `.env`; documente apenas nomes de variáveis
  presentes em `.env.example`.

## Armadilhas conhecidas

- Não altere artefatos CIS em `data/raw/cis/` ou seus sidecars sem entender
  as exceções documentadas em `.gitignore`.
- `fetch` pode precisar de `CIS_EMAIL`, `CIS_USERNAME`, `CIS_PASSWORD`,
  rede e Playwright. Veja
  `docs/study-notes/python/cis-source-download-bugs.md`.
- `DATABASE_URL` do compose local usa a porta host 5435; a CI usa 5432.
  Prefira `.env.example` e os composes atuais a textos antigos.
- `INVARIANT_API_CORS_ORIGINS` aceita origens separadas por vírgula;
  `VITE_API_BASE` é definido no build do Vite.
- O deploy requer a rede Docker externa `vps-proxy`. O nginx do frontend
  não faz proxy de `/api`; o roteamento same-origin depende do proxy
  externo.
- O workflow de deploy usa `git reset --hard` no checkout do runner de
  produção -- e esse checkout é o mesmo diretório usado como workspace de
  desenvolvimento nesta VPS. Qualquer coisa não commitada nesse diretório
  no momento de um deploy é descartada. Nunca replique esse `reset --hard`
  manualmente no worktree do usuário, e commit/push antes de deixar
  trabalho em progresso.
- Checks coletam um snapshot amplo em um único `docker exec` por meio de
  `facts.py`. Mantenha essa fronteira.
- Comandos CIS em texto livre não devem ser executados genericamente.
  `suggestions.py` apenas sugere candidatos; revisão humana e implementação
  explícita são obrigatórias.
- `docs/architecture/checks.md` registra gaps estruturais de containers e
  detalhes como o comportamento de primeira ocorrência de `sshd -T`.

## Checklist antes de entregar mudanças

1. Confirme o estado atual com `git status --short` e preserve mudanças
   alheias.
2. Leia os testes e documentos próximos do componente alterado.
3. Mantenha rastreabilidade e evidência verificável.
4. Rode a menor validação relevante e amplie conforme o risco.
5. Registre decisões arquiteturais não óbvias.
6. Informe claramente o que foi validado e o que depende de infraestrutura
   externa.
