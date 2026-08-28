# Contributing to Invariant

Fluxo de branches e PRs deste repo, do jeito que ele é realmente aplicado
hoje (por CI + rulesets do GitHub, não por convenção informal).

## As duas branches protegidas

- **`dev`** — branch de integração. Todo trabalho novo (feature, fix, o que
  for) entra aqui primeiro, via PR.
- **`main`** — branch de produção. `push` nela dispara `deploy.yml`
  automaticamente no runner self-hosted da VPS. **Só aceita PR vindo de
  `dev`** — qualquer outra origem é bloqueada pelo check `guard`
  (`.github/workflows/guard-main-source.yml`), sem exceção e sem bypass
  possível (nem por admin — ver "Regras que não têm atalho" abaixo).

```
feature/minha-branch --PR--> dev --PR--> main --push--> deploy (produção)
```

## Criar uma branch e abrir PR pra dev

```bash
git checkout dev && git pull
git checkout -b minha-branch
# ... commits ...
gh pr create --base dev --head minha-branch
```

Checks que rodam (`.github/workflows/ci.yml`, dispara em PR e push pra
`dev`/`main`):

- **`test`** (obrigatório no ruleset `protect-dev`) — sobe Postgres +
  6 containers reais de assessment (`infra/docker-compose.yml`), roda
  `alembic upgrade head`, importa os 6 documentos CIS que os testes
  avaliam contra, depois `pytest` completo. Não é mockado, então demora
  (~5-7 min).
- **`frontend`** — `npm ci && npm run lint && npm run build` em `frontend/`.
  Roda em todo PR mas não é um check obrigatório no ruleset de `dev`.

## De `dev` pra `main` (release)

```bash
gh pr create --base main --head dev
```

Precisa de: check `test` verde, check `guard` verde (confirma que a origem
é `dev`) e **1 aprovação humana** (`protect-main` exige
`required_approving_review_count: 1`; qualquer push novo derruba aprovações
antigas — `dismiss_stale_reviews_on_push`). Uma vez mesclado, `deploy.yml`
roda sozinho: `git reset --hard` na cópia de produção pro `FETCH_HEAD` de
`main`, rebuild e `docker compose up -d --build --wait` em
`deploy/docker-compose.prod.yml`. Falha de deploy imprime
`docker compose logs --tail=80` no job.

**Cuidado**: o diretório de deploy em produção é o mesmo caminho usado como
workspace de desenvolvimento nesta VPS. O `git reset --hard` do deploy
descarta qualquer coisa não commitada nesse diretório no momento do
deploy — commit e push antes de deixar trabalho em progresso por aí.

## PRs abertos por agente de IA (Codex, Claude, etc.)

Os dois rulesets (`protect-dev` e `protect-main`) têm
`require_extra_approval_for_unattributed_changes: true` — um PR com commits
"não atribuídos" (autoria de agente/bot, não uma conta humana verificada)
**exige pelo menos 1 aprovação humana antes do merge liberar**, mesmo que
`protect-dev` normalmente peça 0 aprovações. Isso é proposital: nenhum
agente pode aprovar o próprio PR pra contornar essa regra —
`bypass_actors` está vazio nos dois rulesets e
`current_user_can_bypass: never` vale até pra admin. Se um PR desses ficar
`BLOCKED` com todos os checks verdes e `reviewDecision: REVIEW_REQUIRED`, é
isso: precisa de um humano clicar "Approve" no GitHub, não tem comando que
resolva. E o GitHub nunca deixa aprovar o próprio PR — se o autor for a
única pessoa disponível, a saída (documentada, usada mais de uma vez neste
repo sob pressão de prazo) é desligar temporariamente a exigência de review
via API (`gh api -X PUT repos/OWNER/REPO/rulesets/RULESET_ID ...`), mesclar,
e religar imediatamente depois — nunca deixar desligado.
