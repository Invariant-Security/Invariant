#!/usr/bin/env bash
# demo.sh -- demo ao vivo, um botão só, 100% offline, pra apresentação a
# investidores/aceleradora. Tudo que precisa já tem que estar no repo ou
# construído localmente como imagem Docker antes da hora (ver preflight
# abaixo) -- sem internet, sem IA, nada instalado ao vivo.
#
# O que faz, em ordem:
#   1. Preflight: docker + CLI invariant + alembic + as duas imagens
#      hardened precisam já estar disponíveis. Aborta com mensagem clara em
#      vez de tentar consertar algo ao vivo.
#   2. Sobe postgres + adminer só do infra/docker-compose.yml *existente*
#      (nunca alterado por este script) -- os 6 containers de dev/teste
#      ficam parados, não fazem parte da demo.
#   3. Sobe os 6 containers da demo a partir do
#      infra/docker-compose.demo.yml isolado, recriando à força os 5
#      containers "problema" pra cada rodada começar de uma imagem limpa.
#   4. Espera (loop curto, sem sleep longo) até os 6 responderem a
#      `docker exec ... true`.
#   5. Aplica aleatoriamente 2-3 misconfigurações em cada um dos 5
#      containers-problema (scripts/demo/apply_misconfigs.py) e salva o
#      manifesto.
#   6. `alembic upgrade head` (idempotente, só no banco local).
#   7. `invariant extract`/`invariant import_document` pros dois documentos
#      CIS da demo (lê PDFs locais em data/raw/, sem rede).
#   8. `invariant assess --target ...` pros 6 containers da demo -- o
#      comando real do pipeline, rodando ao vivo.
#   9. Um resumo final que reimprime o manifesto ao lado dos resultados do
#      assess, separando cada FAIL entre "ambiental" (limitação genuína de
#      rodar em container, só quando o alvo é de fato detectado como
#      container -- ver docs/architecture/checks.md) e "história de hoje"
#      (bate com uma misconfiguração aplicada nesta rodada).
#
# Repetível: rodar de novo reseta os 5 containers-problema e sorteia um
# conjunto novo de misconfigurações. Sem rede necessária depois do primeiro
# build de imagem.
#
# Uso: ./demo.sh [--seed N]
#   --seed N   Fixa a semente do sorteio de scripts/demo/apply_misconfigs.py
#              pra um manifesto reprodutível (padrão: sorteio aleatório a
#              cada rodada).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SEED_ARGS=()
SEED_VALUE=""
if [[ "${1:-}" == "--seed" ]]; then
    if [[ -z "${2:-}" ]]; then
        echo "ERRO: --seed precisa de um valor" >&2
        exit 1
    fi
    SEED_ARGS=(--seed "$2")
    SEED_VALUE="$2"
fi

DEMO_COMPOSE="infra/docker-compose.demo.yml"
DEV_COMPOSE="infra/docker-compose.yml"

HARDENED_CONTAINER="invariant-demo-ubuntu-hardened"
PROBLEM_CONTAINERS=(invariant-demo-debian-1 invariant-demo-debian-2 invariant-demo-debian-3 invariant-demo-ubuntu-1 invariant-demo-ubuntu-2)
PROBLEM_SERVICES=(demo-debian-1 demo-debian-2 demo-debian-3 demo-ubuntu-1 demo-ubuntu-2)
ALL_DEMO_CONTAINERS=("$HARDENED_CONTAINER" "${PROBLEM_CONTAINERS[@]}")

MANIFEST_DIR="data/demo"
MANIFEST_JSON="$MANIFEST_DIR/manifest.json"
MANIFEST_LOG="$MANIFEST_DIR/manifest_output.txt"
REPORT_JSON="$MANIFEST_DIR/last_report.json"
STATUS_JSON="$MANIFEST_DIR/status.json"
RUNS_JSONL="$MANIFEST_DIR/runs.jsonl"

# Um run_id + started_at por execução (timestamp + PID já é único o
# suficiente pra uma ferramenta de demo local de um operador só -- um UUID
# de verdade seria uma dependência nova sem benefício real aqui). Uma
# chamada a `date` cada é tranquilo -- diferente da instrumentação de
# tempo por etapa abaixo, isso não está no caminho quente e não precisa da
# precisão de subsegundo do EPOCHREALTIME.
RUN_ID="$(date -u +%Y%m%dT%H%M%S)-$$"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

fail() {
    echo "ERRO: $1" >&2
    exit 1
}

# --- Instrumentação de tempo/progresso ---------------------------------
# Envolve cada uma das 9 etapas do pipeline abaixo com um horário de início
# (EPOCHREALTIME do próprio bash, sem processo `date` externo) pra que,
# quando a próxima etapa começar (ou o script terminar), a etapa anterior
# seja impressa como concluída, com o tempo gasto -- e pra que a duração de
# cada etapa entre num resumo final. Puramente de apresentação: nenhuma
# lógica/ordem real do pipeline é alterada por isso.

declare -a STEP_NAMES=()
declare -a STEP_DURATIONS_US=()
CURRENT_STEP_NAME=""
CURRENT_STEP_START=""

COLOR_GREEN=""
COLOR_RESET=""
if [[ -t 1 ]]; then
    COLOR_GREEN=$'\033[0;32m'
    COLOR_RESET=$'\033[0m'
fi

# Formata uma contagem inteira de microssegundos como um número simples
# "N.T" (uma casa decimal), usando só aritmética inteira do bash -- sem
# precisar de bc/awk/date.
format_duration_number() {
    local us="$1"
    local whole=$(( us / 1000000 ))
    local frac=$(( (us / 100000) % 10 ))
    printf '%d.%d' "$whole" "$frac"
}

# Igual, mas como string legível "N.Ts" pra saída no terminal.
format_duration() {
    printf '%ss' "$(format_duration_number "$1")"
}

# Sobrescreve data/demo/status.json com o estado ao vivo da rodada: qual
# etapa está rodando agora (vazio quando termina), cada etapa concluída até
# agora com sua duração, run_id e started_at. É isso que uma futura UI de
# progresso ao vivo consulta -- este script só precisa manter isso correto
# a cada ponto da execução.
write_status_json() {
    local current="$1"
    local finished="$2"
    mkdir -p "$MANIFEST_DIR"
    {
        printf '{\n'
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "started_at": "%s",\n' "$STARTED_AT"
        if [[ -n "$current" ]]; then
            printf '  "current_step": "%s",\n' "$current"
        else
            printf '  "current_step": null,\n'
        fi
        printf '  "finished": %s,\n' "$finished"
        printf '  "completed_steps": [\n'
        local i n=${#STEP_NAMES[@]}
        for i in "${!STEP_NAMES[@]}"; do
            local sep=","
            [[ "$i" -eq $((n - 1)) ]] && sep=""
            printf '    {"name": "%s", "duration_seconds": %s}%s\n' \
                "${STEP_NAMES[$i]}" "$(format_duration_number "${STEP_DURATIONS_US[$i]}")" "$sep"
        done
        printf '  ]\n'
        printf '}\n'
    } > "$STATUS_JSON"
}

# Fecha a etapa que está rodando no momento (se houver): registra sua
# duração e imprime um check verde + tempo decorrido. Chamado tanto quando
# a próxima section() começa quanto uma última vez no fim do script.
finish_current_step() {
    if [[ -n "$CURRENT_STEP_NAME" ]]; then
        local end="$EPOCHREALTIME"
        local start_us="${CURRENT_STEP_START/./}"
        local end_us="${end/./}"
        local diff_us=$(( 10#$end_us - 10#$start_us ))

        STEP_NAMES+=("$CURRENT_STEP_NAME")
        STEP_DURATIONS_US+=("$diff_us")

        local dur
        dur=$(format_duration "$diff_us")
        printf '%s\xe2\x9c\x94 %-38s%s%s\n' "$COLOR_GREEN" "$CURRENT_STEP_NAME" "$COLOR_RESET" "$dur"
    fi
    return 0
}

# Imprime a tabela final de tempo por etapa + total -- deixa claro onde o
# script gastou mais tempo, independente do resto.
print_timing_summary() {
    echo
    echo "Resumo de tempo"
    echo "------------------------------------------------------------"
    local total_us=0
    local i
    for i in "${!STEP_NAMES[@]}"; do
        printf '%-45s %8s\n' "${STEP_NAMES[$i]}" "$(format_duration "${STEP_DURATIONS_US[$i]}")"
        total_us=$(( total_us + STEP_DURATIONS_US[i] ))
    done
    echo "------------------------------------------------------------"
    printf '%-45s %8s\n' "Total" "$(format_duration "$total_us")"
}

section() {
    finish_current_step
    CURRENT_STEP_NAME="$1"
    CURRENT_STEP_START="$EPOCHREALTIME"
    write_status_json "$CURRENT_STEP_NAME" false
    echo
    echo "==> $1"
}

# --- 1. Preflight -----------------------------------------------------
section "Verificações iniciais"

docker info >/dev/null 2>&1 \
    || fail "docker não está disponível/rodando. Prepare isso antes da apresentação -- não dá pra corrigir ao vivo sem internet."

command -v invariant >/dev/null 2>&1 \
    || fail "CLI 'invariant' não encontrada no PATH. Ative o venv do projeto (ver README) antes da apresentação."

command -v alembic >/dev/null 2>&1 \
    || fail "'alembic' não encontrado no PATH. Ative o venv do projeto (ver README) antes da apresentação."

for image in demo-debian-hardened:latest demo-ubuntu-hardened:latest; do
    docker image inspect "$image" >/dev/null 2>&1 \
        || fail "Imagem Docker '$image' não construída localmente. Construa antes: docker compose -f $DEMO_COMPOSE build (precisa de rede uma vez, antes da apresentação)."
done

for doc_pdf_glob in "data/raw/cis/debian/cis_debian_linux_11_"*.pdf "data/raw/cis/ubuntu/cis_ubuntu_20_04_"*.pdf; do
    [[ -f "$doc_pdf_glob" ]] \
        || fail "PDF do CIS ausente: $doc_pdf_glob -- prepare isso antes da apresentação, o extract/import precisa dele."
done

echo "OK: docker, invariant, alembic, as duas imagens hardened e os dois PDFs da demo, tudo presente."

# --- 2. Só o banco do stack de dev (deixa os 6 containers de dev/teste parados) ---
section "Subindo postgres + adminer (infra/docker-compose.yml, só banco)"
docker compose -f "$DEV_COMPOSE" up -d postgres adminer

# --- 3. Containers da demo (compose isolado) -------------------
section "Subindo os 6 containers da demo ($DEMO_COMPOSE)"
docker compose -f "$DEMO_COMPOSE" up -d
# Ensaio idempotente: reseta só os 5 containers "problema" pra uma imagem
# limpa a cada rodada, independente de qualquer misconfiguração de uma
# rodada anterior.
docker compose -f "$DEMO_COMPOSE" up -d --force-recreate "${PROBLEM_SERVICES[@]}"

# --- 4. Espera ativa (sem sleep longo) ------------------------------------
section "Esperando os 6 containers da demo responderem"
wait_for_container() {
    local name="$1"
    local max_attempts=30
    local attempt=0
    until docker exec "$name" true >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [[ "$attempt" -ge "$max_attempts" ]]; then
            fail "container $name não ficou pronto depois de ${max_attempts}s"
        fi
        sleep 1
    done
    echo "  $name: pronto"
}
for c in "${ALL_DEMO_CONTAINERS[@]}"; do
    wait_for_container "$c"
done

# --- 5. Aplica misconfigurações aleatórias nos 5 containers-problema -------------
section "Aplicando misconfigurações (scripts/demo/apply_misconfigs.py)"
mkdir -p "$MANIFEST_DIR"
python scripts/demo/apply_misconfigs.py "${SEED_ARGS[@]}" | tee "$MANIFEST_LOG"

# --- 6. Migra o banco (idempotente) -----------------------------------------
section "Aplicando migrações do banco (alembic upgrade head)"
alembic upgrade head

# --- 7. Extrai + importa os dois documentos CIS da demo (só PDFs locais) --
section "Extraindo + importando os dois documentos CIS da demo"
for doc in cis-debian-linux-11 cis-ubuntu-linux-20-04; do
    echo "-- $doc --"
    invariant extract "$doc"
    invariant import_document "$doc"
done

# --- 8. Avalia os 6 containers da demo -------------------------------------
section "Avaliando os 6 containers da demo (invariant assess)"
invariant assess \
    --target "$HARDENED_CONTAINER" \
    --target "${PROBLEM_CONTAINERS[0]}" \
    --target "${PROBLEM_CONTAINERS[1]}" \
    --target "${PROBLEM_CONTAINERS[2]}" \
    --target "${PROBLEM_CONTAINERS[3]}" \
    --target "${PROBLEM_CONTAINERS[4]}"

# --- 9. Resumo final: manifesto + ambiental vs história de hoje --------
section "Resumo final: manifesto de misconfigurações vs resultado do assess"
echo "--- Manifesto de misconfigurações (da etapa 5) ---"
cat "$MANIFEST_LOG"

echo "--- Classificação dos FAILs: ambiental vs história de hoje ---"
python scripts/demo/report.py \
    "$HARDENED_CONTAINER" "${PROBLEM_CONTAINERS[@]}" \
    --manifest "$MANIFEST_JSON" \
    --json-out "$REPORT_JSON"

finish_current_step
write_status_json "" true

echo
echo "==> Concluído"
echo "demo.sh terminou. Pode rodar de novo quando quiser -- os 5 containers-problema resetam e sorteiam novas misconfigurações automaticamente."

# Adiciona uma linha em runs.jsonl pra esta rodada concluída: run_id, tempo
# (por etapa + total), seed (se houver), e a saída completa de
# build_report() já escrita em $REPORT_JSON acima. Mantido como um scriptzinho
# inline (não uma função de report.py) já que é só encanamento de arquivo
# JSON sobre dados que os dois arquivos já têm -- não faz parte da lógica de
# classificação de FAIL, então não há nada aqui que valha testar além do que
# test_report.py já cobre pro próprio build_report().
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python - "$STATUS_JSON" "$REPORT_JSON" "$RUNS_JSONL" "$FINISHED_AT" "$SEED_VALUE" <<'PYEOF'
import json
import sys
from pathlib import Path

status_path, report_path, runs_path, finished_at, seed = sys.argv[1:6]

status = json.loads(Path(status_path).read_text())
report = json.loads(Path(report_path).read_text())

steps = status["completed_steps"]
total_duration = round(sum(s["duration_seconds"] for s in steps), 1)

record = {
    "run_id": status["run_id"],
    "started_at": status["started_at"],
    "finished_at": finished_at,
    "seed": int(seed) if seed else None,
    "steps": steps,
    "total_duration_seconds": total_duration,
    "report": report,
}

with open(runs_path, "a") as f:
    f.write(json.dumps(record) + "\n")
PYEOF

print_timing_summary
