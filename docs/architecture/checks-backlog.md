# Checks backlog: o que falta implementar, e por quê

Levantamento feito em 2026-08-27 contra o Postgres (documentos CIS já importados),
depois dos 142 `CHECKS` existentes em `src/invariant/assessment/__init__.py`.

**Atualização (round 4, mesmo dia)**: Grupos A + A2 (25 candidatos) foram implementados
via 4 subagents paralelos -- 23 de 25 entraram (`CHECKS` foi de 142 para 165); 2 foram
descartados durante a implementação depois de uma leitura mais funda do audit real:
"Ensure use of privileged commands are collected" (exigiria enumerar SUID/SGID
dinamicamente, não é determinístico) e "Ensure access to all logfiles has been
configured" (drift real de condição em debian_linux_11, mesma categoria do caso
ip-forwarding). Os 23 novos checks foram validados contra os 6 containers de CI reais;
16 deles falham sistemicamente nos 6 (nenhum Dockerfile configura regra de auditoria,
chrony/systemd-timesyncd, ou auditd.conf além do default) -- documentado em
`tests/assessment/test_assess_target.py`'s `_ROUND4_GAP_BY_DOCUMENT`. Grupos B, C e D
abaixo continuam como estavam (não mexidos nesta rodada).

## Números

- **468** controles reais distintos nos 6 documentos alvo (`debian_linux_11/12/13`,
  `ubuntu_linux_20_04/22_04/24_04`).
- **142** já implementados.
- **299** títulos ainda sem `Check` correspondente.
- Desses 299, só **70** têm o **título** resolvendo nos 6 documentos ao mesmo tempo --
  pré-requisito mínimo, per a regra "title-must-resolve-in-all-6"
  (`src/invariant/assessment/__init__.py`, ver também `checks.md`). Os outros 229 não
  batem título em pelo menos 1 documento e não entram nesta lista -- não são "para
  fazer depois", são candidatos que exigiriam achar uma variação de título equivalente
  antes de tudo (mesmo processo que já resolveu casos como "/etc/shadow" vs "access to
  /etc/shadow" em rounds anteriores). Não foram investigados individualmente ainda.

Dos 70 com título batendo, a **condição de auditoria real** (não só o título) foi lida
por documento para os 4 grupos abaixo.

## Grupo A -- prontos para virar `Check` (16 candidatos, sem infra nova)

Condição de auditoria confirmada equivalente (ou trivialmente convergente, ex. texto
idêntico nos 6 docs) nos 6 documentos. Nenhum precisa de mudança em
`infra/docker-compose.yml` ou nos Dockerfiles -- só código em
`src/invariant/assessment/__init__.py`, e alguns precisam de campo novo em
`facts.py` (mesmo padrão já usado: `_TEXT_BLOCKS` + `SystemFacts` + `_parse_collect_output`).

| Título | Condição real (resumo) | facts.py |
|---|---|---|
| Ensure a single time synchronization daemon is in use | exatamente um entre chrony/systemd-timesyncd instalado (não os dois) | já coberto por `installed_packages` |
| Ensure audit configuration files mode is configured | arquivos de `/etc/audit/*.conf` com modo 0640 ou mais restritivo -- script idêntico nos 6 | campo novo (`find /etc/audit -maxdepth 1 -name '*.conf' -exec stat ...`) |
| Ensure audit log files group owner is configured | `grep log_group /etc/audit/auditd.conf` deve ser `adm` ou `root` -- mesma lógica nos 6 | reusa `auditd.conf` (ver campo já coletado ou adicionar) |
| Ensure audit log files mode is configured | logs de auditoria em modo 0640 ou mais restritivo -- mesmo script (1 doc só difere por comentário de página do PDF) | campo novo |
| Ensure audit log files owner is configured | logs de auditoria pertencem a root -- mesmo script (idem, diferença cosmética de PDF) | campo novo |
| Ensure audit log storage size is configured | `grep max_log_file /etc/audit/auditd.conf` -- **texto de auditoria idêntico nos 6 docs** | campo novo (conteúdo de `auditd.conf`) |
| Ensure audit logs are not automatically deleted | `grep max_log_file_action` deve ser `keep_logs` -- **texto idêntico nos 6 docs** | mesmo campo acima |
| Ensure audit tools mode is configured | `/sbin/auditctl` etc. em modo 0755 ou mais restritivo -- mesmo script nos 6 | campo novo (stat dos binários) |
| Ensure auditing for processes that start prior to auditd is enabled | `grep -v audit=1` em `/boot/grub/grub.cfg` deve retornar nada -- mesmo comando em 5/6 docs (debian_11 idêntico em essência). Container não tem `/boot/grub` -> grep sempre vazio -> passa vacuamente, mesmo padrão já usado nos checks de kernel module | campo novo (find /boot -name grub.cfg) |
| Ensure local interactive user dot files access is configured | dotfiles dos usuários interativos (exceto .forward/.rhost/.netrc) em modo 0644 ou mais restritivo e donos corretos -- mesmo script nos 6 | campo novo, mais complexo (precisa enumerar home dirs de usuários interativos, já é um padrão parecido com "home directories" abaixo) |
| Ensure local interactive user home directories are configured | homes de usuários interativos existem, donos corretos, modo 750 ou mais restritivo -- mesmo script nos 6 | campo novo, mesmo esforço do item acima -- fazer os dois juntos, mesma varredura de `/etc/passwd` |
| Ensure password quality checking is enforced | `grep enforcing=0` não deve casar em `pwquality.conf` -- mesmo script nos 6 (diferente do já implementado "dictcheck") | reusa texto de pwquality.conf já coletado (ver Group P) |
| Ensure system is disabled when audit logs are full | `disk_full_action` deve ser `halt` ou `single` em `auditd.conf` -- mesma lógica nos 6 | mesmo campo de auditd.conf |
| Ensure system warns when audit logs are low on space | `space_left_action` deve ser email/exec/single/halt -- mesma lógica nos 6 | mesmo campo de auditd.conf |
| Ensure the audit log file directory mode is configured | diretório de log de auditoria em modo 0750 ou mais restritivo -- mesmo script nos 6 | campo novo |

Repare que 6 desses 16 (`audit configuration files mode`, `audit log files group
owner/mode/owner`, `audit log storage size`, `audit logs are not automatically
deleted`, `audit tools mode`, `the audit log file directory mode`) só dependem de
**um campo comum**: o conteúdo de `/etc/audit/auditd.conf` + permissões dos arquivos
de `/etc/audit/`. Um único novo campo de texto em `facts.py` (algo como
`audit_conf_text` reunindo `cat /etc/audit/auditd.conf`, `find /etc/audit -exec stat`,
`stat` dos binários de `/sbin/auditctl` etc.) cobre a maioria -- bom agrupamento pra um
subagent só, mesmo padrão de "Group" já usado nas rounds anteriores.

## Grupo A2 -- confirmados prontos após leitura funda (9 candidatos, zero facts.py novo)

Investigação adicional (texto completo de auditoria, não truncado, comparando
`debian_linux_11` -- formato antigo -- contra `debian_linux_13` -- formato novo) pra
cada um destes 9: a condição real é uma **regra de auditd carregada**, e a diferença
entre documentos **não é drift de controle, é o próprio auditd aceitando duas
sintaxes** pro mesmo efeito -- formato antigo `-w /caminho -p wa -k chave` vs formato
novo `-a always,exit -F path=/caminho -F perm=wa -k chave`. Os documentos mais novos
dizem isso explicitamente: "the deprecated -w format... is in a passing state"
-- ou seja, o próprio CIS confirma que as duas formas contam como PASS pro mesmo
controle. Isso **não é** o mesmo tipo de drift que matou o candidato do ip-forwarding
(lá eram 2 controles reais diferentes fundidos em 1; aqui é 1 controle só, 2 sintaxes
válidas de escrever a mesma regra).

`facts.py` **já coleta** o campo necessário: `audit_rules_text`
(`cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules`, linha 89) -- zero mudança em
`facts.py` pra este grupo, só `evaluate()` que aceite as duas sintaxes.

| Título | Padrão a aceitar (resumo, confirmar regra-a-regra via Postgres antes de codar) |
|---|---|
| Ensure actions as another user are always logged | `-a always,exit ... -S execve -C euid!=uid ... -k <chave>` (antigo e novo já usam `-a`, só variam flags) |
| Ensure events that modify date and time information are collected | regra pra `adjtimex`/`settimeofday`/`clock_settime` |
| Ensure events that modify the sudo log file are collected | regra `-w` ou `-a`/`-F path=` no arquivo de log do sudo (depende de "Ensure sudo log file exists" estar configurado primeiro -- ver nota abaixo) |
| Ensure events that modify the system's Mandatory Access Controls are collected | regra pra `/etc/apparmor/` e `/etc/apparmor.d/` |
| Ensure login and logout events are collected | antigo `-w /var/log/lastlog -p wa` + `-w /var/run/faillock -p wa`; novo `-a always,exit -F path=/var/log/lastlog -F perm=wa` (idem faillock) |
| Ensure session initiation information is collected | regra pra `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp` |
| Ensure successful file system mounts are collected | regra pra syscall `mount`/`umount2`, usa `UID_MIN` de `/etc/login.defs` (já coletado) |
| Ensure unsuccessful file access attempts are collected | regra pra `EACCES`/`EPERM` em `open`/`openat`/etc., também usa `UID_MIN` |
| Ensure use of privileged commands are collected | regra por cada binário SUID/SGID do sistema -- mais complexo, precisa enumerar binários primeiro (usa `findmnt`+`find -perm`) |

**Nota**: "events that modify the sudo log file" depende de sudo ter
`Defaults logfile=...` configurado (hoje é o gap estrutural conhecido "Ensure sudo log
file exists" -- ver `checks.md`). Sem isso, a regra de auditoria não teria o que
observar de verdade, mas o `Check` em si ainda é implementável e vai mostrar FAIL de
forma correta e explicável (mesmo padrão dos outros gaps estruturais).

## Grupo B -- resolvido (2 candidatos, ambos viraram `Check`)

**Atualização (2026-08-28)**: os dois candidatos foram lidos por completo via Postgres
(script de auditoria inteiro, não truncado) nos 6 documentos e implementados.
`CHECKS` foi de 165 para **167**. Validado contra os 6 containers reais
(baseline + hardened) -- suite de testes completa (443 testes) passando.

| Título | Decisão | Resultado nos containers |
|---|---|---|
| Ensure systemd-journal-remote service is not in use | Audit text idêntico nos 6 docs (só página/rodapé do PDF muda). `systemctl is-enabled/is-active` falha nesses containers (sem systemd real, mesmo gap do Grupo C) -- mas o erro produz exatamente "nada retornado", que é a própria condição de PASS documentada pelo CIS ("Nothing should be returned"), não uma aproximação dela. Diferente das checagens do Grupo C (que precisam provar um estado *positivo* de "rodando", impossível sem systemd real), aqui só é preciso provar a ausência, e o container prova isso por incapacidade -- mesmo precedente já usado em `boot_grub_audit_text`. | PASS vacuamente nos 6 containers reais (baseline e hardened) |
| Ensure systemd-timesyncd configured with authorized timeserver | Script comparado linha a linha nos 6 docs: debian_linux_11 usa um estilo antigo (array associativo), os outros 5 um estilo refatorado -- lógica idêntica, só cosmética de formatação e número de página do PDF diferem (confirmado, não é drift de condição). Condição real: `NTP=` e `FallbackNTP=` devem estar setados (qualquer valor não-vazio) no `timesyncd.conf` mesclado (arquivo base + `conf.d/`, mesmo padrão já usado em `pwquality_text`). O "site policy" mencionado no audit é só uma nota pro revisor humano, não faz parte do critério programático. | FAIL nos 6 containers de teste (baseline/bad, `_SYSTEMIC_GAPS` em `test_assess_target.py`, external_id `2.3.2.1`) -- não são hardenizados. Nas 2 imagens hardened (`infra/docker/demo-*-hardened/Dockerfile`), fechado com um `/etc/systemd/timesyncd.conf` escrito à mão (mesmo padrão "config-only demo" já usado pra pwquality.conf/pwhistory.conf) -- PASS confirmado nas duas após rebuild. |

## Grupo C -- partições: resolvido (24 + 2 bônus = 26 candidatos)

**Atualização (2026-08-28)**: implementado com autorização explícita do usuário para
mexer em infra. `CHECKS` foi de 167 para **193**. `infra/docker-compose.yml` (os 6
containers reais de dev/teste) e `infra/docker-compose.demo.yml` (as 2 imagens
hardened + os 5 containers de problema) agora montam `tmpfs` em `/tmp`, `/home`,
`/var/tmp`, `/var/log`, `/var/log/audit` (`/dev/shm` já vem como tmpfs por padrão do
próprio Docker, confirmado empiricamente -- zero mudança de infra precisou pra ele).

`findmnt -kn <target>` só resolve target-por-target (confirmado empiricamente:
`findmnt -kn A B` sai com código 1 e zero saída se **qualquer um** dos dois não for
mount de verdade -- não é "imprime o que resolve, ignora o resto"), então
`facts.mounts_text` faz um loop, uma invocação por target -- ver o comentário acima
desse campo em `facts.py`.

**2 candidatos bônus, achados durante a implementação**: "Ensure /tmp is a separate
partition" e "Ensure /dev/shm is a separate partition" não entravam na contagem
original de 24 porque cada um tem 2 variantes de título (a mesma dualidade "singular
vs tmpfs-or-separate" que `/etc/shadow` já tinha) -- uma busca ingênua por um único
título não resolve nos 6 docs, as duas juntas resolvem. `/dev/shm` já passa de graça
(ver acima); `/tmp` passa junto com o resto do tmpfs.

**`/var` deliberadamente NÃO virou tmpfs**: montaria por cima de `/var/lib/dpkg` e
`/var/cache/apt`, zerando o banco de dados do dpkg a cada start do container --
quebraria `facts.py`'s `installed_packages` (lido ao vivo via `dpkg-query -W` em
todo `assess_target()`) e, em cascata, todo check de presença de pacote já
implementado (ufw/sudo/auditd/chrony/cron/avahi-ausente/bluetooth-ausente, ...), não
só os novos checks de partição. Único custo real: "Ensure separate partition exists
for /var" (`1.1.2.4.1`, estável nos 6 docs) fica FAIL em todo lugar -- os checks de
`nodev`/`nosuid` *em* `/var` continuam passando vacuamente, porque o audit deles é
condicional ("- IF - a separate partition exists for /var..."), e sem `/var` montado
separado essa condição nunca se aplica. Ver o comentário em `docker-compose.yml` e
`test_assess_target.py`'s `_SYSTEMIC_GAPS`.

**Efeito colateral achado e corrigido**: `ubuntu:24.04` (base de
`ubuntu-permissions-bad`) vem com um usuário interativo real de fábrica (`ubuntu`,
`/home/ubuntu`, modo 750 `ubuntu:ubuntu`) -- o tmpfs em `/home` apagava esse diretório
a cada start, derrubando um check já implementado e antes passando ("Ensure local
interactive user home directories are configured", `7.2.9`). Corrigido recriando o
diretório com o mesmo modo/dono no `CMD` do Dockerfile (só o `RUN` de build não
alcança, o mount só existe quando o container já está rodando) -- ver o comentário
em `infra/docker/ubuntu-permissions-bad/Dockerfile`. Nenhum dos outros 5 containers
reais tem usuário interativo de fábrica (confirmado via `/etc/passwd`), então só esse
precisou do ajuste.

**Imagens hardened**: `/var/log/audit` recebeu `mode: 0750` explícito no
`docker-compose.demo.yml` (via sintaxe longa `volumes: - type: tmpfs`) -- diferente
dos 6 containers de teste, essas 2 imagens instalam `auditd` de verdade, e o modo
default do Docker pro tmpfs (0755) quebraria "Ensure the audit log file directory
mode is configured" (já implementado, não faz parte do Grupo C). Resultado final:
193 `CHECKS`, **187 passam** nas 2 imagens hardened -- os mesmos 5 impossíveis de
container + o `/var` deixado de fora de propósito. Ver `checks.md`.

## Grupo C -- systemd real: resolvido (6 candidatos)

**Atualização (2026-08-28)**: os 6 candidatos foram implementados. `CHECKS` foi de
193 para **199**. Nenhum dos 6 títulos existia como `Check` antes disso -- o "ainda
bloqueado" era literal, não só "falhando em todo lugar".

Confirmado via Postgres (texto de audit idêntico nos 6 documentos, só página/rodapé
do PDF diverge) que **4 dos 6 controles são condicionais** ("- IF - chrony/cron/
systemd-timesyncd está em uso..."): um alvo que nunca instalou um desses daemons
passa vacuamente nesse controle específico, mesma substituição já usada em
`_evaluate_single_time_sync_daemon` e `_evaluate_journal_remote_not_in_use`. Só 2 são
incondicionais (auditd enabled+active, `augenrules --check` == "No change").

**Decisão de infra**: em vez de construir um container novo com systemd real
(`--privileged` + bind mount de `/sys/fs/cgroup`, avaliado e descartado por decisão
do usuário -- focar só na infra já existente), os 6 checks foram validados
diretamente contra **a própria VPS de produção** (systemd real como PID 1, Ubuntu
24.04.4, `document_slug_for_os` resolve `ubuntu_linux_24_04` de forma nativa) e
contra `invariant-api` (container Debian 13 de produção do próprio projeto, sem
systemd -- bom caso de robustez pra "comando não existe" nos 2 controles
incondicionais). Nenhum transporte novo foi criado no código (`collect_facts` segue
100% `docker exec`, como sempre foi) -- a validação contra a VPS em si usou um script
avulso, fora do repositório, que só reaproveita `facts._collect_script()`/
`_parse_collect_output()` via `subprocess` local, sem tocar `facts.py`.

Achado colateral relevante: o scan `find / -xdev` (world-writable/unowned) levou
**~50s** contra o filesystem real da VPS, contra o timeout de 10s que
`facts.collect_facts()` usa hoje para containers -- se algum dia a estratégia mudar
pra assessar hosts reais via um transporte oficial (não é o caso aqui, `docker exec`
continua sendo o único transporte do produto), esse timeout precisaria crescer.

Resultado na VPS real: `cron` e `systemd-timesyncd` PASSam de verdade (ambos
genuinamente `enabled`/`active`, não vacuamente); `auditd` FAIL (não instalado);
`augenrules --check` FAIL fechado (comando não existe sem auditd). Todo caminho de
código dos 6 checks foi exercitado contra um alvo real.

**Efeito colateral #1 (6 containers de dev/teste)**: nenhum instala auditd/chrony/
cron, então só os 2 controles incondicionais viram FAIL de verdade -- confirmado via
`assess_target()`, external_ids adicionados a `_SYSTEMD_REAL_GAP_BY_DOCUMENT` em
`test_assess_target.py`.

**Efeito colateral #2 (2 imagens hardened do demo)**: instalam auditd/chrony/cron mas
não têm systemd real -- 4 dos 6 títulos (os 2 incondicionais + chrony/cron enabled,
que agora têm o pacote presente e portanto a condição "se em uso" passa a se aplicar)
viram FAIL. Adicionados a `scripts/demo/misconfig_catalog.py`'s
`CONTAINER_IMPOSSIBLE_TITLES` (mesmo motivo já documentado pros outros 5: sem systemd
real, não tem como o daemon estar "ativo"). Resultado final: 199 `CHECKS`, **189
passam** nas 2 imagens hardened -- os mesmos 9 impossíveis de container + o `/var`
deixado de fora de propósito. Ver `checks.md`.

## Grupo D -- descartados (13 candidatos)

Título bate nos 6 documentos, mas a condição real não dá pra checar sem inventar
critério, ou já foi tentada e abandonada em rounds anteriores. (Os itens que dependem
de systemd real -- auditd/chrony/cron enabled+active, chrony como usuário `_chrony`,
"running and on disk configuration is the same" -- já estão contados no Grupo C, não
duplicados aqui.)

| Título | Motivo |
|---|---|
| Ensure GDM login banner is configured | GDM não instalado no container; mecanismo de verificação difere de fato entre dconf (Ubuntu) e gsettings travado (Debian 12+) -- não é só boilerplate |
| Ensure IPv6 status is identified | controle informativo ("identify", não "ensure disabled") -- não tem critério pass/fail objetivo, é documentação de política de site |
| Ensure SUID and SGID files are reviewed | revisão manual, sem critério automatizável (já conhecido) |
| Ensure all AppArmor Profiles are enforcing | AppArmor não roda dentro do container (kernel do host, não do container, decide isso) |
| Ensure bootloader password is set | `/boot/grub/grub.cfg` nunca existe em container (sem bootloader) -- mesmo motivo já documentado pro gap estrutural existente "access to bootloader config" |
| Ensure default user shell timeout is configured | TMOUT -- já tentado e abandonado no round 3 (rastreamento por arquivo que `facts.py` não suporta) |
| Ensure filesystem integrity is regularly checked | mecanismo genuinamente diferente por doc: 3 docs checam timer systemd, 2 checam cron job (grep diferente), 1 (ubuntu_20_04) checa mecanismo criptográfico -- drift real de condição, mesmo padrão do caso ip-forwarding que já descartamos antes |
| Ensure journald log file access is configured | precisa `systemd-journald` real configurado; mecanismo também diverge entre ubuntu_20_04 e o resto (override file vs script direto) |
| Ensure kernel module loading unloading and modification is collected | já descartado no round 3 (debian_13 tem condição mais fraca) |
| Ensure latest version of pam is installed | 5 dos 6 docs comparam versão instalada vs versão disponível no repositório (`apt-cache policy` ou equivalente) -- depende de repositório real acessível, mesmo motivo de "updates installed" abaixo |
| Ensure no duplicate user names exist | já descartado (bug real no PDF do debian_11, round 2) |
| Ensure only approved services are listening on a network interface | depende de política de site (`ss -plntu` + "aprovado por política") -- sem lista de "aprovados" pra comparar |
| Ensure updates, patches, and additional security software are installed | depende de estado de repositório apt externo (`apt update && apt -s upgrade`) -- não é reproduzível/determinístico num container isolado |

## Como usar este documento

Grupos A + A2 (25 candidatos, round 4), B (2 candidatos) e os dois pedaços do C
(26 partições + 6 systemd real) já foram implementados -- `CHECKS` foi de 142 para
**199**. Só resta o Grupo D (descartado, não avança).

**Contagem final**: 16 (A) + 9 (A2) + 2 (B) + 26 (C partições, 24 originais + 2
bônus) + 6 (C systemd) + 13 (D) = 72 (dos 70 originais + 2 bônus achados durante a
implementação do C).
