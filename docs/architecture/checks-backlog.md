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

## Grupo B -- ainda precisam de decisão antes de implementar (2 candidatos)

| Título | Pendência |
|---|---|
| Ensure systemd-journal-remote service is not in use | `systemctl is-enabled` não funciona sem systemd real (PID 1) no container -- precisa confirmar se o erro do comando serve de proxy pra "not enabled" (analogia ao vacuous-pass dos checks de kernel module) ou se é Tier 3 puro |
| Ensure systemd-timesyncd configured with authorized timeserver | grep em `/etc/systemd/timesyncd.conf` -- não precisa do serviço rodando, só o arquivo existir; mas a comparação usa `Page NNN` de boilerplate do PDF que não confirmei ser só cosmético nos 6 docs -- precisa 1 leitura a mais antes de decidir |

## Grupo C -- precisam de decisão de infra antes de valer a pena (24 + 6 = 30 candidatos)

**Partições reais (24 candidatos)**: `nodev`/`nosuid`/`noexec` em `/dev/shm`, `/home`,
`/tmp`, `/var`, `/var/log`, `/var/log/audit`, `/var/tmp`, mais "separate partition
exists for" em 5 desses mounts. Condição confirmada uniforme nos 6 docs (mesmo script
`findmnt`-based, padrão CIS bem conhecido) -- **não é ambiguidade, é infra**: precisa
de mounts `tmpfs` de verdade nos containers de teste, que hoje usam o filesystem do
container inteiro sem partições separadas.

**Depende de systemd real rodando (6 candidatos)**: `Ensure auditd service is enabled
and active`, `Ensure chrony is enabled and running`, `Ensure chrony is running as user
_chrony`, `Ensure cron daemon is enabled and active`, `Ensure systemd-timesyncd is
enabled and running`, `Ensure the running and on disk configuration is the same`
(precisa de `augenrules`/auditd real configurado e rodando). Containers atuais não
rodam systemd (PID 1 não é systemd) -- exigiria trocar a imagem base, mudança maior
que qualquer coisa feita até agora.

Nenhuma mudança de infra deve ser feita sem autorização explícita, igual já
documentado em `checks.md` e na memória do projeto.

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

**Grupos A + A2 (25 candidatos) são o alvo da próxima rodada de implementação**, mesmo
padrão das rounds 1-3 (subagents paralelos em worktree, agrupados por campo de
`facts.py` compartilhado). Grupo B (2 candidatos) precisa de mais 1 leitura pontual
antes de entrar ou não numa rodada. Grupos C e D não avançam sem decisão do usuário
(infra) ou seguem descartados.

**Contagem final**: 16 (A) + 9 (A2) + 2 (B) + 30 (C) + 13 (D) = 70.
