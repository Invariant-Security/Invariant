# Checks: structure, traceability rule, and the demo-eligible subset

This documents `src/invariant/assessment/__init__.py`'s `Check` structure
for anyone extending it or building on top of it (e.g.
`scripts/demo/misconfig_catalog.py`), and states the non-negotiable rule
every `Check` and every misconfig recipe must follow.

## The `Check` structure

```python
@dataclass
class Check:
    titles: list[str]
    evaluate: Callable[[SystemFacts], bool]
    evidence: Callable[[SystemFacts], str]
```

- `titles` -- every exact wording a real CIS document uses for this
  control's title. Exact title text drifts between CIS documents for the
  *same* underlying control (e.g. "Ensure permissions on /etc/shadow are
  configured" in `debian_linux_11` vs "Ensure access to /etc/shadow is
  configured" in every other real target document) -- confirmed by
  querying Postgres, not guessed. `assess_target()` looks a control up by
  title against the target's *detected* document (via
  `document_slug_for_os()`), not by a hardcoded `external_id`, because the
  numeric id drifts too (e.g. Debian 13 uses `5.1.21` where the rest use
  `5.1.20`, and `/etc/cron.d`'s id is `2.4.1.7` on `debian_linux_11` but
  `2.4.1.8` everywhere else).
- `evaluate(facts: SystemFacts) -> bool` -- a plain Python comparison
  against one `SystemFacts` snapshot (collected once per target,
  `facts.collect_facts()`, a single `docker exec`). No `Check` ever runs
  its own `docker exec` or shells out -- `facts.py` is the only module that
  talks to a target (see that module's docstring). Adding a new kind of
  check that needs data `SystemFacts` doesn't already carry means adding a
  field to `SystemFacts` (and a line to `facts._collect_script()`) first.
- `evidence(facts: SystemFacts) -> str` -- the human-readable line printed
  for a `FAIL` (`invariant assess`'s summary, see `invariant.cli.assess`),
  the "why" half of `bxsec.md`'s "don't stop at 'HIGH, SSH insecure' --
  show why" rule. Every `evaluate`/`evidence` pair reads the *same* facts
  fields, so the evidence line always matches what was actually compared.

## The non-negotiable rule: every Check cites a real control

**No invented failure conditions, ever.** Every `Check` in `CHECKS` exists
because a real CIS benchmark document contains that exact control, with
that exact title text and audit condition -- most `evaluate()` docstrings
in `assessment/__init__.py` quote the real CIS audit command they match
(e.g. `_evaluate_ssh_max_startups`'s docstring quotes the real `sshd -T |
awk ...` audit script). A `Check` that "sounds like good security advice"
but doesn't trace back to a specific, versioned CIS control does not belong
in `CHECKS` -- this is the same traceability guarantee root `CLAUDE.md`
states for the whole pipeline (source -> document version -> raw artifact
-> content hash -> parser version -> collection event): a `Finding`
without a real control behind it breaks that chain at the last step, the
one a demo viewer actually reads.

This rule extends to `scripts/demo/misconfig_catalog.py`: **every `Recipe`
must cite the real `Check.titles` (copied verbatim from this module) it
breaks** -- a misconfig with no matching `Check` would make `demo.sh`'s
demo lie about what it's showing. `misconfig_catalog.py`'s own module
docstring repeats this; see that file for the full recipe list.

If a control looks worth adding but doesn't fit `SystemFacts`' current
collection scope, or its audit condition can't be resolved for both demo
documents (`debian_linux_11` and `ubuntu_linux_20_04`), it's better dropped
than faked -- `assessment/__init__.py`'s own comments document several
candidates that were looked at and dropped for exactly this reason (see the
comments above `CHECKS`'s Group F/I/J entries).

## The demo-eligible subset

`demo.sh` uses two purpose-built images
(`infra/docker/demo-{debian,ubuntu}-hardened/`, **not** the 6 dev/test
images under `infra/docker/{debian,ubuntu}-*` -- those are untouched,
relied on by `tests/assessment/`'s `@pytest.mark.integration` tests) that
are hardened via plain config edits (`chmod`/`chown`/`sed`) plus a handful
of real packages (`ufw`/`sudo`/`auditd`/`audispd-plugins`/`aide`/
`aide-common`/`cron`/`libpam-pwquality`/`chrony`, alongside the base
pipeline's own `openssh-server`) whose entire point *is* package
presence -- there's no "pure config" way to pass a check that literally
asks "is X installed?" -- plus a real (if never loaded by a live daemon)
auditd rule set written to `/etc/audit/rules.d/50-hardening.rules` at build
time, since the checks that verify audit-rule collection only read that
file, never a live `auditctl -l`.

Goal: **PASS every `Check` except the handful that are genuinely impossible
inside an unprivileged Docker container** (no bootloader, no functioning
systemd/journald PID 1, no immutable-flag-capable audit subsystem without
extra capabilities) -- a materially higher bar than earlier iterations of
this image, which left ~20 checks failing for no better reason than "nobody
configured it yet." Those 20 were closed for real (see the history below);
what's left is a short, honest list of things a Docker container simply
cannot do.

Confirmed empirically (built and assessed against live containers): of the
165 `CHECKS`, exactly **160 pass** on both hardened images with zero
further changes, and the same **5 fail structurally** on both, regardless
of configuration:

| Check title | Why it's genuinely impossible in a container |
|---|---|
| Ensure the audit configuration is immutable | Needs an actual loaded, immutable-flagged auditd rule set (`auditctl -e 2`) -- the audit netlink subsystem generally isn't fully functional inside an unprivileged container namespace, so even with auditd installed and rules written to disk, there's no live daemon to flag as immutable. |
| Ensure journald Compress is configured | `/etc/systemd/journald.conf`'s directives aren't meaningfully consulted without systemd-journald actually running as part of a real systemd PID 1, which this container doesn't have. |
| Ensure journald Storage is configured | same |
| Ensure journald log file rotation is configured | same |
| Ensure access to bootloader config is configured | `/boot/grub/grub.cfg` never exists in a container (no bootloader) |

This 5-title set is `scripts/demo/misconfig_catalog.py`'s
`CONTAINER_IMPOSSIBLE_TITLES` constant.

### Container detection: the "environmental" excuse is conditional, not automatic

`facts.py` collects one more fact than any real `Check` reads:
`container_detection_text` (`/.dockerenv` + `/proc/1/cgroup`), interpreted
by `is_running_in_container(facts) -> bool`. `demo.sh`'s report
(`scripts/demo/report.py`) only classifies a FAIL on a
`CONTAINER_IMPOSSIBLE_TITLES` title as **environmental** when the specific
target is actually detected as a container -- on a bare-metal or VM target
(where `is_running_in_container()` returns `False`), the exact same title
is just a normal FAIL, no automatic excuse, because on a real machine it's
a real, checkable, fixable gap. This exists precisely so the tool doesn't
quietly launder a real gap into "environmental" just because the title
happens to be hard to satisfy in *this specific* demo setup -- the excuse
is about the target, not the title.

### History: how 20 of the original 25 structural gaps were closed

Earlier hardened images left 25 checks failing "structurally" -- most of
those weren't actually impossible, just never configured. Round 4/demo
hardening closed 20 of them for real:

- **Package presence**: `libpam-pwquality`, `cron`, `chrony` installed
  (closes "pam_pwquality module enabled", the 4 cron file/dir permission
  checks, and "single time synchronization daemon", the last one via
  `chrony` XOR `systemd-timesyncd` package presence -- the real CIS audit
  uses `systemctl is-enabled`/`is-active`, unusable without real systemd in
  a container, so this is a deliberate package-presence substitution, same
  pattern as every other package-presence check in this file).
- **PAM/faillock config**: an empty `sugroup` group + a `pam_wheel.so use_uid
  group=sugroup` line in `/etc/pam.d/su` (closes "su command restricted");
  `even_deny_root`/`root_unlock_time = 0` in a freshly-created
  `/etc/security/faillock.conf` (closes "password failed attempts lockout
  includes root account").
- **sudoers**: a `Defaults logfile=/var/log/sudo.log` line (closes "sudo
  log file exists" and unblocks the matching audit rule below).
- **auditd.conf directives**: `max_log_file_action = keep_logs`,
  `disk_full_action = halt`, `disk_error_action = syslog`,
  `space_left_action = email`, `admin_space_left_action = halt` appended
  (the package's own shipped defaults -- `ROTATE`/`SUSPEND`/`SUSPEND`/
  `SYSLOG` -- don't meet CIS's required values; closes 3 checks).
- **Real auditd rules on disk**: `/etc/audit/rules.d/50-hardening.rules`,
  written at build time with one rule per control (execve/euid!=uid,
  date-time syscalls + `/etc/localtime` watch, the sudo log path, both
  AppArmor paths, lastlog+faillock, utmp+wtmp+btmp, the mount syscall, and
  EACCES/EPERM access rules) -- closes the 8 "events ... are collected"/
  "actions ... are logged" titles, since those checks read the rules file
  directly (`facts.audit_rules_text`), never a live `auditctl -l`.

Two titles were investigated and deliberately **not** closed even though
they're technically achievable in principle: "Ensure use of privileged
commands are collected" would need a per-target SUID/SGID enumeration that
isn't deterministic across builds (dropped rather than faked, per the
non-negotiable rule above); "Ensure access to all logfiles has been
configured" has a genuine per-CIS-document condition drift (`debian_linux_11`
lacks the special-case allowlist the other 5 real target documents have for
`/var/log/apt/*.log` etc.) -- these aren't part of `CHECKS` at all, so
they don't appear in the demo-eligible count either way.

### How demo.sh classifies every FAIL

`demo.sh`'s final summary (`scripts/demo/report.py`) splits every FAIL on
a demo container into:

- **environmental** -- the title is in `CONTAINER_IMPOSSIBLE_TITLES` *and*
  the target is detected as a container (see above) -- same on every
  demo container including the hardened baseline, not part of "today's
  story", just a known, genuine limitation of this environment.
- **today's story** -- the title matches a `Recipe` that
  `scripts/demo/apply_misconfigs.py` actually applied to that specific
  container this run.

Any FAIL that's neither would mean a hardened-image regression or an
untracked misconfig -- `demo.sh` flags that loudly rather than silently
folding it into one bucket, since it would mean the demo is showing
something nobody can explain.

## A non-obvious gotcha found while building this: `sshd -T` resolves the *first* occurrence of a repeated directive, not the last

`facts.py` collects sshd's config via `sshd -T` (the effective config,
already resolved), not by `cat`-ing `sshd_config` and parsing text --
deliberate, so a directive left at its secure OpenSSH default (never set
explicitly) still reads correctly (see that module's own comment). One
consequence that isn't obvious from that comment alone, and that
`scripts/demo/misconfig_catalog.py`'s sshd recipes depend on getting
right: when a directive appears **twice** in `sshd_config`, real `sshd`
uses the **first** occurrence and silently ignores the second -- confirmed
empirically (appending a second `PermitRootLogin yes` line below an
existing `PermitRootLogin no` has no effect on `sshd -T`'s output). This is
the opposite of `parse_sshd_config()`'s own doc-comment ("later lines win"
-- true of *that parser*, applied to `sshd -T`'s own de-duplicated output,
not of raw `sshd_config` fed to real `sshd`). Every sshd-directive misconfig
recipe therefore uses `sed -i` to replace the directive's existing line in
place, never appends a second one.
