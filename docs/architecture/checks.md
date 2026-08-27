# Checks: structure, traceability rule, and the quickdemo-eligible subset

This documents `src/invariant/assessment/__init__.py`'s `Check` structure
for anyone extending it or building on top of it (e.g.
`scripts/quickdemo/misconfig_catalog.py`), and states the non-negotiable
rule every `Check` and every misconfig recipe must follow.

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

This rule extends to `scripts/quickdemo/misconfig_catalog.py`: **every
`Recipe` must cite the real `Check.titles` (copied verbatim from this
module) it breaks** -- a misconfig with no matching `Check` would make
`quickdemo.sh`'s demo lie about what it's showing. `misconfig_catalog.py`'s
own module docstring repeats this; see that file for the full recipe list.

If a control looks worth adding but doesn't fit `SystemFacts`' current
collection scope, or its audit condition can't be resolved for both demo
documents (`debian_linux_11` and `ubuntu_linux_20_04`), it's better dropped
than faked -- `assessment/__init__.py`'s own comments document several
candidates that were looked at and dropped for exactly this reason (see the
comments above `CHECKS`'s Group F/I/J entries).

## The quickdemo-eligible subset

`quickdemo.sh` uses two purpose-built images
(`infra/docker/quickdemo-{debian,ubuntu}-hardened/`, **not** the 6
dev/test images under `infra/docker/{debian,ubuntu}-*` -- those are
untouched, relied on by `tests/assessment/`'s `@pytest.mark.integration`
tests) that are hardened via plain config edits (`chmod`/`chown`/`sed`) plus
(as of round 2) a handful of real packages (`ufw`/`sudo`/`auditd`/
`audispd-plugins`/`aide`/`aide-common`, alongside the base pipeline's own
`openssh-server`) whose entire point *is* package presence -- there's no
"pure config" way to pass a check that literally asks "is X installed?" --
to **PASS every `Check` that's achievable without a systemd-capable image
or real separate filesystem mounts.**

Confirmed empirically (built and assessed against live containers): of the
165 `CHECKS`, exactly **140 pass** on both hardened images with zero
further changes, and the same **25 fail structurally** on both, regardless
of configuration -- because the underlying package/file/rule simply isn't
present or loaded, and installing what's left would mean either a
systemd-capable base image, real partition mounts, or actually configuring
and loading a real auditd rule set, all bigger changes than "add a
package":

| Check title | Why it's structural |
|---|---|
| Ensure pam_pwquality module is enabled | `pam_pwquality.so` ships in `libpam-pwquality`, not installed (confirmed: not present under `/usr/lib/*/security/` on a bare image). `pwquality.conf`'s own *directives* (minlen, complexity, difok, ...) are still demo-eligible -- CIS greps that file directly, independent of whether the module is loaded. |
| Ensure the audit configuration is immutable | `auditd`/`audispd-plugins` **are** installed (round 2 -- needed for "Ensure auditd packages are installed"), which also fixed 4 *other* audit-ownership checks that used to be structural gaps here for free (`/etc/audit/`, `/sbin/auditctl` etc. now exist with correct ownership by default). This one still fails -- it needs an actual loaded, immutable-flagged rule set, not just the package installed. |
| Ensure sudo log file exists | `sudo` **is** installed (round 2), but its default `/etc/sudoers` has no `Defaults logfile=...` line -- a real gap, just not one round 2's own checks needed to close. |
| Ensure access to /etc/crontab is configured | no `cron` installed -- `/etc/crontab` doesn't exist (unlike `/etc/cron.d`/`/etc/cron.daily`, which ship on a bare image via other packages and *are* demo-eligible) |
| Ensure access to /etc/cron.hourly is configured | same -- `cron` not installed |
| Ensure access to /etc/cron.weekly is configured | same |
| Ensure access to /etc/cron.monthly is configured | same |
| Ensure journald Compress is configured | `/etc/systemd/journald.conf` isn't consulted the same way / not meaningfully configurable in an unprivileged container without systemd running |
| Ensure journald Storage is configured | same |
| Ensure journald log file rotation is configured | same |
| Ensure access to bootloader config is configured | `/boot/grub/grub.cfg` never exists in a container (no bootloader) |
| Ensure access to the su command is restricted | round 3 -- neither image configures `/etc/pam.d/su`'s `pam_wheel.so` line |
| Ensure password failed attempts lockout includes root account | round 3 -- neither image sets `even_deny_root`/`root_unlock_time` in `faillock.conf` |
| Ensure a single time synchronization daemon is in use | round 4 -- neither `chrony` nor `systemd-timesyncd` is installed on either image |
| Ensure audit logs are not automatically deleted | round 4 -- `auditd.conf`'s shipped default (`max_log_file_action ROTATE`) doesn't meet CIS's required `keep_logs` |
| Ensure system is disabled when audit logs are full | round 4 -- shipped default (`disk_full_action SUSPEND`) isn't `halt`/`single` |
| Ensure system warns when audit logs are low on space | round 4 -- shipped default (`space_left_action SYSLOG`) isn't in the required set |
| Ensure actions as another user are always logged | round 4 -- no real auditd rule loaded on either image (all 8 rows below share this one root cause) |
| Ensure events that modify date and time information are collected | round 4, same root cause as above |
| Ensure events that modify the sudo log file are collected | round 4, same root cause (also downstream of "Ensure sudo log file exists" above) |
| Ensure events that modify the system's Mandatory Access Controls are collected | round 4, same root cause |
| Ensure login and logout events are collected | round 4, same root cause |
| Ensure session initiation information is collected | round 4, same root cause |
| Ensure successful file system mounts are collected | round 4, same root cause |
| Ensure unsuccessful file access attempts are collected | round 4, same root cause |

(`Ensure ufw is installed`, `Ensure sudo is installed`, `Ensure AIDE is
installed`, the ~19 "package X is not in use" checks round 2 added, the 7
of 10 auditd.conf-family checks round 4 added whose shipped defaults
already comply, and the 2 local-interactive-user checks round 4 added are
all demo-eligible and PASS today.)

This 25-title set is `scripts/quickdemo/misconfig_catalog.py`'s
`STRUCTURAL_GAP_TITLES` constant. `quickdemo.sh`'s final summary uses it to
split every FAIL on a demo container into:

- **environmental** -- the title is in `STRUCTURAL_GAP_TITLES` (same on
  every container, including the hardened baseline -- not part of "today's
  story", just a known, documented gap).
- **today's story** -- the title matches a `Recipe` that
  `scripts/quickdemo/apply_misconfigs.py` actually applied to that specific
  container this run.

Any FAIL that's neither would mean a hardened-image regression or an
untracked misconfig -- `quickdemo.sh` flags that loudly rather than
silently folding it into one bucket, since it would mean the demo is
showing something nobody can explain.

## A non-obvious gotcha found while building this: `sshd -T` resolves the *first* occurrence of a repeated directive, not the last

`facts.py` collects sshd's config via `sshd -T` (the effective config,
already resolved), not by `cat`-ing `sshd_config` and parsing text --
deliberate, so a directive left at its secure OpenSSH default (never set
explicitly) still reads correctly (see that module's own comment). One
consequence that isn't obvious from that comment alone, and that
`scripts/quickdemo/misconfig_catalog.py`'s sshd recipes depend on getting
right: when a directive appears **twice** in `sshd_config`, real `sshd`
uses the **first** occurrence and silently ignores the second -- confirmed
empirically (appending a second `PermitRootLogin yes` line below an
existing `PermitRootLogin no` has no effect on `sshd -T`'s output). This is
the opposite of `parse_sshd_config()`'s own doc-comment ("later lines win"
-- true of *that parser*, applied to `sshd -T`'s own de-duplicated output,
not of raw `sshd_config` fed to real `sshd`). Every sshd-directive misconfig
recipe therefore uses `sed -i` to replace the directive's existing line in
place, never appends a second one.
