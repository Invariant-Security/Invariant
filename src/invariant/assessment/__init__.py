"""Assesses Docker demo targets against real controls already in Postgres.

This is the bxsec-branch "Evidence Collector -> Assessment -> Finding" side
of the pipeline (see bxsec.md and PRD sec. 23, "Future Assessment
Architecture") -- distinct from invariant.collector, which preserves CIS
document artifacts, not environment evidence.

Evidence is gathered once per target (facts.collect_facts(), a single
`docker exec`) rather than once per check -- checks are plain Python
comparisons against that snapshot, not their own command. No agent
installed on the target.

Which CIS document applies to a target is *detected* from the collected
facts, not hardcoded. Only 5 controls are actually implemented so far (SSH
PermitRootLogin/PermitUserEnvironment/IgnoreRhosts/LoginGraceTime,
/etc/shadow permissions) -- checking the rest of a document's ~300
controls needs a hand-written evaluator per control, the same way these
were built; there's no generic way to turn CIS's free-text audit
instructions into an executable check. suggestions.suggest_checks()
narrows down which controls are worth looking at next (591 distinct
titles across the database have a single extractable "# <command>" audit
line) but still only proposes -- every candidate needs a human to verify
it against a real target before it becomes a real Check here.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from invariant.assessment.facts import SystemFacts, collect_facts
from invariant.observability import timed
from invariant.storage import postgres as db

TARGETS = [
    "invariant-debian-baseline",
    "invariant-debian-ssh-bad",
    "invariant-debian-permissions-bad",
    "invariant-ubuntu-baseline",
    "invariant-ubuntu-ssh-bad",
    "invariant-ubuntu-permissions-bad",
]


def _evaluate_ssh_permit_root_login(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("permitrootlogin", "").lower() == "no"


def _evidence_ssh_permit_root_login(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("permitrootlogin", "<not set>")
    return f"sshd_config: PermitRootLogin {value}"


def _evaluate_shadow_permissions(facts: SystemFacts) -> bool:
    """Matches the real audit condition (control 7.1.5): mode 640 or more
    restrictive, Uid 0/root, Gid 0/root or the shadow group.
    """
    stat = facts.file_stats.get("/etc/shadow")
    if stat is None or stat.mode is None:
        return False
    return stat.mode <= 0o640 and stat.uid == 0 and stat.gname in ("root", "shadow")


def _evidence_shadow_permissions(facts: SystemFacts) -> str:
    stat = facts.file_stats.get("/etc/shadow")
    if stat is None or stat.mode is None:
        return "/etc/shadow: could not stat"
    return f"/etc/shadow: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"


def _evaluate_ssh_permit_user_environment(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("permituserenvironment", "").lower() == "no"


def _evidence_ssh_permit_user_environment(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("permituserenvironment", "<not set>")
    return f"sshd_config: PermitUserEnvironment {value}"


def _evaluate_ssh_ignore_rhosts(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("ignorerhosts", "").lower() == "yes"


def _evidence_ssh_ignore_rhosts(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("ignorerhosts", "<not set>")
    return f"sshd_config: IgnoreRhosts {value}"


def _evaluate_ssh_login_grace_time(facts: SystemFacts) -> bool:
    value = facts.sshd_config.get("logingracetime", "")
    try:
        seconds = int(value)
    except ValueError:
        return False
    return 1 <= seconds <= 60


def _evidence_ssh_login_grace_time(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("logingracetime", "<not set>")
    return f"sshd_config: LoginGraceTime {value}"


def _permissions_ok(
    facts: SystemFacts, path: str, max_mode: int, allowed_gnames: tuple[str, ...]
) -> bool:
    """Shared by every plain file-permission check below (Group A: /etc/issue,
    /etc/passwd(-), /etc/group(-), /etc/shadow-, /etc/gshadow(-), /etc/shells,
    /etc/ssh/sshd_config) -- their real CIS audit text is otherwise a copy of
    the /etc/shadow one already implemented above (stat mode <= a ceiling,
    Uid 0/root, Gid 0/root or a specific group), just with a different
    path/mode/allowed group.
    """
    stat = facts.file_stats.get(path)
    if stat is None or stat.mode is None:
        return False
    return stat.mode <= max_mode and stat.uid == 0 and stat.gname in allowed_gnames


def _evidence_for_stat(path: str) -> Callable[[SystemFacts], str]:
    def _evidence(facts: SystemFacts) -> str:
        stat = facts.file_stats.get(path)
        if stat is None or stat.mode is None:
            return f"{path}: could not stat"
        return f"{path}: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"

    return _evidence


def _evaluate_etc_issue_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/issue", 0o644, ("root",))


_evidence_etc_issue_permissions = _evidence_for_stat("/etc/issue")


def _evaluate_etc_issue_net_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/issue.net", 0o644, ("root",))


_evidence_etc_issue_net_permissions = _evidence_for_stat("/etc/issue.net")


def _evaluate_etc_passwd_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/passwd", 0o644, ("root",))


_evidence_etc_passwd_permissions = _evidence_for_stat("/etc/passwd")


def _evaluate_etc_passwd_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/passwd-", 0o644, ("root",))


_evidence_etc_passwd_minus_permissions = _evidence_for_stat("/etc/passwd-")


def _evaluate_etc_group_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/group", 0o644, ("root",))


_evidence_etc_group_permissions = _evidence_for_stat("/etc/group")


def _evaluate_etc_group_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/group-", 0o644, ("root",))


_evidence_etc_group_minus_permissions = _evidence_for_stat("/etc/group-")


def _evaluate_etc_shadow_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/shadow-", 0o640, ("root", "shadow"))


_evidence_etc_shadow_minus_permissions = _evidence_for_stat("/etc/shadow-")


def _evaluate_etc_gshadow_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/gshadow", 0o640, ("root", "shadow"))


_evidence_etc_gshadow_permissions = _evidence_for_stat("/etc/gshadow")


def _evaluate_etc_gshadow_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/gshadow-", 0o640, ("root", "shadow"))


_evidence_etc_gshadow_minus_permissions = _evidence_for_stat("/etc/gshadow-")


def _evaluate_etc_shells_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/shells", 0o644, ("root",))


_evidence_etc_shells_permissions = _evidence_for_stat("/etc/shells")


def _evaluate_sshd_config_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/ssh/sshd_config", 0o600, ("root",))


_evidence_sshd_config_permissions = _evidence_for_stat("/etc/ssh/sshd_config")


def _passwd_fields(passwd_text: str) -> list[list[str]]:
    """Splits /etc/passwd-style text into colon-separated fields per
    non-blank line. Lines that don't parse into enough fields (a `cat`
    error message when the file couldn't be read, for instance) are
    dropped rather than raising -- same "don't crash on unreadable input"
    posture as facts.FileStat.mode being None.
    """
    rows = []
    for line in passwd_text.splitlines():
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        rows.append(fields)
    return rows


def _evaluate_shadow_password_fields_not_empty(facts: SystemFacts) -> bool:
    """Real audit (e.g. CIS Debian 12, control 7.2.1): `awk -F: '($2 == ""
    ) {print $1}' /etc/shadow` must return nothing -- every account's
    password field (colon field 2) must be set to something (a hash, or a
    lock marker like `*`/`!`), never empty.
    """
    for fields in _passwd_fields(facts.shadow_text):
        if fields[1] == "":
            return False
    return True


def _evidence_shadow_password_fields_not_empty(facts: SystemFacts) -> str:
    empty_users = [f[0] for f in _passwd_fields(facts.shadow_text) if f[1] == ""]
    if empty_users:
        return f"/etc/shadow: empty password field for: {', '.join(empty_users)}"
    return "/etc/shadow: no empty password fields"


def _evaluate_passwd_accounts_use_shadowed_passwords(facts: SystemFacts) -> bool:
    """Real audit: `awk -F: '($2 != "x") {print $1}' /etc/passwd` must
    return nothing -- every account's /etc/passwd password field (colon
    field 2) must be the literal "x", meaning the real hash lives in
    /etc/shadow instead of sitting in the world-readable passwd file.
    """
    for fields in _passwd_fields(facts.passwd_text):
        if fields[1] != "x":
            return False
    return True


def _evidence_passwd_accounts_use_shadowed_passwords(facts: SystemFacts) -> str:
    not_shadowed = [f[0] for f in _passwd_fields(facts.passwd_text) if f[1] != "x"]
    if not_shadowed:
        return f"/etc/passwd: not using shadowed passwords: {', '.join(not_shadowed)}"
    return "/etc/passwd: all accounts use shadowed passwords"


_GID0_EXCLUDED_PREFIXES = ("sync", "shutdown", "halt", "operator")


def _evaluate_root_only_gid0_account(facts: SystemFacts) -> bool:
    """Real audit (CIS Debian 12/13, 7.2.5): `awk -F: '($1 !~
    /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1}' /etc/passwd`
    must return only "root" -- no account other than root (and a handful
    of system accounts the benchmark excludes by name) may have primary
    GID 0.
    """
    gid0_accounts = [
        fields[0]
        for fields in _passwd_fields(facts.passwd_text)
        if not fields[0].startswith(_GID0_EXCLUDED_PREFIXES) and fields[3] == "0"
    ]
    return gid0_accounts == ["root"]


def _evidence_root_only_gid0_account(facts: SystemFacts) -> str:
    gid0_accounts = [
        fields[0]
        for fields in _passwd_fields(facts.passwd_text)
        if not fields[0].startswith(_GID0_EXCLUDED_PREFIXES) and fields[3] == "0"
    ]
    return f"/etc/passwd: (non-excluded) accounts with primary GID 0: {', '.join(gid0_accounts) or '<none>'}"


def _evaluate_root_only_uid0_account(facts: SystemFacts) -> bool:
    """Real audit: `awk -F: '($3 == 0) {print $1}' /etc/passwd` must
    return only "root" -- no other account may have UID 0.
    """
    uid0_accounts = [fields[0] for fields in _passwd_fields(facts.passwd_text) if fields[2] == "0"]
    return uid0_accounts == ["root"]


def _evidence_root_only_uid0_account(facts: SystemFacts) -> str:
    uid0_accounts = [fields[0] for fields in _passwd_fields(facts.passwd_text) if fields[2] == "0"]
    return f"/etc/passwd: UID 0 accounts: {', '.join(uid0_accounts) or '<none>'}"


def _group_fields(group_text: str) -> list[list[str]]:
    rows = []
    for line in group_text.splitlines():
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) < 3:
            continue
        rows.append(fields)
    return rows


def _evaluate_only_root_group_has_gid0(facts: SystemFacts) -> bool:
    """Real audit: `awk -F: '$3=="0"{print $1}' /etc/group` must return
    only "root" -- no group other than root may be assigned GID 0.
    """
    gid0_groups = [fields[0] for fields in _group_fields(facts.group_text) if fields[2] == "0"]
    return gid0_groups == ["root"]


def _evidence_only_root_group_has_gid0(facts: SystemFacts) -> str:
    gid0_groups = [fields[0] for fields in _group_fields(facts.group_text) if fields[2] == "0"]
    return f"/etc/group: GID 0 assigned to: {', '.join(gid0_groups) or '<none>'}"


def _evaluate_pam_faillock_enabled(facts: SystemFacts) -> bool:
    """Matches the real audit command (e.g. debian_linux_12's "Ensure
    pam_faillock module is enabled"): `grep pam_faillock.so
    /etc/pam.d/common-{auth,account}` -- the module must show up in BOTH
    files, not just one, since faillock needs an auth hook (to count/deny
    attempts) and an account hook (to enforce the lockout) to actually work.
    """
    return "pam_faillock.so" in facts.pam_common_auth and "pam_faillock.so" in facts.pam_common_account


def _evidence_pam_faillock_enabled(facts: SystemFacts) -> str:
    auth = "present" if "pam_faillock.so" in facts.pam_common_auth else "missing"
    account = "present" if "pam_faillock.so" in facts.pam_common_account else "missing"
    return f"pam_faillock.so: common-auth={auth}, common-account={account}"


def _evaluate_pam_pwquality_enabled(facts: SystemFacts) -> bool:
    """Matches the real audit command: `grep pam_pwquality.so
    /etc/pam.d/common-password`."""
    return "pam_pwquality.so" in facts.pam_common_password


def _evidence_pam_pwquality_enabled(facts: SystemFacts) -> str:
    present = "present" if "pam_pwquality.so" in facts.pam_common_password else "missing"
    return f"pam_pwquality.so in common-password: {present}"


def _evaluate_pam_pwhistory_enabled(facts: SystemFacts) -> bool:
    """Matches the real audit command: `grep pam_pwhistory.so
    /etc/pam.d/common-password`."""
    return "pam_pwhistory.so" in facts.pam_common_password


def _evidence_pam_pwhistory_enabled(facts: SystemFacts) -> str:
    present = "present" if "pam_pwhistory.so" in facts.pam_common_password else "missing"
    return f"pam_pwhistory.so in common-password: {present}"


def _pam_unix_nullok_lines(facts: SystemFacts) -> list[str]:
    """Lines across common-auth/common-password/common-account that
    configure pam_unix.so with the nullok argument -- nullok is what lets
    an account with an empty password field authenticate with no password
    at all. The real audit (e.g. debian_linux_12's "Ensure pam_unix does
    not include nullok") also checks common-session and
    common-session-noninteractive, but facts.SystemFacts doesn't collect
    those two files -- see the final summary for that gap.
    """
    offending = []
    for text in (facts.pam_common_auth, facts.pam_common_password, facts.pam_common_account):
        for line in text.splitlines():
            if "pam_unix.so" in line and "nullok" in line:
                offending.append(line.strip())
    return offending


def _evaluate_pam_no_nullok(facts: SystemFacts) -> bool:
    return len(_pam_unix_nullok_lines(facts)) == 0


def _evidence_pam_no_nullok(facts: SystemFacts) -> str:
    lines = _pam_unix_nullok_lines(facts)
    if not lines:
        return "no nullok found on pam_unix.so lines in common-auth/common-password/common-account"
    return "nullok found: " + " | ".join(lines)


# Group G: password quality/history, via pwquality.conf and pwhistory.conf.
def parse_pwquality_conf(text: str) -> dict[str, str]:
    """Parses "key = value" lines from pwquality.conf/pwhistory.conf -- both
    files share this exact format (comments/blank lines skipped, later lines
    win, same convention as parse_login_defs()). Boolean-style options like
    enforce_for_root appear on their own line with no "=" at all; those map
    to "" so a plain membership check (`"enforce_for_root" in directives`)
    is enough to detect them, matching the real audit's `grep
    '^\\h*enforce_for_root\\b'`.
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, value = stripped.partition("=")
        directives[key.strip().lower()] = value.strip() if sep else ""
    return directives


def _evaluate_pwquality_enforce_for_root(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.2.8, "Ensure password quality
    is enforced for the root user"): `grep -Psi '^\\h*enforce_for_root\\b'
    /etc/security/pwquality.conf ...` -- presence of the directive is what's
    checked, not a value (it's a bare flag).
    """
    return "enforce_for_root" in parse_pwquality_conf(facts.pwquality_text)


def _evidence_pwquality_enforce_for_root(facts: SystemFacts) -> str:
    present = "present" if "enforce_for_root" in parse_pwquality_conf(facts.pwquality_text) else "missing"
    return f"pwquality.conf: enforce_for_root {present}"


def _evaluate_pwquality_minlen(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.2.2): `grep -Psi
    '^\\h*minlen\\h*=\\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\\b'
    /etc/security/pwquality.conf`, i.e. minlen must be set and >= 14.
    """
    value = parse_pwquality_conf(facts.pwquality_text).get("minlen")
    if value is None:
        return False
    try:
        return int(value) >= 14
    except ValueError:
        return False


def _evidence_pwquality_minlen(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("minlen", "<not set>")
    return f"pwquality.conf: minlen {value}"


# The real audit (control 5.3.3.2.3, "Ensure password complexity is
# configured") just greps for minclass/[dulo]credit and asks a human to
# judge "conforms to local site policy" against its own example
# (minclass=3, or ucredit=-2/lcredit=-2/dcredit=-1/ocredit=0) -- there's no
# single documented pass/fail threshold to lift verbatim, so this evaluator
# adopts that example as the threshold: either minclass requires at least 3
# character classes, or at least 3 of the 4 [dulo]credit knobs are set to
# mandatory (negative) with none left positive (positive relaxes, rather
# than tightens, pam_pwquality's default policy).
_PWQUALITY_CREDIT_KEYS = ("dcredit", "ucredit", "lcredit", "ocredit")


def _evaluate_pwquality_complexity(facts: SystemFacts) -> bool:
    directives = parse_pwquality_conf(facts.pwquality_text)

    minclass = directives.get("minclass")
    if minclass is not None:
        try:
            if int(minclass) >= 3:
                return True
        except ValueError:
            pass

    credit_values = []
    for key in _PWQUALITY_CREDIT_KEYS:
        value = directives.get(key)
        if value is None:
            continue
        try:
            credit_values.append(int(value))
        except ValueError:
            continue
    negative = sum(1 for v in credit_values if v < 0)
    positive = any(v > 0 for v in credit_values)
    return negative >= 3 and not positive


def _evidence_pwquality_complexity(facts: SystemFacts) -> str:
    directives = parse_pwquality_conf(facts.pwquality_text)
    parts = [f"{key}={directives[key]}" for key in ("minclass", *_PWQUALITY_CREDIT_KEYS) if key in directives]
    if not parts:
        return "pwquality.conf: none of minclass/dcredit/ucredit/lcredit/ocredit set"
    return "pwquality.conf: " + ", ".join(parts)


def _evaluate_pwquality_max_repeat(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.2.4, "Ensure password same
    consecutive characters is configured"): maxrepeat must be set, 3 or
    less, and not 0 (0 disables the check entirely per pwquality.conf's own
    documentation).
    """
    value = parse_pwquality_conf(facts.pwquality_text).get("maxrepeat")
    if value is None:
        return False
    try:
        n = int(value)
    except ValueError:
        return False
    return 1 <= n <= 3


def _evidence_pwquality_max_repeat(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("maxrepeat", "<not set>")
    return f"pwquality.conf: maxrepeat {value}"


def _evaluate_pwquality_max_sequence(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.2.5, "Ensure password maximum
    sequential characters is configured"): maxsequence must be set, 3 or
    less, and not 0 -- same shape as maxrepeat above.
    """
    value = parse_pwquality_conf(facts.pwquality_text).get("maxsequence")
    if value is None:
        return False
    try:
        n = int(value)
    except ValueError:
        return False
    return 1 <= n <= 3


def _evidence_pwquality_max_sequence(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("maxsequence", "<not set>")
    return f"pwquality.conf: maxsequence {value}"


def _evaluate_pwquality_difok(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.2.1, "Ensure password number of
    changed characters is configured"): difok must be set and >= 2.
    """
    value = parse_pwquality_conf(facts.pwquality_text).get("difok")
    if value is None:
        return False
    try:
        return int(value) >= 2
    except ValueError:
        return False


def _evidence_pwquality_difok(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("difok", "<not set>")
    return f"pwquality.conf: difok {value}"


def _pam_pwhistory_line(facts: SystemFacts) -> str:
    """The common-password line configuring pam_pwhistory.so, if any --
    shared by both password-history evaluators below.
    """
    for line in facts.pam_common_password.splitlines():
        if "pam_pwhistory.so" in line:
            return line.strip()
    return ""


def _pam_pwhistory_remember(facts: SystemFacts) -> int | None:
    match = re.search(r"remember=(\d+)", _pam_pwhistory_line(facts))
    return int(match.group(1)) if match else None


def _evaluate_pwhistory_remember(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.3.1, "Ensure password history
    remember is configured"): remember must be >= 24. The real audit text
    documents two valid locations that drift by document -- debian_linux_11
    and ubuntu_linux_20_04/22_04/24_04 only document the pam_pwhistory.so
    remember=<N> argument on common-password's pwhistory line; debian_linux_
    12/13 (and ubuntu_linux_24_04, as a fallback) also accept /etc/security/
    pwhistory.conf's own remember= directive. Both are checked here -- either
    one meeting the threshold passes, matching how the real audit treats
    them as interchangeable.
    """
    conf_value = parse_pwquality_conf(facts.pwhistory_text).get("remember")
    if conf_value is not None:
        try:
            if int(conf_value) >= 24:
                return True
        except ValueError:
            pass
    remember = _pam_pwhistory_remember(facts)
    return remember is not None and remember >= 24


def _evidence_pwhistory_remember(facts: SystemFacts) -> str:
    conf_value = parse_pwquality_conf(facts.pwhistory_text).get("remember", "<not set>")
    remember = _pam_pwhistory_remember(facts)
    pam_value = str(remember) if remember is not None else "<not set>"
    return f"pwhistory.conf: remember {conf_value}; common-password pam_pwhistory.so: remember {pam_value}"


def _evaluate_pwhistory_enforce_for_root(facts: SystemFacts) -> bool:
    """Matches the real audit (control 5.3.3.3.2, "Ensure password history
    is enforced for the root user") -- same two-location split as
    _evaluate_pwhistory_remember() above, for the same reason.
    """
    if "enforce_for_root" in parse_pwquality_conf(facts.pwhistory_text):
        return True
    return "enforce_for_root" in _pam_pwhistory_line(facts)


def _evidence_pwhistory_enforce_for_root(facts: SystemFacts) -> str:
    conf_present = "present" if "enforce_for_root" in parse_pwquality_conf(facts.pwhistory_text) else "missing"
    pam_present = "present" if "enforce_for_root" in _pam_pwhistory_line(facts) else "missing"
    return f"pwhistory.conf: enforce_for_root {conf_present}; common-password pam_pwhistory.so: enforce_for_root {pam_present}"


def parse_login_defs(text: str) -> dict[str, str]:
    """Parses "KEY value" lines from /etc/login.defs -- same shape as
    parse_sshd_config() in facts.py (comments/blank lines skipped, later
    lines win), just uppercase keys since that's login.defs' own
    convention (UMASK, ENCRYPT_METHOD, PASS_MAX_DAYS, ...).
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        directives[key.upper()] = value.strip()
    return directives


def _evaluate_default_umask(facts: SystemFacts) -> bool:
    """Matches the real audit command (e.g. debian_linux_12's "Ensure
    default user umask is configured"): `grep UMASK /etc/login.defs`,
    value must be 027 or more restrictive. "More restrictive" means at
    least those bits are masked (denied) -- checking `umask & 0o027 ==
    0o027` accepts 027 itself and anything stricter (037, 077, ...)
    without hardcoding a single allowed value.
    """
    value = parse_login_defs(facts.login_defs_text).get("UMASK")
    if value is None:
        return False
    try:
        umask = int(value, 8)
    except ValueError:
        return False
    return (umask & 0o027) == 0o027


def _evidence_default_umask(facts: SystemFacts) -> str:
    value = parse_login_defs(facts.login_defs_text).get("UMASK", "<not set>")
    return f"login.defs: UMASK {value}"


def _evaluate_ssh_max_sessions(facts: SystemFacts) -> bool:
    value = facts.sshd_config.get("maxsessions", "")
    try:
        return int(value) <= 10
    except ValueError:
        return False


def _evidence_ssh_max_sessions(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("maxsessions", "<not set>")
    return f"sshd_config: MaxSessions {value}"


def _evaluate_ssh_log_level(facts: SystemFacts) -> bool:
    """Matches the real audit condition (control 5.1.14 in our two demo
    documents): "verify that output matches loglevel VERBOSE or loglevel
    INFO" -- both are accepted, not just INFO. (Some older CIS documents,
    e.g. ubuntu_linux_12_04/14_04, have a stricter "LogLevel is set to
    INFO" control that rejects VERBOSE -- that's a different control with
    different pass criteria, not merged in here.)
    """
    return facts.sshd_config.get("loglevel", "").lower() in ("info", "verbose")


def _evidence_ssh_log_level(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("loglevel", "<not set>")
    return f"sshd_config: LogLevel {value}"


def _evaluate_ssh_use_pam(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("usepam", "").lower() == "yes"


def _evidence_ssh_use_pam(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("usepam", "<not set>")
    return f"sshd_config: UsePAM {value}"


def _evaluate_ssh_disable_forwarding(facts: SystemFacts) -> bool:
    """This is the modern replacement for the CIS "AllowTcpForwarding is
    disabled" control originally scoped for this check: both of our real
    demo documents (debian_linux_11, ubuntu_linux_20_04) use a single
    DisableForwarding directive (OpenSSH 8.7+) that disables all forwarding
    types at once, not per-directive AllowTcpForwarding/AllowAgentForwarding
    controls -- "Ensure SSH AllowTcpForwarding is disabled" doesn't exist as
    a title in either document (confirmed via Postgres), so it was dropped
    in favor of this real, resolvable control.
    """
    return facts.sshd_config.get("disableforwarding", "").lower() == "yes"


def _evidence_ssh_disable_forwarding(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("disableforwarding", "<not set>")
    return f"sshd_config: DisableForwarding {value}"


# Ciphers flagged "weak" by the real CIS audit regex (control 5.1.6):
# cbc-mode 3des/blowfish/cast128/aes, arcfour variants, an old rijndael-cbc
# alias, and chacha20-poly1305@openssh.com (flagged for CVE-2023-48795,
# the Terrapin attack, unless patched -- treated as weak here since the
# audit command itself flags it unconditionally and a patch level isn't
# something facts.py collects).
_WEAK_CIPHER_RE = re.compile(
    r"^(3des|blowfish|cast128|aes(128|192|256))-cbc$"
    r"|^arcfour(128|256)?$"
    r"|^rijndael-cbc@lysator\.liu\.se$"
    r"|^chacha20-poly1305@openssh\.com$"
)


def _evaluate_ssh_ciphers(facts: SystemFacts) -> bool:
    ciphers = facts.sshd_config.get("ciphers", "")
    if not ciphers:
        return False
    return not any(_WEAK_CIPHER_RE.match(c.strip().lower()) for c in ciphers.split(","))


def _evidence_ssh_ciphers(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("ciphers", "<not set>")
    return f"sshd_config: Ciphers {value}"


# Key exchange algorithms flagged "weak" by the real CIS audit (control
# 5.1.12) -- the plain "weak KexAlgorithms" control that applies to our
# demo documents, not the separate FIPS-validated-allowlist variant (only
# present in *_stig documents, which aren't among our demo targets).
_WEAK_KEX_ALGORITHMS = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}


def _evaluate_ssh_kex_algorithms(facts: SystemFacts) -> bool:
    kex = facts.sshd_config.get("kexalgorithms", "")
    if not kex:
        return False
    algorithms = {a.strip().lower() for a in kex.split(",")}
    return not (algorithms & _WEAK_KEX_ALGORITHMS)


def _evidence_ssh_kex_algorithms(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("kexalgorithms", "<not set>")
    return f"sshd_config: KexAlgorithms {value}"


_PRIVATE_HOST_KEY_PATHS = [
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
]

_PUBLIC_HOST_KEY_PATHS = [
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_ed25519_key.pub",
]


def _evaluate_ssh_private_host_key_permissions(facts: SystemFacts) -> bool:
    """Mode 0600 or more restrictive, owned by root, for each private host
    key file that exists -- a simplified version of the real CIS audit
    script, which also accepts group-owned 0640 for a dedicated
    ssh_keys/_ssh group; none of our demo targets use that group, so it's
    not modeled here. A target with no host key files present passes (same
    as the real audit script's "No openSSH private keys found" -> PASS),
    since that's a "nothing to secure" state, not a misconfiguration.
    """
    present = [facts.file_stats[p] for p in _PRIVATE_HOST_KEY_PATHS if facts.file_stats.get(p) and facts.file_stats[p].mode is not None]
    if not present:
        return True
    return all(stat.mode <= 0o600 and stat.uid == 0 for stat in present)


def _evidence_ssh_private_host_key_permissions(facts: SystemFacts) -> str:
    parts = [
        f"{path}: mode={oct(stat.mode)} uid={stat.uid}"
        for path in _PRIVATE_HOST_KEY_PATHS
        if (stat := facts.file_stats.get(path)) and stat.mode is not None
    ]
    return "; ".join(parts) if parts else "no SSH private host key files found"


def _evaluate_ssh_public_host_key_permissions(facts: SystemFacts) -> bool:
    """Mode 0644 or more restrictive, owned by root:root, for each public
    host key file that exists. Same "nothing to secure" PASS as the private
    key check when no host key files are present.
    """
    present = [facts.file_stats[p] for p in _PUBLIC_HOST_KEY_PATHS if facts.file_stats.get(p) and facts.file_stats[p].mode is not None]
    if not present:
        return True
    return all(stat.mode <= 0o644 and stat.uid == 0 and stat.gname == "root" for stat in present)


def _evidence_ssh_public_host_key_permissions(facts: SystemFacts) -> str:
    parts = [
        f"{path}: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"
        for path in _PUBLIC_HOST_KEY_PATHS
        if (stat := facts.file_stats.get(path)) and stat.mode is not None
    ]
    return "; ".join(parts) if parts else "no SSH public host key files found"


def _packages_absent(facts: SystemFacts, *names: str) -> bool:
    """True if none of `names` are in the collected package set -- the
    shared shape behind every "package X is not installed" check below.
    Some CIS documents ask for more than one package name to cover a
    rename/alternate across releases (e.g. "telnet" vs "inetutils-telnet");
    passing every known name and requiring all of them absent is a safe
    superset of the single-name audits, since on a genuinely clean system
    every name in the set is absent anyway.
    """
    return not any(name in facts.installed_packages for name in names)


def _evaluate_ldap_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "ldap-utils")


def _evidence_ldap_client_not_installed(facts: SystemFacts) -> str:
    present = "ldap-utils" in facts.installed_packages
    return f"installed_packages: ldap-utils {'present' if present else 'absent'}"


def _evaluate_nis_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "nis")


def _evidence_nis_client_not_installed(facts: SystemFacts) -> str:
    present = "nis" in facts.installed_packages
    return f"installed_packages: nis {'present' if present else 'absent'}"


def _evaluate_xinetd_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "xinetd")


def _evidence_xinetd_not_installed(facts: SystemFacts) -> str:
    present = "xinetd" in facts.installed_packages
    return f"installed_packages: xinetd {'present' if present else 'absent'}"


def _evaluate_rsync_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "rsync")


def _evidence_rsync_not_installed(facts: SystemFacts) -> str:
    present = "rsync" in facts.installed_packages
    return f"installed_packages: rsync {'present' if present else 'absent'}"


def _evaluate_x_window_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "xserver-common")


def _evidence_x_window_not_installed(facts: SystemFacts) -> str:
    present = "xserver-common" in facts.installed_packages
    return f"installed_packages: xserver-common {'present' if present else 'absent'}"


def _evaluate_telnet_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "telnet", "inetutils-telnet")


def _evidence_telnet_client_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("telnet", "inetutils-telnet") if p in facts.installed_packages]
    return f"installed_packages: telnet/inetutils-telnet {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_rsh_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "rsh-client")


def _evidence_rsh_client_not_installed(facts: SystemFacts) -> str:
    present = "rsh-client" in facts.installed_packages
    return f"installed_packages: rsh-client {'present' if present else 'absent'}"


def _evaluate_ftp_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "ftp", "tnftp")


def _evidence_ftp_client_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("ftp", "tnftp") if p in facts.installed_packages]
    return f"installed_packages: ftp/tnftp {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_talk_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "talk")


def _evidence_talk_client_not_installed(facts: SystemFacts) -> str:
    present = "talk" in facts.installed_packages
    return f"installed_packages: talk {'present' if present else 'absent'}"


def _evaluate_prelink_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "prelink")


def _evidence_prelink_not_installed(facts: SystemFacts) -> str:
    present = "prelink" in facts.installed_packages
    return f"installed_packages: prelink {'present' if present else 'absent'}"


# Group K: package presence -- the opposite direction of the "not installed"
# checks above, same installed_packages field. "Ensure ufw is installed" is
# the only one of 3 candidates that resolves for all 6 real target documents
# (confirmed via Postgres); the other two were dropped -- see the comment
# above the Group K CHECKS entries near the end of this list.
def _evaluate_ufw_installed(facts: SystemFacts) -> bool:
    return "ufw" in facts.installed_packages


def _evidence_ufw_installed(facts: SystemFacts) -> str:
    present = "ufw" in facts.installed_packages
    return f"installed_packages: ufw {'present' if present else 'absent'}"


# Group M: unused network service packages, batch A (round 2). Same
# "package must NOT be installed" shape as the client-side checks above,
# just server-side daemons -- confirmed via Postgres audit text across all
# 6 target documents (debian_linux_11/12/13, ubuntu_linux_20_04/22_04/24_04)
# that each title's audit opens with a `dpkg-query -s <pkg>` (or, for the
# renamed dhcp package, a `dpkg-query -l | grep 'kea'` substring match
# against the real "kea" meta-package) check against the exact package
# named below -- an "enabled/active" fallback branch follows in the real
# audit text ("- OR - - IF - the package is required as a dependency:
# ...systemctl is-enabled/is-active...") but facts.py doesn't collect
# systemd unit state, so (same as every other package-absent check in this
# file) only the package-installed condition is evaluated here.
def _evaluate_avahi_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "avahi-daemon")


def _evidence_avahi_not_in_use(facts: SystemFacts) -> str:
    present = "avahi-daemon" in facts.installed_packages
    return f"installed_packages: avahi-daemon {'present' if present else 'absent'}"


def _evaluate_bluetooth_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "bluez")


def _evidence_bluetooth_not_in_use(facts: SystemFacts) -> str:
    present = "bluez" in facts.installed_packages
    return f"installed_packages: bluez {'present' if present else 'absent'}"


# isc-dhcp-server (debian_11, ubuntu_20_04, ubuntu_22_04) was replaced by
# kea (debian_12, debian_13, ubuntu_24_04) -- confirmed via Postgres, same
# split as telnet/inetutils-telnet above. Both must be absent to PASS.
def _evaluate_dhcp_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "isc-dhcp-server", "kea")


def _evidence_dhcp_server_not_in_use(facts: SystemFacts) -> str:
    present = [p for p in ("isc-dhcp-server", "kea") if p in facts.installed_packages]
    return f"installed_packages: isc-dhcp-server/kea {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_dns_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "bind9")


def _evidence_dns_server_not_in_use(facts: SystemFacts) -> str:
    present = "bind9" in facts.installed_packages
    return f"installed_packages: bind9 {'present' if present else 'absent'}"


def _evaluate_dnsmasq_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "dnsmasq")


def _evidence_dnsmasq_not_in_use(facts: SystemFacts) -> str:
    present = "dnsmasq" in facts.installed_packages
    return f"installed_packages: dnsmasq {'present' if present else 'absent'}"


# ubuntu_linux_22_04's audit text for this control has an internal
# copy/paste glitch: its opening line still says "verify vsftpd is not
# installed", but the dpkg-query command pasted under it greps for
# "ftp"/"tnftp" -- the FTP *client* packages, i.e. the same audit command
# already used for the unrelated "Ensure ftp client is not installed"
# control (_evaluate_ftp_client_not_installed above). Everything else in
# that same document's audit block (the "- OR -" is-enabled/is-active
# fallback, the closing notes) keeps referring to "vsftpd service", and
# all other 5 documents check vsftpd cleanly -- so this is treated as a
# PDF extraction artifact in that one document, not a genuinely different
# condition, and vsftpd is checked uniformly across all 6.
def _evaluate_ftp_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "vsftpd")


def _evidence_ftp_server_not_in_use(facts: SystemFacts) -> str:
    present = "vsftpd" in facts.installed_packages
    return f"installed_packages: vsftpd {'present' if present else 'absent'}"


def _evaluate_ldap_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "slapd")


def _evidence_ldap_server_not_in_use(facts: SystemFacts) -> str:
    present = "slapd" in facts.installed_packages
    return f"installed_packages: slapd {'present' if present else 'absent'}"


# Two distinct real packages (IMAP and POP3 servers), not name-drift
# aliases like isc-dhcp-server/kea above -- the real audit checks each
# with its own separate dpkg-query line, and either one present is a
# finding, so both must be absent to PASS.
def _evaluate_message_access_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "dovecot-imapd", "dovecot-pop3d")


def _evidence_message_access_server_not_in_use(facts: SystemFacts) -> str:
    present = [p for p in ("dovecot-imapd", "dovecot-pop3d") if p in facts.installed_packages]
    return f"installed_packages: dovecot-imapd/dovecot-pop3d {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_nfs_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "nfs-kernel-server")


def _evidence_nfs_server_not_in_use(facts: SystemFacts) -> str:
    present = "nfs-kernel-server" in facts.installed_packages
    return f"installed_packages: nfs-kernel-server {'present' if present else 'absent'}"


def _evaluate_nis_server_not_in_use(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "ypserv")


def _evidence_nis_server_not_in_use(facts: SystemFacts) -> str:
    present = "ypserv" in facts.installed_packages
    return f"installed_packages: ypserv {'present' if present else 'absent'}"


# Group I: auditd config/tooling file ownership + rules immutability. Real
# audit commands (e.g. debian_linux_11 6.4.4.6/6.4.4.7/6.4.4.9/6.4.4.10)
# check a whole file set -- `find /etc/audit/ -type f ( *.conf -o *.rules )
# ! -user root` for config files, `stat -Lc "%n %U" /sbin/auditctl
# /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules`
# for tools -- wider than what facts._STAT_PATHS collects (no
# /etc/audit/auditd.conf, no /sbin/aureport, /sbin/ausearch, /sbin/autrace).
# _owner_ok() below checks ownership only over the subset of each set that
# facts.py actually stats; a facts.py extension to add the missing paths
# would tighten this, but isn't needed to exercise the real behavior these
# controls care about (are the audit config/tool files root-owned).
_AUDIT_CONFIG_PATHS = ["/etc/audit/audit.rules", "/etc/audit/rules.d"]
_AUDIT_TOOL_PATHS = ["/sbin/auditctl", "/sbin/auditd", "/sbin/augenrules"]


def _owner_ok(
    facts: SystemFacts,
    paths: list[str],
    *,
    uid: int | None = None,
    gnames: tuple[str, ...] | None = None,
) -> bool:
    """Shared by the Group I audit-file ownership checks: every path in
    `paths` must be present in facts.file_stats and match the given uid
    and/or group name(s). A path that failed to stat (or wasn't collected)
    fails closed, same posture as _permissions_ok above.
    """
    for path in paths:
        stat = facts.file_stats.get(path)
        if stat is None or stat.uid is None:
            return False
        if uid is not None and stat.uid != uid:
            return False
        if gnames is not None and stat.gname not in gnames:
            return False
    return True


def _evidence_for_stats(paths: list[str]) -> Callable[[SystemFacts], str]:
    def _evidence(facts: SystemFacts) -> str:
        parts = []
        for path in paths:
            stat = facts.file_stats.get(path)
            if stat is None or stat.uid is None:
                parts.append(f"{path}: could not stat")
            else:
                parts.append(f"{path}: uid={stat.uid} gid={stat.gid}({stat.gname})")
        return " | ".join(parts)

    return _evidence


def _evaluate_audit_config_files_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_CONFIG_PATHS, uid=0)


_evidence_audit_config_files_owner = _evidence_for_stats(_AUDIT_CONFIG_PATHS)


def _evaluate_audit_config_files_group_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_CONFIG_PATHS, gnames=("root",))


_evidence_audit_config_files_group_owner = _evidence_for_stats(_AUDIT_CONFIG_PATHS)


def _evaluate_audit_tools_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_TOOL_PATHS, uid=0)


_evidence_audit_tools_owner = _evidence_for_stats(_AUDIT_TOOL_PATHS)


def _evaluate_audit_tools_group_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_TOOL_PATHS, gnames=("root",))


_evidence_audit_tools_group_owner = _evidence_for_stats(_AUDIT_TOOL_PATHS)


# Real audit (e.g. debian_linux_11 6.4.3.20): `grep -Ph -- '^\h*-e\h+2\b'
# /etc/audit/rules.d/*.rules | tail -1` must print "-e 2" -- the immutable
# flag has to be the last line loaded so no further rule changes can take
# effect without a reboot. facts.audit_rules_text concatenates
# rules.d/*.rules then audit.rules (the latter is generated from the
# former by augenrules on a working system, so they agree); a simple
# presence check over that combined text is equivalent here since the
# pattern only ever matches an actual "-e 2" line.
_AUDIT_IMMUTABLE_RE = re.compile(r"^\s*-e\s+2\b", re.MULTILINE)


def _evaluate_audit_config_immutable(facts: SystemFacts) -> bool:
    return bool(_AUDIT_IMMUTABLE_RE.search(facts.audit_rules_text))


def _evidence_audit_config_immutable(facts: SystemFacts) -> str:
    matches = _AUDIT_IMMUTABLE_RE.findall(facts.audit_rules_text)
    if not matches:
        return "audit rules: no '-e 2' (immutable) line found"
    return f"audit rules: found {len(matches)} '-e 2' line(s)"


def _sudoers_active_lines(text: str) -> list[str]:
    """Non-blank, non-comment lines from /etc/sudoers text -- comment
    detection follows the same "strip, then check for a leading #" rule as
    the pam_unix nullok check above, not the real audit's stricter
    "^[^#]" grep (which would also flag an indented "  # ..." line as
    active) -- same posture already established in this module.
    """
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def _evaluate_sudo_no_nopasswd(facts: SystemFacts) -> bool:
    """Real audit (control 5.2.4, e.g. debian_linux_12's "Ensure users
    must provide password for escalation"; debian_linux_11/ubuntu_20_04
    word it "...for privilege escalation"): `grep -r "^[^#].*NOPASSWD"
    /etc/sudoers*` must return nothing -- no active sudoers line may grant
    NOPASSWD privilege escalation. facts.py only collects /etc/sudoers
    itself, not /etc/sudoers.d/* -- a drop-in NOPASSWD rule there would be
    invisible to this check, same "known gap" posture as the nullok
    check's missing common-session files (see module docstring notes
    below the CHECKS list).
    """
    return not any("NOPASSWD" in line for line in _sudoers_active_lines(facts.sudoers_text))


def _evidence_sudo_no_nopasswd(facts: SystemFacts) -> str:
    offending = [line for line in _sudoers_active_lines(facts.sudoers_text) if "NOPASSWD" in line]
    if offending:
        return "sudoers: NOPASSWD found: " + " | ".join(offending)
    return "sudoers: no NOPASSWD entries"


def _evaluate_sudo_reauthentication_required(facts: SystemFacts) -> bool:
    """Real audit (control 5.2.5, "Ensure re-authentication for privilege
    escalation is not disabled globally" -- identical title text in all 6
    real target documents): `grep -r "^[^#].*\\!authenticate"
    /etc/sudoers*` must return nothing -- no active line may carry a
    !authenticate tag, which lets a user run sudo without re-entering
    their password at all.
    """
    return not any("!authenticate" in line for line in _sudoers_active_lines(facts.sudoers_text))


def _evidence_sudo_reauthentication_required(facts: SystemFacts) -> str:
    offending = [line for line in _sudoers_active_lines(facts.sudoers_text) if "!authenticate" in line]
    if offending:
        return "sudoers: !authenticate found: " + " | ".join(offending)
    return "sudoers: no !authenticate entries"


_SUDO_LOGFILE_RE = re.compile(r"(?i)^Defaults\b.*\blogfile\s*=\s*\S")


def _evaluate_sudo_log_file_exists(facts: SystemFacts) -> bool:
    """Real audit (control 5.2.3, "Ensure sudo log file exists" --
    identical title text in all 6 real target documents): grep for a
    `Defaults ... logfile=...` line in /etc/sudoers*.
    """
    return any(_SUDO_LOGFILE_RE.match(line) for line in _sudoers_active_lines(facts.sudoers_text))


def _evidence_sudo_log_file_exists(facts: SystemFacts) -> str:
    match = next((line for line in _sudoers_active_lines(facts.sudoers_text) if _SUDO_LOGFILE_RE.match(line)), None)
    return f"sudoers: {match}" if match else "sudoers: no Defaults logfile= line found"


# Group H: cron file/directory permissions. Same real audit shape as
# _permissions_ok's other users -- stat mode <= a ceiling, Uid 0/root, Gid
# 0/root -- just a 0600 ceiling for the /etc/crontab file and a 0700
# ceiling for the five cron.* directories (confirmed against live
# containers: openssh-server-style packaged defaults are 644/755, i.e.
# world-readable and non-compliant out of the box, the same gotcha already
# noted for sshd_config's own file permissions).
def _evaluate_crontab_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/crontab", 0o600, ("root",))


_evidence_crontab_permissions = _evidence_for_stat("/etc/crontab")


def _evaluate_cron_hourly_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.hourly", 0o700, ("root",))


_evidence_cron_hourly_permissions = _evidence_for_stat("/etc/cron.hourly")


def _evaluate_cron_daily_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.daily", 0o700, ("root",))


_evidence_cron_daily_permissions = _evidence_for_stat("/etc/cron.daily")


def _evaluate_cron_weekly_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.weekly", 0o700, ("root",))


_evidence_cron_weekly_permissions = _evidence_for_stat("/etc/cron.weekly")


def _evaluate_cron_monthly_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.monthly", 0o700, ("root",))


_evidence_cron_monthly_permissions = _evidence_for_stat("/etc/cron.monthly")


def _evaluate_cron_d_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.d", 0o700, ("root",))


_evidence_cron_d_permissions = _evidence_for_stat("/etc/cron.d")


def parse_journald_conf(text: str) -> dict[str, str]:
    """Parses "Key=Value" lines from /etc/systemd/journald.conf -- same
    directive-file shape as parse_sshd_config()/parse_login_defs(), just
    with a `=` separator (systemd's own config-file convention) and
    lowercased keys for case-insensitive lookup. Comment lines (#, ;),
    blank lines, and section headers like [Journal] (no `=` in them) are
    skipped; later lines win on conflict.
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        directives[key.strip().lower()] = value.strip()
    return directives


def _evaluate_journald_compress(facts: SystemFacts) -> bool:
    """Matches the real audit command (identical across all 6 target
    documents): `grep -Psi "^Compress=yes" /etc/systemd/journald.conf`."""
    return parse_journald_conf(facts.journald_text).get("compress", "").lower() == "yes"


def _evidence_journald_compress(facts: SystemFacts) -> str:
    value = parse_journald_conf(facts.journald_text).get("compress", "<not set>")
    return f"journald.conf: Compress={value}"


def _evaluate_journald_storage(facts: SystemFacts) -> bool:
    """Matches the real audit command: `grep -Psi "^Storage=persistent"
    /etc/systemd/journald.conf`."""
    return parse_journald_conf(facts.journald_text).get("storage", "").lower() == "persistent"


def _evidence_journald_storage(facts: SystemFacts) -> str:
    value = parse_journald_conf(facts.journald_text).get("storage", "<not set>")
    return f"journald.conf: Storage={value}"


# The 5 log-rotation parameters the real audit greps for (control
# "Ensure journald log file rotation is configured"): `systemd-analyze
# cat-config systemd/journald.conf | ... grep -Psi --
# '\b(SystemMaxUse|SystemKeepFree|RuntimeMaxUse|RuntimeKeepFree|MaxFileSec)='`
# then asks a human to "verify logs are rotated according to site policy" --
# there's no single canonical value (it's site-policy-dependent), so the
# check models the audit's own bar: at least one of these directives is
# explicitly set to a non-empty value, not left at journald's defaults.
_JOURNALD_ROTATION_KEYS = (
    "systemmaxuse",
    "systemkeepfree",
    "runtimemaxuse",
    "runtimekeepfree",
    "maxfilesec",
)


def _evaluate_journald_log_rotation(facts: SystemFacts) -> bool:
    directives = parse_journald_conf(facts.journald_text)
    return any(directives.get(key) for key in _JOURNALD_ROTATION_KEYS)


def _evidence_journald_log_rotation(facts: SystemFacts) -> str:
    directives = parse_journald_conf(facts.journald_text)
    set_keys = [f"{key}={directives[key]}" for key in _JOURNALD_ROTATION_KEYS if directives.get(key)]
    if set_keys:
        return "journald.conf: " + ", ".join(set_keys)
    return "journald.conf: none of SystemMaxUse/SystemKeepFree/RuntimeMaxUse/RuntimeKeepFree/MaxFileSec are set"


# The real audit greps for `/nologin\b` (word boundary) on non-comment
# lines of /etc/shells -- catches both /sbin/nologin and /usr/sbin/nologin
# style paths, not just a literal "nologin" shell name.
_NOLOGIN_RE = re.compile(r"/nologin\b")


def _evaluate_shells_no_nologin(facts: SystemFacts) -> bool:
    for line in facts.shells_text.splitlines():
        if line.strip().startswith("#"):
            continue
        if _NOLOGIN_RE.search(line):
            return False
    return True


def _evidence_shells_no_nologin(facts: SystemFacts) -> str:
    offending = [
        line.strip()
        for line in facts.shells_text.splitlines()
        if not line.strip().startswith("#") and _NOLOGIN_RE.search(line)
    ]
    if offending:
        return "/etc/shells: nologin listed: " + ", ".join(offending)
    return "/etc/shells: nologin not listed"


def _evaluate_etc_motd_permissions(facts: SystemFacts) -> bool:
    """Real audit (e.g. debian_linux_11's 1.6.4): '[ -e /etc/motd ] && stat
    ... -- OR -- Nothing is returned' -- unlike the Group A files (which
    are always expected to exist), a missing /etc/motd is an explicitly
    documented PASS, not a fail-closed condition (confirmed empirically:
    plain ubuntu:22.04 ships with no /etc/motd at all). Permission
    comparison itself reuses _permissions_ok(), same as every other
    file-permission check.
    """
    stat = facts.file_stats.get("/etc/motd")
    if stat is None or stat.mode is None:
        return True
    return _permissions_ok(facts, "/etc/motd", 0o644, ("root",))


def _evidence_etc_motd_permissions(facts: SystemFacts) -> str:
    stat = facts.file_stats.get("/etc/motd")
    if stat is None or stat.mode is None:
        return "/etc/motd: absent (not configured -- passes per documented audit OR-clause)"
    return f"/etc/motd: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"


def _evaluate_bootloader_config_permissions(facts: SystemFacts) -> bool:
    """Real audit (e.g. debian_linux_12's 1.4.2): stat /boot/grub/grub.cfg,
    verify Uid/Gid both 0/root and mode 0600 or more restrictive -- unlike
    /etc/motd, there's no documented "file absent -> PASS" clause here, so
    a missing/unreadable file fails closed via _permissions_ok() (same
    posture as the shadow/passwd family): an unprotected or absent
    bootloader config can't be verified secure. Confirmed empirically that
    bare debian:12/ubuntu:22.04 images ship with no /boot/grub/grub.cfg at
    all (no bootloader installed in a container) -- this is exercised by a
    throwaway container with a fake grub.cfg created for validation, not by
    the real demo targets, which will all report FAIL for this reason.
    """
    return _permissions_ok(facts, "/boot/grub/grub.cfg", 0o600, ("root",))


_evidence_bootloader_config_permissions = _evidence_for_stat("/boot/grub/grub.cfg")


# Group F: remaining sshd_config directives (MACs, MaxStartups) + PAM/
# login.defs checks (pam_unix module family, pam_pwhistory use_authtok,
# login.defs password hashing algorithm). Two assigned candidates were
# dropped -- see the final summary below the CHECKS list.

# MACs flagged "weak" by the real CIS audit regex (control 5.1.15/5.1.16):
# broken/short-digest HMACs and the umac-64 family, with or without
# Encrypt-Then-Mac -- same "flagged unconditionally regardless of patch
# level" posture as _WEAK_CIPHER_RE above (CVE-2023-48795 note applies to
# the etm variants here too).
_WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
}


def _evaluate_ssh_macs(facts: SystemFacts) -> bool:
    macs = facts.sshd_config.get("macs", "")
    if not macs:
        return False
    algorithms = {m.strip().lower() for m in macs.split(",")}
    return not (algorithms & _WEAK_MACS)


def _evidence_ssh_macs(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("macs", "<not set>")
    return f"sshd_config: MACs {value}"


def _evaluate_ssh_max_startups(facts: SystemFacts) -> bool:
    """Real audit (control 5.1.17/5.1.18/5.1.19): `sshd -T | awk '$1 ~
    /^\\s*maxstartups/{split($2, a, ":");{if(a[1] > 10 || a[2] > 30 ||
    a[3] > 60) print $0}}'` must return nothing -- MaxStartups'
    "start:rate:full" triple must be 10:30:60 or more restrictive in every
    field. `sshd -T` always reports it as that colon-separated triple.
    """
    value = facts.sshd_config.get("maxstartups", "")
    parts = value.split(":")
    if len(parts) != 3:
        return False
    try:
        start, rate, full = (int(p) for p in parts)
    except ValueError:
        return False
    return start <= 10 and rate <= 30 and full <= 60


def _evidence_ssh_max_startups(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("maxstartups", "<not set>")
    return f"sshd_config: MaxStartups {value}"


def _evaluate_strong_password_hashing_algorithm(facts: SystemFacts) -> bool:
    """Real audit (control 5.4.1.4): `grep -Pi
    '^\\h*ENCRYPT_METHOD\\h+(SHA512|yescrypt)\\b' /etc/login.defs` -- case
    insensitive per the audit's own `-i` flag, so the value is upper-cased
    before comparing rather than requiring an exact-case match.
    """
    value = parse_login_defs(facts.login_defs_text).get("ENCRYPT_METHOD", "")
    return value.upper() in ("SHA512", "YESCRYPT")


def _evidence_strong_password_hashing_algorithm(facts: SystemFacts) -> str:
    value = parse_login_defs(facts.login_defs_text).get("ENCRYPT_METHOD", "<not set>")
    return f"login.defs: ENCRYPT_METHOD {value}"


def _pam_unix_present(text: str) -> bool:
    return any("pam_unix.so" in line for line in text.splitlines())


def _evaluate_pam_unix_enabled(facts: SystemFacts) -> bool:
    """Real audit (control 5.3.2.1): `grep pam_unix.so /etc/pam.d/common-
    {account,auth,password,session[,session-noninteractive]}` -- pam_unix.so
    must show up in every file in that list (4 files on debian_linux_11,
    5 on every other real target document, which also lists
    common-session-noninteractive). facts.SystemFacts collects
    common-auth/common-account/common-password but not common-session or
    common-session-noninteractive -- same collection gap already called
    out for _pam_unix_nullok_lines above -- so this checks the 3 available
    files, a safe subset of the real 4-5 file audit.
    """
    return (
        _pam_unix_present(facts.pam_common_auth)
        and _pam_unix_present(facts.pam_common_account)
        and _pam_unix_present(facts.pam_common_password)
    )


def _evidence_pam_unix_enabled(facts: SystemFacts) -> str:
    auth = "present" if _pam_unix_present(facts.pam_common_auth) else "missing"
    account = "present" if _pam_unix_present(facts.pam_common_account) else "missing"
    password = "present" if _pam_unix_present(facts.pam_common_password) else "missing"
    return f"pam_unix.so: common-auth={auth}, common-account={account}, common-password={password}"


_REMEMBER_RE = re.compile(r"\bremember=\d+\b")


def _pam_unix_remember_lines(facts: SystemFacts) -> list[str]:
    """Lines across common-auth/common-password/common-account that
    configure pam_unix.so with a remember= argument -- remember belongs on
    pam_pwhistory.so (password history), not pam_unix.so. Real audit
    (control 5.3.3.4.2) also checks common-session/common-session-
    noninteractive, which facts.py doesn't collect -- same gap as
    _pam_unix_nullok_lines above.
    """
    offending = []
    for text in (facts.pam_common_auth, facts.pam_common_password, facts.pam_common_account):
        for line in text.splitlines():
            if "pam_unix.so" in line and _REMEMBER_RE.search(line):
                offending.append(line.strip())
    return offending


def _evaluate_pam_unix_no_remember(facts: SystemFacts) -> bool:
    return len(_pam_unix_remember_lines(facts)) == 0


def _evidence_pam_unix_no_remember(facts: SystemFacts) -> str:
    lines = _pam_unix_remember_lines(facts)
    if not lines:
        return "no remember= found on pam_unix.so lines in common-auth/common-password/common-account"
    return "remember= found: " + " | ".join(lines)


def _pam_unix_password_lines(facts: SystemFacts) -> list[str]:
    return [line.strip() for line in facts.pam_common_password.splitlines() if "pam_unix.so" in line]


def _evaluate_pam_unix_strong_password_hashing(facts: SystemFacts) -> bool:
    """Real audit (control 5.3.3.4.3): `grep -PH '^\\h*password\\h+
    ([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512|yescrypt)\\b'
    /etc/pam.d/common-password`. ubuntu_linux_20_04's audit text is
    narrower here -- it only accepts sha512, not yescrypt (confirmed via
    Postgres) -- so that one real document is branched on explicitly using
    facts.os_id/os_version_id (already collected, not a new field); every
    other real target document accepts both.
    """
    lines = _pam_unix_password_lines(facts)
    has_sha512 = any("sha512" in line.lower() for line in lines)
    has_yescrypt = any("yescrypt" in line.lower() for line in lines)
    if facts.os_id == "ubuntu" and facts.os_version_id == "20.04":
        return has_sha512
    return has_sha512 or has_yescrypt


def _evidence_pam_unix_strong_password_hashing(facts: SystemFacts) -> str:
    lines = _pam_unix_password_lines(facts)
    return "common-password pam_unix.so line(s): " + (" | ".join(lines) if lines else "<none>")


def _evaluate_pam_unix_use_authtok(facts: SystemFacts) -> bool:
    """Real audit (control 5.3.3.4.4): `grep -PH '^\\h*password\\h+
    ([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b'
    /etc/pam.d/common-password` -- identical wording across every real
    target document, unlike the hashing-algorithm control above.
    """
    return any("use_authtok" in line for line in _pam_unix_password_lines(facts))


def _evidence_pam_unix_use_authtok(facts: SystemFacts) -> str:
    lines = _pam_unix_password_lines(facts)
    return "common-password pam_unix.so line(s): " + (" | ".join(lines) if lines else "<none>")


def _evaluate_pam_pwhistory_use_authtok(facts: SystemFacts) -> bool:
    """Real audit (control 5.3.3.3.3): either the pam_pwhistory.so line in
    /etc/pam.d/common-password carries use_authtok, OR (the newer,
    pam-configs-driven layout used by debian_linux_13/ubuntu_linux_24_04)
    /etc/security/pwhistory.conf sets use_authtok directly -- either
    location satisfies the control, matching the real audit's own "- OR/IF
    -" wording. facts.pwhistory_text (pwhistory.conf) is already collected
    for the sibling "pam_pwhistory module is enabled" family.
    """
    pwhistory_lines = [line for line in facts.pam_common_password.splitlines() if "pam_pwhistory.so" in line]
    if any("use_authtok" in line for line in pwhistory_lines):
        return True
    for line in facts.pwhistory_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("use_authtok"):
            return True
    return False


def _evidence_pam_pwhistory_use_authtok(facts: SystemFacts) -> str:
    pwhistory_lines = [line.strip() for line in facts.pam_common_password.splitlines() if "pam_pwhistory.so" in line]
    conf_active = [
        line.strip() for line in facts.pwhistory_text.splitlines() if line.strip().lower().startswith("use_authtok")
    ]
    return (
        f"common-password pam_pwhistory.so line(s): {' | '.join(pwhistory_lines) or '<none>'}; "
        f"pwhistory.conf use_authtok: {'set' if conf_active else 'not set'}"
    )


# Group L: sshd_config directives (round 2). Real audit conditions for all
# 7 confirmed identical across all 6 real target documents (debian_linux_
# 11/12/13, ubuntu_linux_20_04/22_04/24_04) via Postgres before writing
# these -- see the CHECKS entries below for per-control notes.
def _evaluate_ssh_max_auth_tries(facts: SystemFacts) -> bool:
    """Real audit: `sshd -T | grep maxauthtries`, MaxAuthTries must be 4 or
    less."""
    value = facts.sshd_config.get("maxauthtries", "")
    try:
        return int(value) <= 4
    except ValueError:
        return False


def _evidence_ssh_max_auth_tries(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("maxauthtries", "<not set>")
    return f"sshd_config: MaxAuthTries {value}"


def _evaluate_ssh_permit_empty_passwords(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("permitemptypasswords", "").lower() == "no"


def _evidence_ssh_permit_empty_passwords(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("permitemptypasswords", "<not set>")
    return f"sshd_config: PermitEmptyPasswords {value}"


def _evaluate_ssh_hostbased_authentication(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("hostbasedauthentication", "").lower() == "no"


def _evidence_ssh_hostbased_authentication(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("hostbasedauthentication", "<not set>")
    return f"sshd_config: HostbasedAuthentication {value}"


def _evaluate_ssh_gssapi_authentication(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("gssapiauthentication", "").lower() == "no"


def _evidence_ssh_gssapi_authentication(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("gssapiauthentication", "<not set>")
    return f"sshd_config: GSSAPIAuthentication {value}"


def _evaluate_ssh_client_alive(facts: SystemFacts) -> bool:
    """Real audit: `sshd -T | grep -Pi -- '(clientaliveinterval|
    clientalivecountmax)'`, both must be greater than zero -- one Check,
    both conditions, since the real audit greps for both directives
    together and there's no CIS control for either one alone.
    """
    try:
        interval = int(facts.sshd_config.get("clientaliveinterval", ""))
        count_max = int(facts.sshd_config.get("clientalivecountmax", ""))
    except ValueError:
        return False
    return interval > 0 and count_max > 0


def _evidence_ssh_client_alive(facts: SystemFacts) -> str:
    interval = facts.sshd_config.get("clientaliveinterval", "<not set>")
    count_max = facts.sshd_config.get("clientalivecountmax", "<not set>")
    return f"sshd_config: ClientAliveInterval {interval}, ClientAliveCountMax {count_max}"


def _evaluate_ssh_banner(facts: SystemFacts) -> bool:
    """Partial check: real audit condition has two parts -- (1) Banner is
    set to an absolute path (`sshd -T | grep -Pi -- '^banner\\h+\\/\\H+'`),
    and (2), on debian_12/13 and ubuntu_22_04/24_04, that the banner
    *file's content* doesn't leak OS info (a grep of that file's content
    against /etc/os-release's ID). facts.py collects sshd_config but not
    arbitrary banner file content, so only part (1) is checked here --
    matching this project's existing precedent for "configured" (not
    "correct value") checks (e.g. _evaluate_pwquality_enforce_for_root,
    _evaluate_sudo_log_file_exists above), which verify a directive is
    present/set rather than judging site-policy-dependent content.
    """
    value = facts.sshd_config.get("banner", "")
    return value.startswith("/")


def _evidence_ssh_banner(facts: SystemFacts) -> str:
    value = facts.sshd_config.get("banner", "<not set>")
    return f"sshd_config: Banner {value} (directive-set only, content not verified)"


def _evaluate_ssh_access(facts: SystemFacts) -> bool:
    """Real audit: `sshd -T | grep -Pi -- '^\\h*(allow|deny)(users|
    groups)\\h+\\H+'` must match at least one of AllowUsers/AllowGroups/
    DenyUsers/DenyGroups -- the real audit itself then asks a human to
    review the actual list against site policy (CIS doesn't prescribe a
    value), so presence of any one directive is the machine-checkable
    bar, same "configured, not judged" posture as _evaluate_ssh_banner
    above.
    """
    return any(
        facts.sshd_config.get(directive, "")
        for directive in ("allowusers", "allowgroups", "denyusers", "denygroups")
    )


def _evidence_ssh_access(facts: SystemFacts) -> str:
    parts = [
        f"{directive}={facts.sshd_config[directive]}"
        for directive in ("allowusers", "allowgroups", "denyusers", "denygroups")
        if facts.sshd_config.get(directive)
    ]
    return "sshd_config: " + (", ".join(parts) if parts else "none of AllowUsers/AllowGroups/DenyUsers/DenyGroups set")
# Group N: unused network service packages batch B + required packages
# (round 2). All 11 titles below confirmed via Postgres to resolve in all 6
# target documents, audit text read in full for each (not just a snippet).
#
# Part A (8): same "package must NOT be installed" shape as Group I's
# _packages_absent-based checks above -- the real audit's dpkg-query check
# is unconditional, with an "- OR - IF the package is required as a
# dependency, check its systemd unit isn't enabled/active" fallback branch
# that every existing _packages_absent check in this file already omits
# (SystemFacts has no systemd unit-state collection), so this follows the
# established precedent rather than inventing a new shape.
#
# Part B (3): opposite direction, same installed_packages field.
#   - "Ensure sudo is installed": confirmed OR across all 6 docs -- each
#     lists sudo, then "- OR -", then sudo-ldap. (debian_linux_13 also
#     lists a further libsss-sudo+sssd alternative; not needed since
#     sudo/sudo-ldap alone already covers the common case identically to
#     the other 5 docs.)
#   - "Ensure auditd packages are installed": confirmed AND across all 6
#     docs -- unlike the sudo control, there is no "- OR -" between the
#     auditd step and the audispd-plugins step; both are stated as
#     required verifications with no alternative offered.
#   - "Ensure AIDE is installed": same AND shape as auditd, confirmed
#     across all 6 docs -- aide and aide-common are both required
#     verification steps with no "- OR -" between them.
def _evaluate_cups_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "cups")


def _evidence_cups_not_installed(facts: SystemFacts) -> str:
    present = "cups" in facts.installed_packages
    return f"installed_packages: cups {'present' if present else 'absent'}"


def _evaluate_rpcbind_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "rpcbind")


def _evidence_rpcbind_not_installed(facts: SystemFacts) -> str:
    present = "rpcbind" in facts.installed_packages
    return f"installed_packages: rpcbind {'present' if present else 'absent'}"


def _evaluate_samba_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "samba")


def _evidence_samba_not_installed(facts: SystemFacts) -> str:
    present = "samba" in facts.installed_packages
    return f"installed_packages: samba {'present' if present else 'absent'}"


def _evaluate_snmp_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "snmpd")


def _evidence_snmp_not_installed(facts: SystemFacts) -> str:
    present = "snmpd" in facts.installed_packages
    return f"installed_packages: snmpd {'present' if present else 'absent'}"


def _evaluate_tftp_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "tftpd-hpa")


def _evidence_tftp_server_not_installed(facts: SystemFacts) -> str:
    present = "tftpd-hpa" in facts.installed_packages
    return f"installed_packages: tftpd-hpa {'present' if present else 'absent'}"


def _evaluate_web_proxy_not_installed(facts: SystemFacts) -> bool:
    """ubuntu_linux_20_04's audit additionally names squid-openssl; the
    other 5 docs check squid alone. Requiring both absent is a safe
    superset (same reasoning as _packages_absent's own docstring, and the
    same pattern already used for telnet/inetutils-telnet and ftp/tnftp).
    """
    return _packages_absent(facts, "squid", "squid-openssl")


def _evidence_web_proxy_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("squid", "squid-openssl") if p in facts.installed_packages]
    return f"installed_packages: squid/squid-openssl {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_web_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "apache2", "nginx")


def _evidence_web_server_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("apache2", "nginx") if p in facts.installed_packages]
    return f"installed_packages: apache2/nginx {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_autofs_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "autofs")


def _evidence_autofs_not_installed(facts: SystemFacts) -> str:
    present = "autofs" in facts.installed_packages
    return f"installed_packages: autofs {'present' if present else 'absent'}"


def _evaluate_sudo_installed(facts: SystemFacts) -> bool:
    return "sudo" in facts.installed_packages or "sudo-ldap" in facts.installed_packages


def _evidence_sudo_installed(facts: SystemFacts) -> str:
    present = [p for p in ("sudo", "sudo-ldap") if p in facts.installed_packages]
    return f"installed_packages: sudo/sudo-ldap {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_auditd_packages_installed(facts: SystemFacts) -> bool:
    return "auditd" in facts.installed_packages and "audispd-plugins" in facts.installed_packages


def _evidence_auditd_packages_installed(facts: SystemFacts) -> str:
    missing = [p for p in ("auditd", "audispd-plugins") if p not in facts.installed_packages]
    return f"installed_packages: auditd/audispd-plugins {'both present' if not missing else 'missing: ' + ','.join(missing)}"


def _evaluate_aide_installed(facts: SystemFacts) -> bool:
    return "aide" in facts.installed_packages and "aide-common" in facts.installed_packages


def _evidence_aide_installed(facts: SystemFacts) -> str:
    missing = [p for p in ("aide", "aide-common") if p not in facts.installed_packages]
    return f"installed_packages: aide/aide-common {'both present' if not missing else 'missing: ' + ','.join(missing)}"


@dataclass
class Check:
    """One implemented, hand-written evaluator, plus every title wording
    it's known to appear under -- exact title text drifts a little between
    CIS documents (confirmed: "Ensure permissions on /etc/shadow are
    configured" vs "Ensure access to /etc/shadow is configured" for the
    same underlying check), so the control is looked up by title, not a
    hardcoded external_id (also confirmed to drift between documents --
    Debian 13 uses 5.1.21 where the rest use 5.1.20).
    """

    titles: list[str]
    evaluate: Callable[[SystemFacts], bool]
    evidence: Callable[[SystemFacts], str]


# The only controls Invariant actually knows how to check right now.
# Adding another means writing its evaluate()/evidence() by hand, the same
# way these were -- extending facts.SystemFacts first if it needs a new
# kind of collected data.
CHECKS = [
    Check(
        titles=["Ensure sshd PermitRootLogin is disabled"],
        evaluate=_evaluate_ssh_permit_root_login,
        evidence=_evidence_ssh_permit_root_login,
    ),
    Check(
        titles=[
            "Ensure permissions on /etc/shadow are configured",
            "Ensure access to /etc/shadow is configured",
        ],
        evaluate=_evaluate_shadow_permissions,
        evidence=_evidence_shadow_permissions,
    ),
    Check(
        titles=["Ensure sshd PermitUserEnvironment is disabled"],
        evaluate=_evaluate_ssh_permit_user_environment,
        evidence=_evidence_ssh_permit_user_environment,
    ),
    Check(
        titles=["Ensure sshd IgnoreRhosts is enabled"],
        evaluate=_evaluate_ssh_ignore_rhosts,
        evidence=_evidence_ssh_ignore_rhosts,
    ),
    Check(
        titles=["Ensure sshd LoginGraceTime is configured"],
        evaluate=_evaluate_ssh_login_grace_time,
        evidence=_evidence_ssh_login_grace_time,
    ),
    # Group A: plain file-permission checks. Title wording drifts the same
    # way it does for /etc/shadow -- confirmed across debian_linux_11/12/13
    # and ubuntu_linux_20_04/22_04/24_04 (our 6 demo targets' documents):
    # debian_linux_11 always uses "Ensure permissions on X are configured",
    # every other target document uses "Ensure access to X is configured".
    # Both wordings are the same control (identical audit text), so both
    # are listed. hosts.allow/hosts.deny permission controls were looked at
    # and dropped -- see module docstring notes below the CHECKS list.
    Check(
        titles=[
            "Ensure access to /etc/issue is configured",
            "Ensure permissions on /etc/issue are configured",
        ],
        evaluate=_evaluate_etc_issue_permissions,
        evidence=_evidence_etc_issue_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/issue.net is configured",
            "Ensure permissions on /etc/issue.net are configured",
        ],
        evaluate=_evaluate_etc_issue_net_permissions,
        evidence=_evidence_etc_issue_net_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/passwd is configured",
            "Ensure permissions on /etc/passwd are configured",
        ],
        evaluate=_evaluate_etc_passwd_permissions,
        evidence=_evidence_etc_passwd_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/passwd- is configured",
            "Ensure permissions on /etc/passwd- are configured",
        ],
        evaluate=_evaluate_etc_passwd_minus_permissions,
        evidence=_evidence_etc_passwd_minus_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/group is configured",
            "Ensure permissions on /etc/group are configured",
        ],
        evaluate=_evaluate_etc_group_permissions,
        evidence=_evidence_etc_group_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/group- is configured",
            "Ensure permissions on /etc/group- are configured",
        ],
        evaluate=_evaluate_etc_group_minus_permissions,
        evidence=_evidence_etc_group_minus_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/shadow- is configured",
            "Ensure permissions on /etc/shadow- are configured",
        ],
        evaluate=_evaluate_etc_shadow_minus_permissions,
        evidence=_evidence_etc_shadow_minus_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/gshadow is configured",
            "Ensure permissions on /etc/gshadow are configured",
        ],
        evaluate=_evaluate_etc_gshadow_permissions,
        evidence=_evidence_etc_gshadow_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/gshadow- is configured",
            "Ensure permissions on /etc/gshadow- are configured",
        ],
        evaluate=_evaluate_etc_gshadow_minus_permissions,
        evidence=_evidence_etc_gshadow_minus_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/shells is configured",
            "Ensure permissions on /etc/shells are configured",
        ],
        evaluate=_evaluate_etc_shells_permissions,
        evidence=_evidence_etc_shells_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/ssh/sshd_config is configured",
            "Ensure permissions on /etc/ssh/sshd_config are configured",
        ],
        evaluate=_evaluate_sshd_config_permissions,
        evidence=_evidence_sshd_config_permissions,
    ),
    # Group B: passwd/group/shadow content checks.
    Check(
        titles=[
            "Ensure /etc/shadow password fields are not empty",
            "Ensure password fields are not empty",
            "Ensure Password Fields are Not Empty",
        ],
        evaluate=_evaluate_shadow_password_fields_not_empty,
        evidence=_evidence_shadow_password_fields_not_empty,
    ),
    Check(
        titles=["Ensure accounts in /etc/passwd use shadowed passwords"],
        evaluate=_evaluate_passwd_accounts_use_shadowed_passwords,
        evidence=_evidence_passwd_accounts_use_shadowed_passwords,
    ),
    Check(
        titles=["Ensure root is the only GID 0 account"],
        evaluate=_evaluate_root_only_gid0_account,
        evidence=_evidence_root_only_gid0_account,
    ),
    Check(
        titles=[
            "Ensure root is the only UID 0 account",
            "Verify No UID 0 Accounts Exist Other Than root",
            "Configure root and system accounts and environment Page 637 Internal Only - General 5.4.2.1 Ensure root is the only UID 0 account",
            "Configure root and system accounts and environment Page 671  5.4.2.1 Ensure root is the only UID 0 account",
            "Configure root and system accounts and environment Page 677 Internal Only - General 5.4.2.1 Ensure root is the only UID 0 account",
        ],
        evaluate=_evaluate_root_only_uid0_account,
        evidence=_evidence_root_only_uid0_account,
    ),
    Check(
        titles=["Ensure group root is the only GID 0 group"],
        evaluate=_evaluate_only_root_group_has_gid0,
        evidence=_evidence_only_root_group_has_gid0,
    ),
    # Group C: PAM + login.defs checks.
    Check(
        titles=["Ensure pam_faillock module is enabled"],
        evaluate=_evaluate_pam_faillock_enabled,
        evidence=_evidence_pam_faillock_enabled,
    ),
    Check(
        titles=["Ensure pam_pwquality module is enabled"],
        evaluate=_evaluate_pam_pwquality_enabled,
        evidence=_evidence_pam_pwquality_enabled,
    ),
    Check(
        titles=["Ensure pam_pwhistory module is enabled"],
        evaluate=_evaluate_pam_pwhistory_enabled,
        evidence=_evidence_pam_pwhistory_enabled,
    ),
    Check(
        # "Ensure pam_unix does not include nullok" is the wording every
        # real target document (debian_linux_11/12/13, ubuntu_linux_20_04/
        # 22_04/24_04) actually uses; "Ensure pam modules do not include
        # nullok" is the STIG documents' wording for the same underlying
        # misconfiguration (nullok on a pam_unix.so line).
        titles=[
            "Ensure pam_unix does not include nullok",
            "Ensure pam modules do not include nullok",
        ],
        evaluate=_evaluate_pam_no_nullok,
        evidence=_evidence_pam_no_nullok,
    ),
    Check(
        # Assigned candidate was "Ensure default user umask is 077 or more
        # restrictive", but that exact control only exists in the STIG
        # documents, which document_slug_for_os() never resolves to (see
        # final summary). "Ensure default user umask is configured" is the
        # real equivalent in every CIS document backing the actual demo
        # targets, at a 027-or-more-restrictive threshold instead of 077.
        titles=["Ensure default user umask is configured"],
        evaluate=_evaluate_default_umask,
        evidence=_evidence_default_umask,
    ),
    # Group G: password quality/history, via pwquality.conf and
    # pwhistory.conf. All 8 assigned candidates turned out to be distinct
    # real controls with full 6-document title coverage -- none dropped.
    # "Ensure minimum password length is configured" (debian_linux_11,
    # ubuntu_linux_20_04/22_04) and "Ensure password length is configured"
    # (debian_linux_12/13, ubuntu_linux_24_04) are the same control (identical
    # minlen audit text, same external_id 5.3.3.2.2) under drifted wording,
    # same pattern as the file-permission "access to X"/"permissions on X"
    # drift Group A already documented.
    Check(
        titles=["Ensure password quality is enforced for the root user"],
        evaluate=_evaluate_pwquality_enforce_for_root,
        evidence=_evidence_pwquality_enforce_for_root,
    ),
    Check(
        titles=[
            "Ensure minimum password length is configured",
            "Ensure password length is configured",
        ],
        evaluate=_evaluate_pwquality_minlen,
        evidence=_evidence_pwquality_minlen,
    ),
    Check(
        titles=["Ensure password complexity is configured"],
        evaluate=_evaluate_pwquality_complexity,
        evidence=_evidence_pwquality_complexity,
    ),
    Check(
        titles=["Ensure password same consecutive characters is configured"],
        evaluate=_evaluate_pwquality_max_repeat,
        evidence=_evidence_pwquality_max_repeat,
    ),
    Check(
        titles=["Ensure password maximum sequential characters is configured"],
        evaluate=_evaluate_pwquality_max_sequence,
        evidence=_evidence_pwquality_max_sequence,
    ),
    Check(
        titles=["Ensure password number of changed characters is configured"],
        evaluate=_evaluate_pwquality_difok,
        evidence=_evidence_pwquality_difok,
    ),
    Check(
        titles=["Ensure password history remember is configured"],
        evaluate=_evaluate_pwhistory_remember,
        evidence=_evidence_pwhistory_remember,
    ),
    Check(
        titles=["Ensure password history is enforced for the root user"],
        evaluate=_evaluate_pwhistory_enforce_for_root,
        evidence=_evidence_pwhistory_enforce_for_root,
    ),
    # Group D: remaining sshd_config directives + SSH host key permissions.
    Check(
        titles=[
            "Ensure sshd MaxSessions is configured",
            "Ensure SSH MaxSessions is set to 10 or less",
            "Ensure SSH MaxSessions is limited",
        ],
        evaluate=_evaluate_ssh_max_sessions,
        evidence=_evidence_ssh_max_sessions,
    ),
    Check(
        titles=[
            "Ensure sshd LogLevel is configured",
            "Ensure SSH LogLevel is appropriate",
        ],
        evaluate=_evaluate_ssh_log_level,
        evidence=_evidence_ssh_log_level,
    ),
    Check(
        titles=[
            "Ensure sshd UsePAM is enabled",
            "Ensure SSH PAM is enabled",
        ],
        evaluate=_evaluate_ssh_use_pam,
        evidence=_evidence_ssh_use_pam,
    ),
    Check(
        titles=["Ensure sshd DisableForwarding is enabled"],
        evaluate=_evaluate_ssh_disable_forwarding,
        evidence=_evidence_ssh_disable_forwarding,
    ),
    Check(
        titles=[
            "Ensure sshd Ciphers are configured",
            "Ensure only strong ciphers are used",
            "Ensure only strong Ciphers are used",
        ],
        evaluate=_evaluate_ssh_ciphers,
        evidence=_evidence_ssh_ciphers,
    ),
    Check(
        titles=[
            "Ensure sshd KexAlgorithms is configured",
            "Ensure only strong Key Exchange algorithms are used",
        ],
        evaluate=_evaluate_ssh_kex_algorithms,
        evidence=_evidence_ssh_kex_algorithms,
    ),
    Check(
        titles=[
            "Ensure permissions on SSH private host key files are configured",
            "Ensure access to SSH private host key files is configured",
        ],
        evaluate=_evaluate_ssh_private_host_key_permissions,
        evidence=_evidence_ssh_private_host_key_permissions,
    ),
    Check(
        titles=[
            "Ensure permissions on SSH public host key files are configured",
            "Ensure access to SSH public host key files is configured",
        ],
        evaluate=_evaluate_ssh_public_host_key_permissions,
        evidence=_evidence_ssh_public_host_key_permissions,
    ),
    Check(
        titles=["Ensure ldap client is not installed"],
        evaluate=_evaluate_ldap_client_not_installed,
        evidence=_evidence_ldap_client_not_installed,
    ),
    Check(
        titles=["Ensure nis client is not installed", "Ensure NIS Client is not installed"],
        evaluate=_evaluate_nis_client_not_installed,
        evidence=_evidence_nis_client_not_installed,
    ),
    Check(
        titles=["Ensure xinetd services are not in use"],
        evaluate=_evaluate_xinetd_not_installed,
        evidence=_evidence_xinetd_not_installed,
    ),
    Check(
        titles=["Ensure rsync services are not in use"],
        evaluate=_evaluate_rsync_not_installed,
        evidence=_evidence_rsync_not_installed,
    ),
    Check(
        titles=["Ensure X window server services are not in use"],
        evaluate=_evaluate_x_window_not_installed,
        evidence=_evidence_x_window_not_installed,
    ),
    Check(
        titles=["Ensure telnet client is not installed"],
        evaluate=_evaluate_telnet_client_not_installed,
        evidence=_evidence_telnet_client_not_installed,
    ),
    Check(
        titles=["Ensure rsh client is not installed"],
        evaluate=_evaluate_rsh_client_not_installed,
        evidence=_evidence_rsh_client_not_installed,
    ),
    Check(
        titles=["Ensure ftp client is not installed"],
        evaluate=_evaluate_ftp_client_not_installed,
        evidence=_evidence_ftp_client_not_installed,
    ),
    Check(
        titles=["Ensure talk client is not installed"],
        evaluate=_evaluate_talk_client_not_installed,
        evidence=_evidence_talk_client_not_installed,
    ),
    Check(
        titles=["Ensure prelink is not installed"],
        evaluate=_evaluate_prelink_not_installed,
        evidence=_evidence_prelink_not_installed,
    ),
    # Group I: auditd config/tooling file ownership + rules immutability.
    # Title wording is identical across all 6 real documents for these five
    # (confirmed via Postgres) -- no variant aliases needed, unlike the
    # Group A /etc/shadow-style controls. Three candidates from this
    # group's brief were looked at and dropped:
    #   - "Ensure audit log files group owner is configured": real audit
    #     targets the log_group parameter in /etc/audit/auditd.conf and the
    #     directory named there (typically /var/log/audit) -- neither is in
    #     facts._STAT_PATHS/_TEXT_BLOCKS, so this would always evaluate to
    #     the same "not configured" answer regardless of target state.
    #     Would need facts.py extended with an auditd.conf text block and a
    #     /var/log/audit stat entry to do meaningfully.
    #   - "Ensure the audit configuration is loaded regardless of errors"
    #     (the `-c` flag equivalent of the immutable-flag check below):
    #     confirmed via Postgres this title only exists in debian_linux_13,
    #     not the other 5 documents backing our demo targets -- would raise
    #     LookupError on every other target, per the title-must-resolve-in-
    #     all-6 constraint.
    #   - "Ensure SUID and SGID files are reviewed": confirmed via Postgres
    #     this control's real audit is a script that *lists* SUID/SGID
    #     files for a human to review, not a pass/fail condition -- same
    #     "Manual" shape prior groups dropped elsewhere.
    Check(
        titles=["Ensure audit configuration files owner is configured"],
        evaluate=_evaluate_audit_config_files_owner,
        evidence=_evidence_audit_config_files_owner,
    ),
    Check(
        titles=["Ensure audit configuration files group owner is configured"],
        evaluate=_evaluate_audit_config_files_group_owner,
        evidence=_evidence_audit_config_files_group_owner,
    ),
    Check(
        titles=["Ensure audit tools owner is configured"],
        evaluate=_evaluate_audit_tools_owner,
        evidence=_evidence_audit_tools_owner,
    ),
    Check(
        titles=["Ensure audit tools group owner is configured"],
        evaluate=_evaluate_audit_tools_group_owner,
        evidence=_evidence_audit_tools_group_owner,
    ),
    Check(
        titles=["Ensure the audit configuration is immutable"],
        evaluate=_evaluate_audit_config_immutable,
        evidence=_evidence_audit_config_immutable,
    ),
    # Group H: sudoers + cron file permissions.
    Check(
        titles=["Ensure sudo log file exists"],
        evaluate=_evaluate_sudo_log_file_exists,
        evidence=_evidence_sudo_log_file_exists,
    ),
    Check(
        # "...for privilege escalation" (debian_linux_11, ubuntu_linux_20_04)
        # vs "...for escalation" (debian_linux_12/13, ubuntu_linux_22_04/
        # 24_04) -- same NOPASSWD-in-sudoers audit under both titles.
        titles=[
            "Ensure users must provide password for privilege escalation",
            "Ensure users must provide password for escalation",
        ],
        evaluate=_evaluate_sudo_no_nopasswd,
        evidence=_evidence_sudo_no_nopasswd,
    ),
    Check(
        titles=["Ensure re-authentication for privilege escalation is not disabled globally"],
        evaluate=_evaluate_sudo_reauthentication_required,
        evidence=_evidence_sudo_reauthentication_required,
    ),
    # "Ensure sudo authentication timeout is configured[...]" (5.2.6) was
    # looked at and dropped: debian_linux_11/12/13 and ubuntu_linux_22_04/
    # 24_04 all primarily grep timestamp_timeout= out of /etc/sudoers* (a
    # static text check we could do), but ubuntu_linux_20_04's audit text
    # for the *same* control is written entirely around `sudo -V | grep
    # "Authentication timestamp timeout:"` -- no /etc/sudoers* grep at all
    # -- with no static fallback. facts.py deliberately never runs a
    # config-independent live command like `sudo -V` (see module docstring
    # and facts.py's own comments), so this control can't be resolved
    # correctly for all 6 real target documents from the current
    # SystemFacts snapshot. Dropped rather than guessing at ubuntu_20_04's
    # runtime default.
    Check(
        titles=[
            "Ensure access to /etc/crontab is configured",
            "Ensure permissions on /etc/crontab are configured",
        ],
        evaluate=_evaluate_crontab_permissions,
        evidence=_evidence_crontab_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/cron.hourly is configured",
            "Ensure permissions on /etc/cron.hourly are configured",
        ],
        evaluate=_evaluate_cron_hourly_permissions,
        evidence=_evidence_cron_hourly_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/cron.daily is configured",
            "Ensure permissions on /etc/cron.daily are configured",
        ],
        evaluate=_evaluate_cron_daily_permissions,
        evidence=_evidence_cron_daily_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/cron.weekly is configured",
            "Ensure permissions on /etc/cron.weekly are configured",
        ],
        evaluate=_evaluate_cron_weekly_permissions,
        evidence=_evidence_cron_weekly_permissions,
    ),
    Check(
        titles=[
            "Ensure access to /etc/cron.monthly is configured",
            "Ensure permissions on /etc/cron.monthly are configured",
        ],
        evaluate=_evaluate_cron_monthly_permissions,
        evidence=_evidence_cron_monthly_permissions,
    ),
    Check(
        # /etc/cron.d's external_id itself drifts (2.4.1.7 in
        # debian_linux_11, which has no cron.yearly control; 2.4.1.8 in
        # every other real target document, which inserts a cron.yearly
        # control -- not implemented here, not one of this group's
        # assigned paths -- at 2.4.1.7 first). Title-based lookup makes
        # that irrelevant to the Check itself; see test_assess_target.py's
        # _SYSTEMIC_GAPS handling for where it does matter.
        titles=[
            "Ensure access to /etc/cron.d is configured",
            "Ensure permissions on /etc/cron.d are configured",
        ],
        evaluate=_evaluate_cron_d_permissions,
        evidence=_evidence_cron_d_permissions,
    ),
    # Group J: journald config + a few standalone file checks. rsyslog was
    # dropped in its entirety (all 4 candidates) -- confirmed via Postgres
    # that debian_linux_11's benchmark version has zero "rsyslog"-titled
    # controls anywhere (it only covers journald for logging; rsyslog
    # config/CA-cert/gtls-forwarding controls first appear starting with
    # debian_linux_12), so none of the 4 rsyslog candidates can resolve
    # across all 6 real target documents -- see the module docstring notes
    # below CHECKS for the per-candidate detail.
    Check(
        titles=["Ensure journald Compress is configured"],
        evaluate=_evaluate_journald_compress,
        evidence=_evidence_journald_compress,
    ),
    Check(
        titles=["Ensure journald Storage is configured"],
        evaluate=_evaluate_journald_storage,
        evidence=_evidence_journald_storage,
    ),
    Check(
        titles=["Ensure journald log file rotation is configured"],
        evaluate=_evaluate_journald_log_rotation,
        evidence=_evidence_journald_log_rotation,
    ),
    Check(
        # "Ensure nologin is not listed in /etc/shells" is the clean title
        # (debian_linux_12, ubuntu_linux_20_04, ubuntu_linux_24_04); the
        # other 3 documents glue a PDF page-header onto the same control
        # (confirmed via Postgres -- same audit text, same external_id
        # 5.4.3.1, just a garbled title), so those exact garbled strings
        # are listed as aliases rather than treated as separate controls.
        titles=[
            "Ensure nologin is not listed in /etc/shells",
            "Configure user default environment Page 690  5.4.3.1 Ensure nologin is not listed in /etc/shells",
            "Configure user default environment Page 693 Internal Only - General 5.4.3.1 Ensure nologin is not listed in /etc/shells",
            "Configure user default environment Page 654 Internal Only - General 5.4.3.1 Ensure nologin is not listed in /etc/shells",
        ],
        evaluate=_evaluate_shells_no_nologin,
        evidence=_evidence_shells_no_nologin,
    ),
    Check(
        titles=["Ensure access to /etc/motd is configured"],
        evaluate=_evaluate_etc_motd_permissions,
        evidence=_evidence_etc_motd_permissions,
    ),
    Check(
        titles=["Ensure access to bootloader config is configured"],
        evaluate=_evaluate_bootloader_config_permissions,
        evidence=_evidence_bootloader_config_permissions,
    ),
    # Group F: remaining sshd_config directives + PAM/login.defs checks.
    # Two assigned candidates were dropped -- title/semantics didn't hold
    # up across all 6 real documents:
    #   - "Ensure root user umask is configured": the real audit greps
    #     `/root/.bash_profile`, `/root/.bashrc` (and, on debian_12/13 +
    #     ubuntu_22_04/24_04, `/root/.profile` instead of .bash_profile)
    #     for a umask line -- never /etc/login.defs or /etc/pam.d/login,
    #     confirmed via Postgres audit text on every document. facts.py
    #     collects neither root shell rc file, so this control can't be
    #     evaluated from existing SystemFacts without adding a new field,
    #     contrary to this group's assigned "zero new facts" scope --
    #     left for a future group to add the collection field deliberately
    #     rather than bolted on here as a side effect.
    #   - "Ensure root account access is controlled": resolves in 5 of 6
    #     documents (missing from debian_linux_11) with audit text "root
    #     password is either set (P) or locked (L)" via `passwd -S root`.
    #     debian_linux_11's nearest control at the same position (5.4.2.4)
    #     is "Ensure root password is set" instead -- a *stricter*, only
    #     partially-overlapping condition (P only, L is not accepted) --
    #     not a wording variant of the same control, so merging its title
    #     in would silently loosen debian_linux_11's real pass condition.
    Check(
        titles=["Ensure sshd MACs are configured"],
        evaluate=_evaluate_ssh_macs,
        evidence=_evidence_ssh_macs,
    ),
    Check(
        titles=["Ensure sshd MaxStartups is configured"],
        evaluate=_evaluate_ssh_max_startups,
        evidence=_evidence_ssh_max_startups,
    ),
    Check(
        titles=["Ensure strong password hashing algorithm is configured"],
        evaluate=_evaluate_strong_password_hashing_algorithm,
        evidence=_evidence_strong_password_hashing_algorithm,
    ),
    Check(
        titles=["Ensure pam_unix module is enabled"],
        evaluate=_evaluate_pam_unix_enabled,
        evidence=_evidence_pam_unix_enabled,
    ),
    Check(
        titles=["Ensure pam_unix does not include remember"],
        evaluate=_evaluate_pam_unix_no_remember,
        evidence=_evidence_pam_unix_no_remember,
    ),
    Check(
        titles=["Ensure pam_unix includes a strong password hashing algorithm"],
        evaluate=_evaluate_pam_unix_strong_password_hashing,
        evidence=_evidence_pam_unix_strong_password_hashing,
    ),
    Check(
        titles=["Ensure pam_unix includes use_authtok"],
        evaluate=_evaluate_pam_unix_use_authtok,
        evidence=_evidence_pam_unix_use_authtok,
    ),
    Check(
        titles=["Ensure pam_pwhistory includes use_authtok"],
        evaluate=_evaluate_pam_pwhistory_use_authtok,
        evidence=_evidence_pam_pwhistory_use_authtok,
    ),
    # Group K: package presence (installed_packages must contain the
    # package, the inverse of the "not installed" checks in the block
    # above). Two assigned candidates were dropped: "Ensure rsyslog is
    # installed" only has a control on debian_linux_12/13 and
    # ubuntu_linux_20_04/22_04/24_04 (confirmed via Postgres) -- no
    # rsyslog-titled control exists on debian_linux_11 at all, consistent
    # with the Group J comment above ("debian_linux_11 ... only covers
    # journald for logging"), and invariant-debian-baseline resolves to
    # exactly that document, so assess_target() would raise LookupError
    # against it. "Ensure rsyslog-gnutls is installed" is narrower still --
    # only debian_linux_12, debian_linux_13, ubuntu_linux_24_04 -- missing
    # debian_linux_11 *and* ubuntu_linux_20_04/22_04, all three real target
    # documents. "Ensure ufw is installed" is the one candidate confirmed
    # present, with matching unconditional dpkg-query audit text, on all 6
    # real target documents (debian_linux_11/12/13,
    # ubuntu_linux_20_04/22_04/24_04).
    Check(
        titles=["Ensure ufw is installed"],
        evaluate=_evaluate_ufw_installed,
        evidence=_evidence_ufw_installed,
    ),
    # Group L: sshd_config directives (round 2). All 7 titles confirmed
    # (via Postgres, full audit text read per document) identical across
    # all 6 real target documents -- no dropped candidates this round.
    Check(
        titles=["Ensure sshd MaxAuthTries is configured"],
        evaluate=_evaluate_ssh_max_auth_tries,
        evidence=_evidence_ssh_max_auth_tries,
    ),
    Check(
        titles=["Ensure sshd PermitEmptyPasswords is disabled"],
        evaluate=_evaluate_ssh_permit_empty_passwords,
        evidence=_evidence_ssh_permit_empty_passwords,
    ),
    Check(
        titles=["Ensure sshd HostbasedAuthentication is disabled"],
        evaluate=_evaluate_ssh_hostbased_authentication,
        evidence=_evidence_ssh_hostbased_authentication,
    ),
    Check(
        titles=["Ensure sshd GSSAPIAuthentication is disabled"],
        evaluate=_evaluate_ssh_gssapi_authentication,
        evidence=_evidence_ssh_gssapi_authentication,
    ),
    Check(
        titles=["Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"],
        evaluate=_evaluate_ssh_client_alive,
        evidence=_evidence_ssh_client_alive,
    ),
    Check(
        # Partial check -- see _evaluate_ssh_banner's docstring: the
        # banner-file-content half of the real audit (checked against
        # /etc/os-release on debian_12/13, ubuntu_22_04/24_04) isn't
        # verified, only that Banner points at an absolute path.
        titles=["Ensure sshd Banner is configured"],
        evaluate=_evaluate_ssh_banner,
        evidence=_evidence_ssh_banner,
    ),
    Check(
        # Directive-presence only -- the real audit itself asks a human to
        # review the actual user/group list against site policy, same as
        # this project's other "configured, not judged" checks.
        titles=["Ensure sshd access is configured"],
        evaluate=_evaluate_ssh_access,
        evidence=_evidence_ssh_access,
    ),
    # Group M: unused network service packages, batch A (round 2).
    Check(
        titles=["Ensure avahi daemon services are not in use"],
        evaluate=_evaluate_avahi_not_in_use,
        evidence=_evidence_avahi_not_in_use,
    ),
    Check(
        titles=["Ensure bluetooth services are not in use"],
        evaluate=_evaluate_bluetooth_not_in_use,
        evidence=_evidence_bluetooth_not_in_use,
    ),
    Check(
        titles=["Ensure dhcp server services are not in use"],
        evaluate=_evaluate_dhcp_server_not_in_use,
        evidence=_evidence_dhcp_server_not_in_use,
    ),
    Check(
        titles=["Ensure dns server services are not in use"],
        evaluate=_evaluate_dns_server_not_in_use,
        evidence=_evidence_dns_server_not_in_use,
    ),
    Check(
        titles=["Ensure dnsmasq services are not in use"],
        evaluate=_evaluate_dnsmasq_not_in_use,
        evidence=_evidence_dnsmasq_not_in_use,
    ),
    Check(
        titles=["Ensure ftp server services are not in use"],
        evaluate=_evaluate_ftp_server_not_in_use,
        evidence=_evidence_ftp_server_not_in_use,
    ),
    Check(
        titles=["Ensure ldap server services are not in use"],
        evaluate=_evaluate_ldap_server_not_in_use,
        evidence=_evidence_ldap_server_not_in_use,
    ),
    Check(
        titles=["Ensure message access server services are not in use"],
        evaluate=_evaluate_message_access_server_not_in_use,
        evidence=_evidence_message_access_server_not_in_use,
    ),
    Check(
        titles=["Ensure network file system services are not in use"],
        evaluate=_evaluate_nfs_server_not_in_use,
        evidence=_evidence_nfs_server_not_in_use,
    ),
    Check(
        titles=["Ensure nis server services are not in use"],
        evaluate=_evaluate_nis_server_not_in_use,
        evidence=_evidence_nis_server_not_in_use,
    ),
    # Group N: unused network service packages batch B + required packages (round 2)
    Check(
        titles=["Ensure print server services are not in use"],
        evaluate=_evaluate_cups_not_installed,
        evidence=_evidence_cups_not_installed,
    ),
    Check(
        titles=["Ensure rpcbind services are not in use"],
        evaluate=_evaluate_rpcbind_not_installed,
        evidence=_evidence_rpcbind_not_installed,
    ),
    Check(
        titles=["Ensure samba file server services are not in use"],
        evaluate=_evaluate_samba_not_installed,
        evidence=_evidence_samba_not_installed,
    ),
    Check(
        titles=["Ensure snmp services are not in use"],
        evaluate=_evaluate_snmp_not_installed,
        evidence=_evidence_snmp_not_installed,
    ),
    Check(
        titles=["Ensure tftp server services are not in use"],
        evaluate=_evaluate_tftp_server_not_installed,
        evidence=_evidence_tftp_server_not_installed,
    ),
    Check(
        titles=["Ensure web proxy server services are not in use"],
        evaluate=_evaluate_web_proxy_not_installed,
        evidence=_evidence_web_proxy_not_installed,
    ),
    Check(
        titles=["Ensure web server services are not in use"],
        evaluate=_evaluate_web_server_not_installed,
        evidence=_evidence_web_server_not_installed,
    ),
    Check(
        titles=["Ensure autofs services are not in use"],
        evaluate=_evaluate_autofs_not_installed,
        evidence=_evidence_autofs_not_installed,
    ),
    Check(
        titles=["Ensure sudo is installed"],
        evaluate=_evaluate_sudo_installed,
        evidence=_evidence_sudo_installed,
    ),
    Check(
        titles=["Ensure auditd packages are installed"],
        evaluate=_evaluate_auditd_packages_installed,
        evidence=_evidence_auditd_packages_installed,
    ),
    Check(
        titles=["Ensure AIDE is installed"],
        evaluate=_evaluate_aide_installed,
        evidence=_evidence_aide_installed,
    ),
]


@dataclass
class Finding:
    """The full chain bxsec.md asks for: Finding -> Control -> Source ->
    Document Version -> Evidence, so a viewer can see not just "this
    failed" but which real control said so and where that control came
    from.
    """

    target: str
    external_id: str
    status: str  # "PASS" or "FAIL"
    control_title: str
    source_name: str
    document_name: str
    document_version: str
    evidence_output: str
    collected_at: str
    # Real CIS remediation text (invariant.normalizer.Control.remediation),
    # already extracted from the PDF and stored on the control -- not
    # invented here. Defaults to "" for the handful of test fixtures that
    # construct a Finding without it.
    remediation: str = ""
    # The raw artifact (PDF) this control's document_version was extracted
    # from -- closes the last link of the Finding -> Control -> Source ->
    # Document Version -> Original evidence chain (collector.save_raw_artifact,
    # already stored in document_versions, just never selected before).
    # document_retrieved_at is when THAT artifact was collected, distinct
    # from collected_at above (when THIS finding was assessed).
    raw_artifact_path: str = ""
    content_hash: str = ""
    document_retrieved_at: str = ""


def document_slug_for_os(os_id: str, version_id: str) -> str:
    """Maps a detected OS id/version to the matching document_slug in
    source.KNOWN_CIS_DOCUMENTS, e.g. ("debian", "11") -> "debian_linux_11",
    ("ubuntu", "20.04") -> "ubuntu_linux_20_04". Matches the naming
    convention already used there.
    """
    return f"{os_id}_linux_{version_id.replace('.', '_')}"


def assess_target(target: str) -> list[Finding]:
    with timed(f"collect_facts:{target}"):
        facts = collect_facts(target)

    if not facts.os_id or not facts.os_version_id:
        raise LookupError(f"could not detect OS for target {target!r}: {facts!r}")
    document = document_slug_for_os(facts.os_id, facts.os_version_id)
    collected_at = datetime.now(timezone.utc).isoformat()

    conn = db.connect()
    findings = []
    for check in CHECKS:
        status = "PASS" if check.evaluate(facts) else "FAIL"

        control = db.select_control_by_title(conn, document=document, titles=check.titles)
        if control is None:
            raise LookupError(f"none of {check.titles!r} found for document {document!r}")

        findings.append(
            Finding(
                target=target,
                external_id=control["external_id"],
                status=status,
                control_title=control["title"],
                source_name=control["source_name"],
                document_name=control["document_name"],
                document_version=control["publisher_version"],
                evidence_output=check.evidence(facts),
                collected_at=collected_at,
                remediation=control["normalized_data"].get("remediation", ""),
                raw_artifact_path=control["raw_artifact_path"] or "",
                content_hash=control["content_hash"] or "",
                document_retrieved_at=(
                    control["retrieved_at"].isoformat() if control["retrieved_at"] else ""
                ),
            )
        )
    conn.close()
    return findings


def assess_targets(targets: list[str]) -> dict[str, list[Finding]]:
    """Runs assess_target() over an arbitrary list of container names --
    the same shape as assess_all(), just not hardcoded to TARGETS. Backs
    `invariant assess --target ...` (see invariant.cli.assess), which lets
    quickdemo.sh (and anyone else) assess a different fixed set of
    containers without duplicating assess_all()'s own logic.
    """
    return {target: assess_target(target) for target in targets}


def assess_all() -> dict[str, list[Finding]]:
    return assess_targets(TARGETS)
