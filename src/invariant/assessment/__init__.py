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
            )
        )
    conn.close()
    return findings


def assess_all() -> dict[str, list[Finding]]:
    return {target: assess_target(target) for target in TARGETS}
