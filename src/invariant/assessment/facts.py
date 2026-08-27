"""Collects a broad snapshot of a target's state in one pass, instead of
one `docker exec` per check.

No agent installed on the target -- one script run once via `docker exec`,
matching how agentless tools (Ansible, OpenSCAP) gather evidence. Checks
then evaluate against the returned SystemFacts as plain Python, not by
running their own command.

This module is deliberately the *only* place that knows how to talk to a
target. Adding a new kind of check means adding a field here (and a new
line in the collection script) -- individual Check.evaluate()/evidence()
functions in invariant.assessment never run their own docker exec.
"""

import subprocess
from dataclasses import dataclass, field

# Paths every implemented Check currently needs stat() on. Grows as more
# checks are added -- there's nothing distro-specific about this list, it's
# just "which files does any check care about right now." A missing file
# (e.g. an unused SSH host key algorithm) just comes back as a FileStat
# with every field None -- not an error.
_STAT_PATHS = [
    "/etc/shadow",
    "/etc/issue",
    "/etc/issue.net",
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/group",
    "/etc/group-",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/shells",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ed25519_key.pub",
    "/etc/crontab",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/cron.d",
    "/etc/motd",
    "/boot/grub/grub.cfg",
    "/etc/audit/audit.rules",
    "/etc/audit/rules.d",
    "/sbin/auditctl",
    "/sbin/auditd",
    "/sbin/augenrules",
]

_MARKER_OS_RELEASE = "===OS_RELEASE==="
_MARKER_SSHD_CONFIG = "===SSHD_CONFIG==="
_MARKER_STAT_PREFIX = "===STAT:"

# Enumerates every /etc/passwd account's home directory + the dotfiles
# directly inside it, in one pass -- backs the "local interactive user home
# directories"/"dot files access" checks, which need per-user dynamic paths
# _STAT_PATHS can't express (that list is fixed). Deliberately does *not*
# pre-filter to "interactive" users here (that needs /etc/shells, already
# its own text block) -- it just stats every account's home and lets
# assessment/__init__.py's _local_interactive_users() decide which rows are
# relevant, same "collect broadly, filter in evaluate()" split as the rest
# of this module. A home directory that doesn't exist (`[ -d "$h" ]` false)
# simply emits no HOME line for that user -- evaluate() treats a missing
# entry as "home doesn't exist", it's not a collection error.
_INTERACTIVE_USER_FILES_CMD = """awk -F: '{print $1, $6}' /etc/passwd | while read -r u h; do [ -n "$h" ] && [ -d "$h" ] || continue; stat -Lc "HOME $u %U %G %a $h" "$h"; find "$h" -maxdepth 1 -type f -name '.*' 2>/dev/null | while read -r f; do stat -Lc "DOT $u %U %G %a $(basename "$f")" "$f"; done; done"""

# (SystemFacts attribute name, output marker, shell command). Read as plain
# text -- each check does its own parsing/grepping over the raw content,
# same as sshd_config was before it got a dedicated parser. A file that
# doesn't exist just yields its `cat`/`dpkg-query` error text; that's a
# legitimate "not configured" signal for a check to interpret, not a
# collection failure (unlike mount/auditd, which fail structurally in an
# unprivileged container and can't be checked here at all).
_TEXT_BLOCKS = [
    ("passwd_text", "===PASSWD===", "cat /etc/passwd 2>&1"),
    ("group_text", "===GROUP===", "cat /etc/group 2>&1"),
    ("shadow_text", "===SHADOW_TEXT===", "cat /etc/shadow 2>&1"),
    ("pam_common_auth", "===PAM_COMMON_AUTH===", "cat /etc/pam.d/common-auth 2>&1"),
    ("pam_common_password", "===PAM_COMMON_PASSWORD===", "cat /etc/pam.d/common-password 2>&1"),
    ("pam_common_account", "===PAM_COMMON_ACCOUNT===", "cat /etc/pam.d/common-account 2>&1"),
    ("pam_login", "===PAM_LOGIN===", "cat /etc/pam.d/login 2>&1"),
    ("login_defs_text", "===LOGIN_DEFS===", "cat /etc/login.defs 2>&1"),
    ("hosts_allow_text", "===HOSTS_ALLOW===", "cat /etc/hosts.allow 2>&1"),
    ("hosts_deny_text", "===HOSTS_DENY===", "cat /etc/hosts.deny 2>&1"),
    ("installed_packages_text", "===INSTALLED_PACKAGES===", "dpkg-query -W -f='${Package}\\n' 2>&1"),
    ("pwquality_text", "===PWQUALITY===", "cat /etc/security/pwquality.conf 2>&1"),
    ("pwhistory_text", "===PWHISTORY===", "cat /etc/security/pwhistory.conf 2>&1"),
    ("sudoers_text", "===SUDOERS===", "cat /etc/sudoers 2>&1"),
    ("shells_text", "===SHELLS===", "cat /etc/shells 2>&1"),
    ("rsyslog_text", "===RSYSLOG===", "cat /etc/rsyslog.conf 2>&1"),
    ("journald_text", "===JOURNALD===", "cat /etc/systemd/journald.conf 2>&1"),
    ("audit_rules_text", "===AUDIT_RULES===", "cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>&1"),
    ("interactive_user_files_text", "===INTERACTIVE_USER_FILES===", _INTERACTIVE_USER_FILES_CMD),
]


def _collect_script() -> str:
    # `sshd -T` (not `cat /etc/ssh/sshd_config`) on purpose: it prints the
    # *effective* config -- every directive, including ones left at their
    # OpenSSH default because the config file never sets them explicitly
    # (confirmed: our own demo containers never set IgnoreRhosts, but
    # `sshd -T` still correctly reports its secure default, "yes"; parsing
    # the raw file would have missed it entirely and looked unset). This
    # is also literally what CIS's own audit commands run.
    #
    # Each block's marker is echoed *before* its command runs, so every
    # marker is guaranteed present in the output even if the command
    # itself errors (missing file, missing package database, ...) --
    # `_parse_collect_output` relies on that to slice the output
    # positionally instead of needing every command to succeed.
    text_commands = "; ".join(
        f"echo '{marker}'; {command}" for _, marker, command in _TEXT_BLOCKS
    )
    stat_commands = "\n".join(
        f"echo '{_MARKER_STAT_PREFIX}{path}==='; "
        f"stat -Lc 'mode=%a uid=%u gid=%g gname=%G' {path} 2>&1"
        for path in _STAT_PATHS
    )
    return (
        f"echo '{_MARKER_OS_RELEASE}'; cat /etc/os-release 2>&1; "
        f"echo '{_MARKER_SSHD_CONFIG}'; sshd -T 2>&1; "
        f"{text_commands}; "
        f"{stat_commands}"
    )


@dataclass
class FileStat:
    mode: int | None  # octal permission bits, e.g. 0o640; None if stat failed
    uid: int | None
    gid: int | None
    gname: str | None


@dataclass
class SystemFacts:
    os_id: str | None
    os_version_id: str | None
    sshd_config: dict[str, str]  # lowercased directive -> value
    file_stats: dict[str, FileStat]  # path -> FileStat
    passwd_text: str = ""
    group_text: str = ""
    shadow_text: str = ""
    pam_common_auth: str = ""
    pam_common_password: str = ""
    pam_common_account: str = ""
    pam_login: str = ""
    login_defs_text: str = ""
    hosts_allow_text: str = ""
    hosts_deny_text: str = ""
    installed_packages: set[str] = field(default_factory=set)
    pwquality_text: str = ""
    pwhistory_text: str = ""
    sudoers_text: str = ""
    shells_text: str = ""
    rsyslog_text: str = ""
    journald_text: str = ""
    audit_rules_text: str = ""
    interactive_user_files_text: str = ""


def _parse_os_release(text: str) -> dict[str, str]:
    info = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        info[key.strip()] = value.strip().strip('"')
    return info


def parse_sshd_config(text: str) -> dict[str, str]:
    """Parses "directive value" lines -- works on `sshd -T`'s effective-
    config output (what _collect_script() actually feeds it: already
    lowercase, one directive per line, defaults included) and on a raw
    sshd_config file just as well (comments/blank lines skipped). Later
    lines win on conflict.
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        directive, value = parts
        directives[directive.lower()] = value.strip()
    return directives


def _parse_installed_packages(text: str) -> set[str]:
    """Parses `dpkg-query -W -f='${Package}\\n'` output -- one package name
    per line. A package database read failure (non-Debian image) just
    yields an empty set, same "not present" meaning as a package that was
    never installed.
    """
    return {line.strip() for line in text.splitlines() if line.strip()}


def _parse_stat_line(text: str) -> FileStat:
    fields = {}
    for token in text.strip().split():
        if "=" in token:
            key, _, value = token.partition("=")
            fields[key] = value

    if "mode" not in fields:
        return FileStat(mode=None, uid=None, gid=None, gname=None)
    return FileStat(
        mode=int(fields["mode"], 8),
        uid=int(fields["uid"]),
        gid=int(fields["gid"]),
        gname=fields["gname"],
    )


def _parse_collect_output(output: str) -> SystemFacts:
    if _MARKER_OS_RELEASE not in output or _MARKER_SSHD_CONFIG not in output:
        raise LookupError(f"collection script did not run as expected, got: {output!r}")

    # Every marker up to (but not including) the per-path stat markers, in
    # the exact order _collect_script() emits them -- lets us slice the
    # output positionally without each command needing to succeed.
    ordered_markers = [_MARKER_OS_RELEASE, _MARKER_SSHD_CONFIG] + [m for _, m, _ in _TEXT_BLOCKS]
    try:
        positions = [output.index(marker) for marker in ordered_markers]
        stat_section_start = output.index(_MARKER_STAT_PREFIX)
    except ValueError as exc:
        raise LookupError(f"collection script did not run as expected, got: {output!r}") from exc
    positions.append(stat_section_start)

    segments = {}
    for i, marker in enumerate(ordered_markers):
        start = positions[i] + len(marker)
        end = positions[i + 1]
        segments[marker] = output[start:end].strip("\n")

    os_release = _parse_os_release(segments[_MARKER_OS_RELEASE])
    sshd_config = parse_sshd_config(segments[_MARKER_SSHD_CONFIG])
    text_values = {attr: segments[marker] for attr, marker, _ in _TEXT_BLOCKS}

    file_stats = {}
    remainder = output[stat_section_start:]
    for path in _STAT_PATHS:
        marker = f"{_MARKER_STAT_PREFIX}{path}==="
        start = remainder.index(marker) + len(marker)
        next_marker_positions = [
            remainder.index(f"{_MARKER_STAT_PREFIX}{p}===", start)
            for p in _STAT_PATHS
            if f"{_MARKER_STAT_PREFIX}{p}===" in remainder[start:]
        ]
        end = min(next_marker_positions) if next_marker_positions else len(remainder)
        file_stats[path] = _parse_stat_line(remainder[start:end])

    return SystemFacts(
        os_id=os_release.get("ID"),
        os_version_id=os_release.get("VERSION_ID"),
        sshd_config=sshd_config,
        file_stats=file_stats,
        passwd_text=text_values["passwd_text"],
        group_text=text_values["group_text"],
        shadow_text=text_values["shadow_text"],
        pam_common_auth=text_values["pam_common_auth"],
        pam_common_password=text_values["pam_common_password"],
        pam_common_account=text_values["pam_common_account"],
        pam_login=text_values["pam_login"],
        login_defs_text=text_values["login_defs_text"],
        hosts_allow_text=text_values["hosts_allow_text"],
        hosts_deny_text=text_values["hosts_deny_text"],
        installed_packages=_parse_installed_packages(text_values["installed_packages_text"]),
        pwquality_text=text_values["pwquality_text"],
        pwhistory_text=text_values["pwhistory_text"],
        sudoers_text=text_values["sudoers_text"],
        shells_text=text_values["shells_text"],
        rsyslog_text=text_values["rsyslog_text"],
        journald_text=text_values["journald_text"],
        audit_rules_text=text_values["audit_rules_text"],
        interactive_user_files_text=text_values["interactive_user_files_text"],
    )


def collect_facts(target: str) -> SystemFacts:
    """Runs one compound command inside the target via `docker exec` and
    parses its output into a SystemFacts snapshot -- everything a Check
    needs, gathered in a single round trip.
    """
    result = subprocess.run(
        ["docker", "exec", target, "sh", "-c", _collect_script()],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return _parse_collect_output(result.stdout + result.stderr)
