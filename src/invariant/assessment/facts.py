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
    # /etc/security/pwquality.conf.d/*.conf is part of the real audit for
    # "Ensure password quality checking is enforced" (Group U below) --
    # pwquality reads the base file then the conf.d dir, later values
    # winning, so concatenating both here (missing dir just yields its own
    # `cat` error text, same established pattern) keeps parse_pwquality_conf()
    # accurate for every check that already reads this field, not just the
    # new one.
    ("pwquality_text", "===PWQUALITY===", "cat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>&1"),
    ("pwhistory_text", "===PWHISTORY===", "cat /etc/security/pwhistory.conf 2>&1"),
    ("faillock_text", "===FAILLOCK===", "cat /etc/security/faillock.conf 2>&1"),
    ("sudoers_text", "===SUDOERS===", "cat /etc/sudoers 2>&1"),
    ("shells_text", "===SHELLS===", "cat /etc/shells 2>&1"),
    ("rsyslog_text", "===RSYSLOG===", "cat /etc/rsyslog.conf 2>&1"),
    ("journald_text", "===JOURNALD===", "cat /etc/systemd/journald.conf 2>&1"),
    ("audit_rules_text", "===AUDIT_RULES===", "cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>&1"),
    (
        "kernel_modules_text",
        "===KERNEL_MODULES===",
        "find /lib/modules -mindepth 1 2>&1; echo '---MODPROBE---'; modprobe --showconfig 2>&1; "
        "echo '---LSMOD---'; lsmod 2>&1",
    ),
    ("pam_su_text", "===PAM_SU===", "cat /etc/pam.d/su 2>&1"),
    # The real audit for "Ensure root user umask is configured" checks
    # different file pairs by document (/root/.bash_profile + /root/.bashrc
    # on debian_linux_11/ubuntu_linux_20_04; /root/.profile + /root/.bashrc
    # on every other real target document) -- concatenating all three here
    # avoids per-document branching in facts.py; a missing file just yields
    # its `cat` error text, same established pattern as every other block.
    ("root_shell_startup_text", "===ROOT_SHELL_STARTUP===", "cat /root/.bash_profile /root/.profile /root/.bashrc 2>&1"),
    # The next 3 are full-filesystem `find` scans, not fixed-path reads --
    # a different kind of collection than every block above. A container
    # only has one real mount point (confirmed empirically: `findmnt -Dkerno
    # fstype,target` never lists "/" itself in a container -- the real
    # audit's own mount-enumeration loop would silently scan nothing), so
    # these run `find / -xdev ...` directly instead of the real audit's
    # findmnt-driven multi-mount loop; `-xdev` alone already keeps the scan
    # from crossing into bind-mounted/pseudo filesystems (/proc, /sys,
    # /dev, ...), which is all the real loop is for on a full VM. Timed at
    # ~150-220ms each against a bare debian:12 container -- well inside the
    # existing 10s timeout, no bump needed.
    (
        "world_writable_text",
        "===WORLD_WRITABLE===",
        r"find / -xdev \( -path '/run/user/*' -o -path '/proc/*' -o -path '*/containerd/*' "
        r"-o -path '*/kubelet/*' -o -path '/sys/*' -o -path '/snap/*' \) -prune -o "
        r"\( -type f -o -type d \) -perm -0002 -printf '%y:%m:%p\n' 2>&1",
    ),
    (
        "unowned_text",
        "===UNOWNED===",
        r"find / -xdev \( -path '/run/user/*' -o -path '/proc/*' -o -path '*/containerd/*' "
        r"-o -path '*/kubelet/pods/*' -o -path '*/kubelet/plugins/*' -o -path '/sys/fs/cgroup/memory/*' "
        r"-o -path '/var/*/private/*' \) -prune -o \( -type f -o -type d \) \( -nouser -o -nogroup \) "
        r"-printf '%y:%u:%g:%p\n' 2>&1",
    ),
    # Root's real PATH, the way an interactive root login shell would see
    # it (the real audit reads it via `sudo -Hiu root env`/`sudo su - root
    # -c env`; collection already executes as root inside the target via
    # `docker exec`, and `sudo` isn't installed on 3 of the 6 real target
    # documents' matching containers -- so this spawns root's own login
    # shell directly instead, `bash -l`, which sources /etc/profile and
    # root's own profile/rc chain -- unlike a plain `sh -c` that sources
    # nothing). First line of output is the raw PATH string; each
    # following line reports one ':'-separated component in order
    # (`DIR:<path>:mode=.. uid=.. gid=.. gname=..` if it's a directory that
    # exists, `NODIR:<path>` otherwise, `<path>` empty for a "::" or
    # trailing ":" component) -- awk's `-F:` split (unlike shell word
    # splitting) preserves empty fields the same way Python's `str.split(
    # ":")` does, so the two line up positionally.
    (
        "root_path_probe_text",
        "===ROOT_PATH_PROBE===",
        "l_rp=\"$(bash -l -c 'echo $PATH' 2>&1)\"; printf '%s\\n' \"$l_rp\"; "
        "printf '%s\\n' \"$l_rp\" | awk -F: '{for(i=1;i<=NF;i++) print $i}' | "
        "while IFS= read -r l_p; do "
        "if [ -n \"$l_p\" ] && [ -d \"$l_p\" ]; then printf 'DIR:%s:' \"$l_p\"; "
        "stat -Lc 'mode=%a uid=%u gid=%g gname=%G' \"$l_p\" 2>&1; "
        "else printf 'NODIR:%s\\n' \"$l_p\"; fi; done",
    ),
    # Real audit for "Ensure auditing for processes that start prior to
    # auditd is enabled" (Group U below), run close to verbatim: `find
    # /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} +
    # | grep -v 'audit=1'` should return nothing. A container has no
    # /boot/grub/grub.cfg at all -- `find` matches zero files, the whole
    # pipe naturally produces no output, same vacuous-PASS precedent as
    # the kernel-module checks above (grep against something that isn't
    # there correctly reports "nothing to flag").
    (
        "boot_grub_audit_text",
        "===BOOT_GRUB_AUDIT===",
        r"find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + 2>/dev/null | grep -v 'audit=1' 2>&1",
    ),
    ("interactive_user_files_text", "===INTERACTIVE_USER_FILES===", _INTERACTIVE_USER_FILES_CMD),
    # auditd.conf directives + the file-system evidence the 10 Group A (per
    # checks-backlog.md) auditd.conf-family checks need: the config files
    # under /etc/audit/ (mode), the audit log directory + the files in it
    # (mode/owner/group -- the directory is derived from auditd.conf's own
    # `log_file` directive via `dirname`, the same way the real CIS audit
    # scripts do it, not hardcoded, in case a real target ever overrides
    # it), and a fixed set of audit tool binaries (mode). One shell command,
    # 4 sections separated by their own markers (same "one text field, self-
    # parsed sub-markers" shape as kernel_modules_text above).
    #
    # The tool list is 6 binaries (auditctl, aureport, ausearch, auditd,
    # augenrules, autrace) -- debian_linux_13's own script for "Ensure audit
    # tools mode is configured" drops /sbin/autrace from its array (the
    # other 5 real target documents keep it), but checking it uniformly
    # everywhere is a strict superset, not a false-positive risk: a missing
    # /sbin/autrace just yields no matching stat line for that path (see
    # _parse_stat_lines), and a present-but-permissive one is a real gap
    # regardless of whether the specific target document's own audit text
    # happens to check it -- same "widen the shared check, don't branch per
    # document" pattern used everywhere else in this module.
    (
        "audit_conf_text",
        "===AUDIT_CONF===",
        "cat /etc/audit/auditd.conf 2>&1; echo '---CONFFILES---'; "
        "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) "
        "-printf 'mode=%m uid=%U gid=%G gname=%g path=%p\\n' 2>&1; "
        "echo '---LOGDIR---'; "
        "l_dir=\"$(dirname \"$(awk -F= '$1 ~ /^[[:space:]]*log_file[[:space:]]*$/ "
        "{print $2}' /etc/audit/auditd.conf 2>/dev/null | xargs 2>/dev/null)\" 2>/dev/null)\"; "
        "if [ -n \"$l_dir\" ] && [ -d \"$l_dir\" ]; then "
        "stat -Lc 'mode=%a uid=%u gid=%g gname=%G path=%n' \"$l_dir\" 2>&1; "
        "echo '---LOGFILES---'; "
        "find \"$l_dir\" -maxdepth 1 -type f -printf 'mode=%m uid=%U gid=%G gname=%g path=%p\\n' 2>&1; "
        "else echo 'LOGDIR_NOT_FOUND'; echo '---LOGFILES---'; fi; "
        "echo '---TOOLS---'; "
        "stat -Lc 'mode=%a uid=%u gid=%g gname=%G path=%n' /sbin/auditctl /sbin/aureport "
        "/sbin/ausearch /sbin/auditd /sbin/augenrules /sbin/autrace 2>&1",
    ),
    # "Ensure systemd-timesyncd configured with authorized timeserver"
    # (checks-backlog.md Group B) -- confirmed via Postgres, full untruncated
    # audit script compared across all 6 real documents: same underlying
    # bash logic everywhere (debian_linux_11 uses an older associative-array
    # style, the other 5 a refactored array style), only page numbers and
    # array-bookkeeping cosmetics differ. The real audit reads the merged
    # config via `systemd-analyze cat-config`, i.e. base file + conf.d, later
    # file wins -- concatenating both here is the same established pattern
    # as pwquality_text above (a missing conf.d dir just yields its own
    # `cat` error text).
    ("timesyncd_text", "===TIMESYNCD===", "cat /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf 2>&1"),
    # "Ensure systemd-journal-remote service is not in use" (checks-backlog.md
    # Group B) -- audit text is verbatim identical across all 6 real
    # documents (confirmed via Postgres, only page-number/footer boilerplate
    # differs): `systemctl is-enabled ...socket ...service | grep -P
    # '^enabled'` then the same with `is-active`/`^active`, and "nothing
    # should be returned" from either is the documented PASS condition.
    # These containers don't run real systemd (PID 1 isn't systemd, same gap
    # documented for Group C), so `systemctl` itself errors out here -- but
    # that error is exactly "nothing matching ^enabled/^active", the literal
    # letter of the audit's own PASS condition, not an approximation of it
    # (contrast Group C's enabled+active checks, which need to prove a
    # *positive* running state that a systemd-less container genuinely can't
    # demonstrate). Same vacuous-PASS precedent as boot_grub_audit_text.
    (
        "journal_remote_status_text",
        "===JOURNAL_REMOTE_STATUS===",
        "systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>&1 | grep -P -- '^enabled'; "
        "systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>&1 | grep -P -- '^active'",
    ),
    # checks-backlog.md "Grupo C -- systemd real" (6 candidates). Real audit
    # commands, verbatim, confirmed via Postgres across all 6 target
    # documents (identical text, only page/footer noise and external_id
    # differ). Collected unconditionally on every target, same as every
    # other field here -- a target with no real systemd just gets
    # systemctl's own error text back ("System has not been booted with
    # systemd as init system..."), which every evaluate() below reads as
    # "not enabled/active" (for the 2 unconditional controls) or, combined
    # with installed_packages, as a vacuous PASS for the 4 controls whose
    # own real audit text is gated "- IF - X is in use on the system" --
    # same substitution pattern _evaluate_single_time_sync_daemon already
    # uses, and the same reasoning already applied to
    # journal_remote_status_text above.
    (
        "systemd_service_status_text",
        "===SYSTEMD_SERVICE_STATUS===",
        "echo '--AUDITD_ENABLED--'; systemctl is-enabled auditd 2>&1; "
        "echo '--AUDITD_ACTIVE--'; systemctl is-active auditd 2>&1; "
        "echo '--CHRONY_ENABLED--'; systemctl is-enabled chrony.service 2>&1; "
        "echo '--CHRONY_ACTIVE--'; systemctl is-active chrony.service 2>&1; "
        "echo '--CRON_ENABLED--'; systemctl list-unit-files 2>&1 | awk '$1~/^crond?\\.service/{print $2}'; "
        "echo '--CRON_ACTIVE--'; systemctl list-units 2>&1 | awk '$1~/^crond?\\.service/{print $3}'; "
        "echo '--TIMESYNCD_ENABLED--'; systemctl is-enabled systemd-timesyncd.service 2>&1; "
        "echo '--TIMESYNCD_ACTIVE--'; systemctl is-active systemd-timesyncd.service 2>&1",
    ),
    # "Ensure chrony is running as user _chrony" -- real audit is a live
    # `ps -ef` grep, unconditional on package presence: a target with no
    # chronyd process at all naturally produces no output either way, same
    # vacuous-pass-by-absence precedent as boot_grub_audit_text.
    (
        "chrony_process_user_text",
        "===CHRONY_PROCESS_USER===",
        "ps -ef 2>&1 | awk '(/[c]hronyd/ && $1!=\"_chrony\") { print $1 }'",
    ),
    # "Ensure the running and on disk configuration is the same" -- real
    # audit is `augenrules --check`, whose PASS text is exactly "No
    # change". A target without augenrules installed gets a shell error
    # here, read as FAIL -- fails closed, same posture Group I already
    # established for every other auditd-absent check (a missing
    # auditd.conf/log directory is an explicit FAIL branch in the real
    # script, not a vacuous pass).
    ("audit_rules_sync_text", "===AUDIT_RULES_SYNC===", "augenrules --check 2>&1"),
    # checks-backlog.md Group C's 24 partition/mount-option candidates: one
    # `findmnt -kn <target>` per candidate mount point, looped rather than
    # passed as one multi-target invocation -- confirmed empirically that
    # `findmnt -kn A B` exits 1 with zero output the moment even one of A/B
    # isn't a real mount (not "print what resolves, skip the rest"), which
    # would silently blank every target's line the first time any one of
    # the 7 isn't mounted. Looped, each target's line (or absence) is
    # independent. Real audit for both the "<option> set on X" and the
    # "separate partition exists for X" families is this exact command
    # (confirmed via Postgres across all 6 target documents) -- a target
    # that isn't a real mount at all yields no line here, which is what the
    # "<option> set" evaluators read as a vacuous PASS (CIS's own "- IF - a
    # separate partition exists" conditional), not a failure.
    (
        "mounts_text",
        "===MOUNTS===",
        "for l_t in /dev/shm /home /tmp /var /var/log /var/log/audit /var/tmp; do "
        "findmnt -kn \"$l_t\" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; done",
    ),
    # Best-effort "is this target a container" signal for demo.sh's report
    # (scripts/demo/report.py) -- not read by any real Check, this tool has
    # no transport to a target other than `docker exec`, so there's no more
    # authoritative way to ask (no cloud metadata endpoint, no hypervisor
    # check). /.dockerenv is Docker's own marker file; /proc/1/cgroup
    # mentioning a container-runtime path fragment covers Docker/containerd/
    # Kubernetes even where /.dockerenv is absent (e.g. containerd directly).
    # See is_running_in_container() below for how this is interpreted.
    (
        "container_detection_text",
        "===CONTAINER_DETECTION===",
        "test -f /.dockerenv && echo '/.dockerenv:present' || echo '/.dockerenv:absent'; "
        "cat /proc/1/cgroup 2>&1",
    ),
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
    faillock_text: str = ""
    sudoers_text: str = ""
    shells_text: str = ""
    rsyslog_text: str = ""
    journald_text: str = ""
    audit_rules_text: str = ""
    kernel_modules_text: str = ""
    pam_su_text: str = ""
    root_shell_startup_text: str = ""
    world_writable_text: str = ""
    unowned_text: str = ""
    root_path_probe_text: str = ""
    boot_grub_audit_text: str = ""
    interactive_user_files_text: str = ""
    audit_conf_text: str = ""
    timesyncd_text: str = ""
    journal_remote_status_text: str = ""
    systemd_service_status_text: str = ""
    chrony_process_user_text: str = ""
    audit_rules_sync_text: str = ""
    mounts_text: str = ""
    container_detection_text: str = ""


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
        faillock_text=text_values["faillock_text"],
        sudoers_text=text_values["sudoers_text"],
        shells_text=text_values["shells_text"],
        rsyslog_text=text_values["rsyslog_text"],
        journald_text=text_values["journald_text"],
        audit_rules_text=text_values["audit_rules_text"],
        kernel_modules_text=text_values["kernel_modules_text"],
        pam_su_text=text_values["pam_su_text"],
        root_shell_startup_text=text_values["root_shell_startup_text"],
        world_writable_text=text_values["world_writable_text"],
        unowned_text=text_values["unowned_text"],
        root_path_probe_text=text_values["root_path_probe_text"],
        boot_grub_audit_text=text_values["boot_grub_audit_text"],
        interactive_user_files_text=text_values["interactive_user_files_text"],
        audit_conf_text=text_values["audit_conf_text"],
        timesyncd_text=text_values["timesyncd_text"],
        journal_remote_status_text=text_values["journal_remote_status_text"],
        systemd_service_status_text=text_values["systemd_service_status_text"],
        chrony_process_user_text=text_values["chrony_process_user_text"],
        audit_rules_sync_text=text_values["audit_rules_sync_text"],
        mounts_text=text_values["mounts_text"],
        container_detection_text=text_values["container_detection_text"],
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


_CONTAINER_CGROUP_MARKERS = ("docker", "containerd", "kubepods")


def is_running_in_container(facts: SystemFacts) -> bool:
    """Best-effort "is this target a container" signal, used only by
    demo.sh's report (scripts/demo/report.py) to decide whether a FAIL on a
    container-impossible title (no bootloader, no functioning systemd/
    journald, audit subsystem often not fully functional without extra
    capabilities) is an environment limitation or a real gap -- on a
    bare-metal/VM target the same title is just a normal FAIL, no automatic
    excuse. Not used by any real Check or by assess_target() itself.

    True if /.dockerenv exists (Docker's own marker file) or /proc/1/cgroup
    mentions a known container-runtime path fragment (covers containerd/
    Kubernetes even where /.dockerenv is absent). A false negative here just
    means a demo report treats a FAIL as a real gap instead of an
    environment limitation -- fails closed, not open.
    """
    first_line, _, cgroup_text = facts.container_detection_text.partition("\n")
    if first_line.strip() == "/.dockerenv:present":
        return True
    return any(marker in cgroup_text for marker in _CONTAINER_CGROUP_MARKERS)
