"""Collects a broad snapshot of a target's state in one pass, instead of
one `docker exec` per check.

No agent installed on the target -- one script run once via `docker exec`,
matching how agentless tools (Ansible, OpenSCAP) gather evidence. Checks
then evaluate against the returned SystemFacts as plain Python, not by
running their own command.
"""

import subprocess
from dataclasses import dataclass, field

# Paths every implemented Check currently needs stat() on. Grows as more
# checks are added -- there's nothing distro-specific about this list, it's
# just "which files does any check care about right now."
_STAT_PATHS = ["/etc/shadow"]

_MARKER_OS_RELEASE = "===OS_RELEASE==="
_MARKER_SSHD_CONFIG = "===SSHD_CONFIG==="
_MARKER_STAT_PREFIX = "===STAT:"


def _collect_script() -> str:
    stat_commands = "\n".join(
        f"echo '{_MARKER_STAT_PREFIX}{path}==='; "
        f"stat -Lc 'mode=%a uid=%u gid=%g gname=%G' {path} 2>&1"
        for path in _STAT_PATHS
    )
    return (
        f"echo '{_MARKER_OS_RELEASE}'; cat /etc/os-release 2>&1; "
        f"echo '{_MARKER_SSHD_CONFIG}'; cat /etc/ssh/sshd_config 2>&1; "
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


def _parse_os_release(text: str) -> dict[str, str]:
    info = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        info[key.strip()] = value.strip().strip('"')
    return info


def parse_sshd_config(text: str) -> dict[str, str]:
    """OpenSSH directives are case-insensitive and "Directive value" per
    line; comments start with '#', blank lines are skipped. Later lines
    win on conflict -- matches how sshd itself resolves duplicates enough
    for our purposes (we only ever append one override line per Dockerfile).
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

    os_release_start = output.index(_MARKER_OS_RELEASE) + len(_MARKER_OS_RELEASE)
    sshd_start = output.index(_MARKER_SSHD_CONFIG)
    os_release_text = output[os_release_start:sshd_start]

    sshd_end = output.index(_MARKER_STAT_PREFIX) if _MARKER_STAT_PREFIX in output else len(output)
    sshd_text = output[sshd_start + len(_MARKER_SSHD_CONFIG) : sshd_end]

    file_stats = {}
    remainder = output[sshd_end:]
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

    os_release = _parse_os_release(os_release_text)
    return SystemFacts(
        os_id=os_release.get("ID"),
        os_version_id=os_release.get("VERSION_ID"),
        sshd_config=parse_sshd_config(sshd_text),
        file_stats=file_stats,
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
