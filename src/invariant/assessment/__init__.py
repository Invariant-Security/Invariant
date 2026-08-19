"""Assesses Docker demo targets against real controls already in Postgres.

This is the bxsec-branch "Evidence Collector -> Assessment -> Finding" side
of the pipeline (see bxsec.md and PRD sec. 23, "Future Assessment
Architecture") -- distinct from invariant.collector, which preserves CIS
document artifacts, not environment evidence.

Which CIS document applies to a target is *detected*, not hardcoded: each
target's real OS/version is read from its own /etc/os-release (the same
file every modern Linux distro exposes for exactly this purpose), then
mapped to a document_slug. Only two controls are actually implemented
(SSH root login, /etc/shadow permissions) -- checking the rest of a
document's ~300 controls would need a hand-written evidence command +
evaluator per control, the same way these two were built; there's no
generic way to turn CIS's free-text audit instructions into an executable
check.
"""

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from invariant.storage import postgres as db

TARGETS = [
    "invariant-debian-baseline",
    "invariant-debian-ssh-bad",
    "invariant-debian-permissions-bad",
    "invariant-ubuntu-baseline",
    "invariant-ubuntu-ssh-bad",
    "invariant-ubuntu-permissions-bad",
]

_SSH_COMMAND = "sshd -T | grep permitrootlogin"


def _evaluate_ssh_permit_root_login(output: str) -> bool:
    return output.strip() == "permitrootlogin no"


_SHADOW_COMMAND = "stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow"
_SHADOW_STAT_RE = re.compile(
    r"\((?P<mode>\d+)/\S+\)\s+Uid:\s*\(\s*(?P<uid>\d+)/\s*\S+\)\s+Gid:\s*\(\s*(?P<gid>\d+)/\s*(?P<gname>\S+)\)"
)


def _evaluate_shadow_permissions(output: str) -> bool:
    """Matches control 7.1.5's real audit condition: mode 640 or more
    restrictive, Uid 0/root, Gid 0/root or the shadow group.
    """
    match = _SHADOW_STAT_RE.search(output)
    if not match:
        return False
    mode = int(match.group("mode"), 8)
    uid = int(match.group("uid"))
    gname = match.group("gname")
    return mode <= 0o640 and uid == 0 and gname in ("root", "shadow")


@dataclass
class Check:
    """One implemented, hand-written evidence command + evaluator, plus
    every title wording it's known to appear under -- exact title text
    drifts a little between CIS documents (confirmed: "Ensure permissions
    on /etc/shadow are configured" vs "Ensure access to /etc/shadow is
    configured" for the same underlying check), so the control is looked
    up by title, not a hardcoded external_id (also confirmed to drift
    between documents -- Debian 13 uses 5.1.21 where the rest use 5.1.20).
    """

    titles: list[str]
    command: str
    evaluate: Callable[[str], bool]


# The only two controls Invariant actually knows how to check right now.
# Adding another means writing its evidence command + evaluator by hand,
# the same way these were: run the control's real audit command, confirm
# what a real PASS/FAIL looks like against a real target, then encode it
# here.
CHECKS = [
    Check(
        titles=["Ensure sshd PermitRootLogin is disabled"],
        command=_SSH_COMMAND,
        evaluate=_evaluate_ssh_permit_root_login,
    ),
    Check(
        titles=[
            "Ensure permissions on /etc/shadow are configured",
            "Ensure access to /etc/shadow is configured",
        ],
        command=_SHADOW_COMMAND,
        evaluate=_evaluate_shadow_permissions,
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
    evidence_command: str
    evidence_output: str
    collected_at: str


def collect(target: str, command: str) -> str:
    """Runs a command inside a running container via `docker exec` and
    returns its combined stdout+stderr, stripped. This is the "Evidence
    Collector" -- no real network SSH, matching the demo's Docker-only
    scope (see bxsec.md sec. 3).
    """
    result = subprocess.run(
        ["docker", "exec", target, "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return (result.stdout + result.stderr).strip()


def detect_os(target: str) -> dict[str, str]:
    """Reads /etc/os-release inside the target and parses its KEY=value
    lines -- the standard, real way every modern Linux distro exposes what
    it is. No assumption is made about the target ahead of time.
    """
    output = collect(target, "cat /etc/os-release")
    info = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        info[key.strip()] = value.strip().strip('"')
    return info


def document_slug_for_os(os_id: str, version_id: str) -> str:
    """Maps a detected OS id/version to the matching document_slug in
    source.KNOWN_CIS_DOCUMENTS, e.g. ("debian", "11") -> "debian_linux_11",
    ("ubuntu", "20.04") -> "ubuntu_linux_20_04". Matches the naming convention
    already used there.
    """
    return f"{os_id}_linux_{version_id.replace('.', '_')}"


def assess_target(target: str) -> list[Finding]:
    os_info = detect_os(target)
    if "ID" not in os_info or "VERSION_ID" not in os_info:
        raise LookupError(f"could not detect OS for target {target!r}: {os_info!r}")
    document = document_slug_for_os(os_info["ID"], os_info["VERSION_ID"])

    conn = db.connect()
    findings = []
    for check in CHECKS:
        output = collect(target, check.command)
        status = "PASS" if check.evaluate(output) else "FAIL"

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
                evidence_command=check.command,
                evidence_output=output,
                collected_at=datetime.now(timezone.utc).isoformat(),
            )
        )
    conn.close()
    return findings


def assess_all() -> dict[str, list[Finding]]:
    return {target: assess_target(target) for target in TARGETS}
