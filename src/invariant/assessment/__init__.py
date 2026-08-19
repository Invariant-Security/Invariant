"""Assesses Docker demo targets against real controls already in Postgres.

This is the bxsec-branch "Evidence Collector -> Assessment -> Finding" side
of the pipeline (see bxsec.md and PRD sec. 23, "Future Assessment
Architecture") -- distinct from invariant.collector, which preserves CIS
document artifacts, not environment evidence.
"""

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from invariant.storage import postgres as db

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
class AssessedControl:
    external_id: str
    command: str
    evaluate: Callable[[str], bool]


def ssh_permit_root_login(external_id: str) -> AssessedControl:
    return AssessedControl(external_id, _SSH_COMMAND, _evaluate_ssh_permit_root_login)


def shadow_permissions(external_id: str) -> AssessedControl:
    return AssessedControl(external_id, _SHADOW_COMMAND, _evaluate_shadow_permissions)


# Maps each demo Docker container to the CIS document it should be assessed
# against, and which controls to check -- external_id numbering drifts
# slightly between documents (confirmed: Debian 13's sshd PermitRootLogin
# check is 7.1.21, not 7.1.20 like the other 5), so each target names its
# own id rather than assuming one id applies everywhere.
TARGETS = {
    "invariant-debian-baseline": {
        "document": "debian_linux_11",
        "controls": [ssh_permit_root_login("5.1.20"), shadow_permissions("7.1.5")],
    },
    "invariant-debian-ssh-bad": {
        "document": "debian_linux_12",
        "controls": [ssh_permit_root_login("5.1.20"), shadow_permissions("7.1.5")],
    },
    "invariant-debian-permissions-bad": {
        "document": "debian_linux_13",
        "controls": [ssh_permit_root_login("5.1.21"), shadow_permissions("7.1.5")],
    },
    "invariant-ubuntu-baseline": {
        "document": "ubuntu_20_04",
        "controls": [ssh_permit_root_login("5.1.20"), shadow_permissions("7.1.5")],
    },
    "invariant-ubuntu-ssh-bad": {
        "document": "ubuntu_22_04",
        "controls": [ssh_permit_root_login("5.1.20"), shadow_permissions("7.1.5")],
    },
    "invariant-ubuntu-permissions-bad": {
        "document": "ubuntu_24_04",
        "controls": [ssh_permit_root_login("5.1.20"), shadow_permissions("7.1.5")],
    },
}


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


def assess_target(target: str) -> list[Finding]:
    if target not in TARGETS:
        raise ValueError(f"unknown target: {target!r} (known: {', '.join(TARGETS)})")

    document = TARGETS[target]["document"]
    conn = db.connect()
    findings = []
    for assessed in TARGETS[target]["controls"]:
        output = collect(target, assessed.command)
        status = "PASS" if assessed.evaluate(output) else "FAIL"

        control = db.select_control_by_external_id(conn, document=document, external_id=assessed.external_id)
        if control is None:
            raise LookupError(f"control {assessed.external_id!r} not found for document {document!r}")

        findings.append(
            Finding(
                target=target,
                external_id=assessed.external_id,
                status=status,
                control_title=control["title"],
                source_name=control["source_name"],
                document_name=control["document_name"],
                document_version=control["publisher_version"],
                evidence_command=assessed.command,
                evidence_output=output,
                collected_at=datetime.now(timezone.utc).isoformat(),
            )
        )
    conn.close()
    return findings


def assess_all() -> dict[str, list[Finding]]:
    return {target: assess_target(target) for target in TARGETS}
