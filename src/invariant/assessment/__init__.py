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
