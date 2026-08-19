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
