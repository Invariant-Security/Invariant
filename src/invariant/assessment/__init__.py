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
