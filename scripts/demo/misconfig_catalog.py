"""Catalog of demo misconfiguration recipes for demo.sh.

Each Recipe below breaks exactly one control that PASSES on the hardened
demo images (infra/docker/demo-{debian,ubuntu}-hardened/Dockerfile) back to
a FAIL state, via a plain `docker exec <container> sh -c "<command>"` -- no
new packages, no network, matching the same "pure config" posture the
hardened Dockerfiles themselves use. scripts/demo/apply_misconfigs.py draws
2-3 non-repeating recipes per "problem" container from this pool.

Every recipe cites the real Check.titles list it targets, copied verbatim
from src/invariant/assessment/__init__.py's CHECKS -- never an invented
failure condition. See docs/architecture/checks.md for the non-negotiable
rule this enforces ("every Check must cite a real control... never
invented") and for how "demo-eligible" (this catalog's scope) was derived:
it's every one of the 199 CHECKS that already PASSES on both hardened
images except the 9 genuinely-impossible-in-an-unprivileged-container gaps
documented in CONTAINER_IMPOSSIBLE_TITLES below (no bootloader, no
functioning systemd/journald PID 1, no immutable-flag-capable audit
subsystem without extra capabilities, no live auditd/chrony/cron daemon).
Everything else that used to be a gap here (cron file permissions,
pam_pwquality, su restriction, faillock root lockout, single time-sync
daemon, auditd.conf directives, real audit rules) was closed by hardening
the two Dockerfiles for real -- see docs/architecture/checks.md's own
history of that work. "Ensure separate partition exists for /var"
(checks-backlog.md Group C) also fails on both images but is deliberately
NOT in CONTAINER_IMPOSSIBLE_TITLES -- it's a real infra tradeoff (`/var`
staying off tmpfs to protect dpkg's own database), not a container
impossibility, so it's simply outside this catalog's "demo-eligible" scope.

`document` on each Recipe is informational only (which of the two demo CIS
documents -- debian_linux_11 or ubuntu_linux_20_04 -- this recipe's control
lives in for that distro); assess_target() itself resolves the control by
title against whichever document matches the target's detected OS, so it's
never read by apply_misconfigs.py, only by a human via `invariant assess`'s
own printed Finding chain or checks.md.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Recipe:
    id: str
    distro: str  # "any", "debian", or "ubuntu" -- every recipe here is
    # "any" because the two hardened images (see module docstring) share an
    # identical file layout for everything this catalog touches; the field
    # still exists so a future distro-specific recipe (e.g. one keyed off a
    # config path that only exists on one of the two images) has somewhere
    # to say so, and so apply_misconfigs.py has one real filter to apply
    # rather than assuming every recipe is universally safe.
    check_titles: tuple[str, ...]
    document: str
    description: str
    commands: tuple[str, ...]


# The 5 CHECKS titles that fail on both hardened images no matter how much
# they're configured -- genuinely impossible inside an unprivileged Docker
# container, not "never got around to hardening it" (see the module
# docstring's history: the other 20 that used to be structural gaps here
# were closed by hardening the two Dockerfiles for real). demo.sh's report
# (scripts/demo/report.py) only honors a title in this set as
# "environmental" when the specific target is actually detected as a
# container (facts.is_running_in_container()) -- on a bare-metal/VM target
# these same titles are just normal PASS/FAIL based on the real evaluate()
# result, no automatic excuse.
CONTAINER_IMPOSSIBLE_TITLES = frozenset(
    {
        # Needs an actual loaded, immutable-flagged auditd rule set (`auditctl
        # -e 2`) -- the audit netlink subsystem generally isn't fully
        # functional inside an unprivileged container namespace, so even
        # with auditd installed and rules written to disk (see the two
        # Dockerfiles), there's no live daemon to flag as immutable.
        "Ensure the audit configuration is immutable",
        # journald.conf's Compress/Storage/rotation directives aren't
        # meaningfully consulted without systemd-journald actually running
        # as part of a real systemd PID 1, which this container doesn't have.
        "Ensure journald Compress is configured",
        "Ensure journald Storage is configured",
        "Ensure journald log file rotation is configured",
        # /boot/grub/grub.cfg never exists in a container -- no bootloader.
        "Ensure access to bootloader config is configured",
        # checks-backlog.md "Grupo C -- systemd real": auditd/chrony/cron are
        # installed and configured on both hardened images (see the two
        # Dockerfiles), but neither runs systemd as PID 1, so none of these
        # daemons is ever actually *running* -- `systemctl is-enabled/
        # is-active` can't report a real state, same structural limit as the
        # journald/immutable-audit entries above. "Ensure chrony is running
        # as user _chrony" and "Ensure systemd-timesyncd is enabled and
        # running" are NOT in this set: both pass vacuously here instead
        # (no chronyd process at all; systemd-timesyncd never installed,
        # chrony is this image's chosen single time-sync daemon) -- CIS's
        # own audit text gates all 4 titles below/above on "- IF - X is in
        # use", so a genuinely-absent daemon is a legitimate PASS, not a gap.
        "Ensure auditd service is enabled and active",
        "Ensure chrony is enabled and running",
        "Ensure cron daemon is enabled and active",
        # `augenrules --check` compares the live-loaded ruleset against
        # rules.d/*.rules -- with no systemd/auditd ever starting, nothing
        # ever loads the rules, so "running" and "on disk" can never match
        # regardless of how correct the on-disk rules file is.
        "Ensure the running and on disk configuration is the same",
    }
)

_DEBIAN_DOC = "debian_linux_11"
_UBUNTU_DOC = "ubuntu_linux_20_04"
_BOTH_DOCS = f"{_DEBIAN_DOC} / {_UBUNTU_DOC}"

RECIPES: list[Recipe] = [
    # --- File permission/ownership (Group A/D of CHECKS) ---
    Recipe(
        id="shadow-world-readable",
        distro="any",
        check_titles=(
            "Ensure permissions on /etc/shadow are configured",
            "Ensure access to /etc/shadow is configured",
        ),
        document=_BOTH_DOCS,
        description="/etc/shadow loosened to 644 (world-readable password hashes)",
        commands=("chmod 644 /etc/shadow",),
    ),
    Recipe(
        id="passwd-world-writable",
        distro="any",
        # Same "mode 666 also trips round 3's world-writable scan" reason
        # as ssh-public-host-key-wrong-owner/shells-world-writable above,
        # confirmed empirically.
        check_titles=(
            "Ensure access to /etc/passwd is configured",
            "Ensure permissions on /etc/passwd are configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="/etc/passwd loosened to 666 (world-writable account database)",
        commands=("chmod 666 /etc/passwd",),
    ),
    Recipe(
        id="group-world-writable",
        distro="any",
        check_titles=(
            "Ensure access to /etc/group is configured",
            "Ensure permissions on /etc/group are configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="/etc/group loosened to 666 (world-writable group database)",
        commands=("chmod 666 /etc/group",),
    ),
    Recipe(
        id="gshadow-world-readable",
        distro="any",
        check_titles=(
            "Ensure access to /etc/gshadow is configured",
            "Ensure permissions on /etc/gshadow are configured",
        ),
        document=_BOTH_DOCS,
        description="/etc/gshadow loosened to 644 (world-readable group password hashes)",
        commands=("chmod 644 /etc/gshadow",),
    ),
    Recipe(
        id="sshd-config-world-readable",
        distro="any",
        check_titles=(
            "Ensure access to /etc/ssh/sshd_config is configured",
            "Ensure permissions on /etc/ssh/sshd_config are configured",
        ),
        document=_BOTH_DOCS,
        description="/etc/ssh/sshd_config loosened to 644 (world-readable daemon config)",
        commands=("chmod 644 /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-private-host-key-world-readable",
        distro="any",
        check_titles=(
            "Ensure permissions on SSH private host key files are configured",
            "Ensure access to SSH private host key files is configured",
        ),
        document=_BOTH_DOCS,
        description="SSH private host key (RSA) loosened to 644 (world-readable host private key)",
        commands=("chmod 644 /etc/ssh/ssh_host_rsa_key",),
    ),
    Recipe(
        id="ssh-public-host-key-wrong-owner",
        distro="any",
        # Round 3's full-filesystem world-writable scan also flags this
        # file for the same reason -- mode 666 sets the "other" write bit,
        # exactly what that check looks for -- confirmed empirically; not
        # a second, unrelated gap.
        check_titles=(
            "Ensure permissions on SSH public host key files are configured",
            "Ensure access to SSH public host key files is configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="SSH public host key (RSA) mode loosened past 644",
        commands=("chmod 666 /etc/ssh/ssh_host_rsa_key.pub",),
    ),
    Recipe(
        id="shells-world-writable",
        distro="any",
        # Same reasoning as ssh-public-host-key-wrong-owner above -- mode
        # 666 also trips round 3's world-writable scan, confirmed
        # empirically.
        check_titles=(
            "Ensure access to /etc/shells is configured",
            "Ensure permissions on /etc/shells are configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="/etc/shells loosened to 666 (world-writable allowed-shells list)",
        commands=("chmod 666 /etc/shells",),
    ),
    Recipe(
        id="cron-d-world-writable",
        distro="any",
        # 777 on a *directory* also trips round 3's world-writable scan
        # (it flags both files and directories with the "other" write
        # bit set), confirmed empirically.
        check_titles=(
            "Ensure access to /etc/cron.d is configured",
            "Ensure permissions on /etc/cron.d are configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="/etc/cron.d loosened to 777 (world-writable cron drop-in directory)",
        commands=("chmod 777 /etc/cron.d",),
    ),
    Recipe(
        id="cron-daily-group-writable",
        distro="any",
        check_titles=(
            "Ensure access to /etc/cron.daily is configured",
            "Ensure permissions on /etc/cron.daily are configured",
        ),
        document=_BOTH_DOCS,
        description="/etc/cron.daily loosened to 775 (group-writable cron.daily directory)",
        commands=("chmod 775 /etc/cron.daily",),
    ),
    Recipe(
        id="issue-net-world-writable",
        distro="any",
        check_titles=(
            "Ensure access to /etc/issue.net is configured",
            "Ensure permissions on /etc/issue.net are configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="/etc/issue.net loosened to 666 (world-writable pre-login SSH banner)",
        commands=("chmod 666 /etc/issue.net",),
    ),
    Recipe(
        id="motd-world-writable",
        distro="any",
        check_titles=(
            "Ensure access to /etc/motd is configured",
            "Ensure world writable files and directories are secured",
        ),
        document=_BOTH_DOCS,
        description="/etc/motd loosened to 666 (world-writable message-of-the-day)",
        commands=("chmod 666 /etc/motd",),
    ),
    # --- sshd_config directives (Group D/F of CHECKS). Every misconfig
    # here uses `sed -i` to replace the directive's existing line in place
    # -- confirmed empirically that `sshd -T` resolves the *first*
    # occurrence of a repeated directive, so appending a second line (the
    # naive approach) silently has no effect.
    Recipe(
        id="ssh-permit-root-login",
        distro="any",
        check_titles=("Ensure sshd PermitRootLogin is disabled",),
        document=_BOTH_DOCS,
        description="sshd PermitRootLogin flipped to yes",
        commands=("sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-permit-user-environment",
        distro="any",
        check_titles=("Ensure sshd PermitUserEnvironment is disabled",),
        document=_BOTH_DOCS,
        description="sshd PermitUserEnvironment flipped to yes",
        commands=("sed -i 's/^PermitUserEnvironment no/PermitUserEnvironment yes/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-ignore-rhosts",
        distro="any",
        check_titles=("Ensure sshd IgnoreRhosts is enabled",),
        document=_BOTH_DOCS,
        description="sshd IgnoreRhosts flipped to no",
        commands=("sed -i 's/^IgnoreRhosts yes/IgnoreRhosts no/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-login-grace-time",
        distro="any",
        check_titles=("Ensure sshd LoginGraceTime is configured",),
        document=_BOTH_DOCS,
        description="sshd LoginGraceTime set to 0 (disables the grace-time limit entirely)",
        commands=("sed -i 's/^LoginGraceTime 30/LoginGraceTime 0/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-max-sessions",
        distro="any",
        check_titles=(
            "Ensure sshd MaxSessions is configured",
            "Ensure SSH MaxSessions is set to 10 or less",
            "Ensure SSH MaxSessions is limited",
        ),
        document=_BOTH_DOCS,
        description="sshd MaxSessions raised to 50",
        commands=("sed -i 's/^MaxSessions 10/MaxSessions 50/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-log-level",
        distro="any",
        check_titles=(
            "Ensure sshd LogLevel is configured",
            "Ensure SSH LogLevel is appropriate",
        ),
        document=_BOTH_DOCS,
        description="sshd LogLevel dropped to QUIET (neither INFO nor VERBOSE)",
        commands=("sed -i 's/^LogLevel VERBOSE/LogLevel QUIET/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-use-pam",
        distro="any",
        check_titles=(
            "Ensure sshd UsePAM is enabled",
            "Ensure SSH PAM is enabled",
        ),
        document=_BOTH_DOCS,
        description="sshd UsePAM flipped to no",
        commands=("sed -i 's/^UsePAM yes/UsePAM no/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-disable-forwarding",
        distro="any",
        check_titles=("Ensure sshd DisableForwarding is enabled",),
        document=_BOTH_DOCS,
        description="sshd DisableForwarding flipped to no (TCP/agent/X11 forwarding re-enabled)",
        commands=("sed -i 's/^DisableForwarding yes/DisableForwarding no/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-weak-ciphers",
        distro="any",
        check_titles=(
            "Ensure sshd Ciphers are configured",
            "Ensure only strong ciphers are used",
            "Ensure only strong Ciphers are used",
        ),
        document=_BOTH_DOCS,
        description="sshd Ciphers replaced with a CBC-mode (weak) cipher list",
        commands=("sed -i 's/^Ciphers.*/Ciphers aes256-cbc,aes128-cbc/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-weak-macs",
        distro="any",
        check_titles=("Ensure sshd MACs are configured",),
        document=_BOTH_DOCS,
        description="sshd MACs replaced with hmac-md5/hmac-sha1-96 (weak)",
        commands=("sed -i 's/^MACs.*/MACs hmac-md5,hmac-sha1-96/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-weak-kex",
        distro="any",
        check_titles=(
            "Ensure sshd KexAlgorithms is configured",
            "Ensure only strong Key Exchange algorithms are used",
        ),
        document=_BOTH_DOCS,
        description="sshd KexAlgorithms replaced with diffie-hellman-group14-sha1 (weak)",
        commands=("sed -i 's/^KexAlgorithms.*/KexAlgorithms diffie-hellman-group14-sha1/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-max-startups",
        distro="any",
        check_titles=("Ensure sshd MaxStartups is configured",),
        document=_BOTH_DOCS,
        description="sshd MaxStartups loosened to 20:30:100 (full-queue limit above 60)",
        commands=("sed -i 's/^MaxStartups 10:30:60/MaxStartups 20:30:100/' /etc/ssh/sshd_config",),
    ),
    # --- PAM / login.defs / account content (Groups C/F/G plus Group B's
    # account-content checks) ---
    Recipe(
        id="pam-unix-nullok",
        distro="any",
        check_titles=(
            "Ensure pam_unix does not include nullok",
            "Ensure pam modules do not include nullok",
        ),
        document=_BOTH_DOCS,
        description="nullok re-added to pam_unix.so on common-auth (empty passwords accepted)",
        commands=("sed -i 's/pam_unix\\.so$/pam_unix.so nullok/' /etc/pam.d/common-auth",),
    ),
    Recipe(
        id="pam-unix-use-authtok-removed",
        distro="any",
        check_titles=("Ensure pam_unix includes use_authtok",),
        document=_BOTH_DOCS,
        description="use_authtok removed from pam_unix.so on common-password",
        commands=("sed -i 's/ use_authtok//' /etc/pam.d/common-password",),
    ),
    Recipe(
        id="pam-unix-weak-hashing",
        distro="any",
        check_titles=("Ensure pam_unix includes a strong password hashing algorithm",),
        document=_BOTH_DOCS,
        description="pam_unix.so hashing algorithm downgraded to md5",
        commands=("sed -i 's/obscure \\(yescrypt\\|sha512\\)/obscure md5/' /etc/pam.d/common-password",),
    ),
    Recipe(
        id="pam-unix-remember-added",
        distro="any",
        check_titles=("Ensure pam_unix does not include remember",),
        document=_BOTH_DOCS,
        description="remember=5 added to pam_unix.so on common-password (belongs on pam_pwhistory, not pam_unix)",
        # [a-z0-9_]*, not [a-z0-9]* -- found the hard way running demo.sh
        # with several different seeds: ubuntu's real common-password line
        # reads "pam_unix.so obscure use_authtok ...", and the underscore
        # in "use_authtok" isn't in [a-z0-9], so the old pattern only
        # captured "use" and inserted "remember=5" mid-word, corrupting the
        # line into "obscure use remember=5_authtok ..." -- silently
        # breaking the unrelated "Ensure pam_unix includes use_authtok"
        # check as a second, untracked FAIL. Confirmed empirically against
        # a live container that the corrected pattern leaves use_authtok
        # intact while still inserting remember=5.
        commands=(
            "sed -i 's/\\(pam_unix\\.so obscure [a-z0-9_]*\\)/\\1 remember=5/' /etc/pam.d/common-password",
        ),
    ),
    Recipe(
        id="pam-faillock-disabled",
        distro="any",
        check_titles=("Ensure pam_faillock module is enabled",),
        document=_BOTH_DOCS,
        description="pam_faillock.so removed from common-auth",
        commands=("sed -i '/pam_faillock\\.so/d' /etc/pam.d/common-auth",),
    ),
    Recipe(
        id="pam-pwhistory-disabled",
        distro="any",
        check_titles=("Ensure pam_pwhistory module is enabled",),
        document=_BOTH_DOCS,
        description="pam_pwhistory.so removed from common-password",
        commands=("sed -i '/pam_pwhistory\\.so/d' /etc/pam.d/common-password",),
    ),
    Recipe(
        id="pam-pwhistory-use-authtok-removed",
        distro="any",
        check_titles=("Ensure pam_pwhistory includes use_authtok",),
        document=_BOTH_DOCS,
        description="use_authtok line removed from pwhistory.conf",
        commands=("sed -i '/^use_authtok$/d' /etc/security/pwhistory.conf",),
    ),
    Recipe(
        id="pwquality-enforce-for-root-removed",
        distro="any",
        check_titles=("Ensure password quality is enforced for the root user",),
        document=_BOTH_DOCS,
        description="enforce_for_root removed from pwquality.conf",
        commands=("sed -i '/enforce_for_root/d' /etc/security/pwquality.conf",),
    ),
    Recipe(
        id="pwquality-minlen-too-short",
        distro="any",
        check_titles=(
            "Ensure minimum password length is configured",
            "Ensure password length is configured",
        ),
        document=_BOTH_DOCS,
        description="pwquality.conf minlen dropped to 6 (below the 14 floor)",
        commands=("sed -i 's/minlen = 14/minlen = 6/' /etc/security/pwquality.conf",),
    ),
    Recipe(
        id="pwquality-complexity-relaxed",
        distro="any",
        check_titles=("Ensure password complexity is configured",),
        document=_BOTH_DOCS,
        description="pwquality.conf minclass dropped to 1 (below the 3-class floor)",
        commands=("sed -i 's/minclass = 3/minclass = 1/' /etc/security/pwquality.conf",),
    ),
    Recipe(
        id="pwquality-max-repeat-disabled",
        distro="any",
        check_titles=("Ensure password same consecutive characters is configured",),
        document=_BOTH_DOCS,
        description="pwquality.conf maxrepeat set to 0 (disables the check entirely)",
        commands=("sed -i 's/maxrepeat = 3/maxrepeat = 0/' /etc/security/pwquality.conf",),
    ),
    Recipe(
        id="pwquality-max-sequence-disabled",
        distro="any",
        check_titles=("Ensure password maximum sequential characters is configured",),
        document=_BOTH_DOCS,
        description="pwquality.conf maxsequence set to 0 (disables the check entirely)",
        commands=("sed -i 's/maxsequence = 3/maxsequence = 0/' /etc/security/pwquality.conf",),
    ),
    Recipe(
        id="pwquality-difok-disabled",
        distro="any",
        check_titles=("Ensure password number of changed characters is configured",),
        document=_BOTH_DOCS,
        description="pwquality.conf difok dropped to 0 (below the floor of 2)",
        commands=("sed -i 's/difok = 2/difok = 0/' /etc/security/pwquality.conf",),
    ),
    Recipe(
        id="pwhistory-remember-too-short",
        distro="any",
        check_titles=("Ensure password history remember is configured",),
        document=_BOTH_DOCS,
        description="pwhistory.conf remember dropped to 5 (below the 24 floor)",
        commands=("sed -i 's/remember = 24/remember = 5/' /etc/security/pwhistory.conf",),
    ),
    Recipe(
        id="pwhistory-enforce-for-root-removed",
        distro="any",
        check_titles=("Ensure password history is enforced for the root user",),
        document=_BOTH_DOCS,
        description="enforce_for_root removed from pwhistory.conf",
        commands=("sed -i '/enforce_for_root/d' /etc/security/pwhistory.conf",),
    ),
    Recipe(
        id="default-umask-loosened",
        distro="any",
        check_titles=("Ensure default user umask is configured",),
        document=_BOTH_DOCS,
        description="login.defs UMASK reverted to 022 (not 027-or-stricter)",
        commands=("sed -i 's/^UMASK.*/UMASK\\t022/' /etc/login.defs",),
    ),
    Recipe(
        id="weak-password-hashing-algorithm",
        distro="any",
        check_titles=("Ensure strong password hashing algorithm is configured",),
        document=_BOTH_DOCS,
        description="login.defs ENCRYPT_METHOD downgraded to MD5",
        commands=("sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD MD5/' /etc/login.defs",),
    ),
    Recipe(
        id="extra-uid0-account",
        # Found running demo.sh for real after round 2 added "Ensure
        # no duplicate UIDs exist": a second UID-0 account is unavoidably
        # also a duplicate UID, same story as extra-gid0-group below. Also
        # picked up two pre-existing (round-2-unrelated) latent bugs while
        # verifying this: (1) debian_linux_11's own title for the UID-0
        # control has 3 PDF-extraction-garbled variants in Postgres (page
        # numbers/headers leaked into the title text) that the real Check
        # already lists as aliases but this recipe never did -- would have
        # shown as UNEXPLAINED against a debian container specifically;
        # (2) the original command's GID (1000) and shell
        # (/usr/sbin/nologin) combination now also breaks "Ensure all
        # groups in /etc/passwd exist in /etc/group" (GID 1000 doesn't
        # exist) and "Ensure accounts without a valid login shell are
        # locked" (no matching shadow lock entry) -- fixed by pointing at
        # GID 33 (www-data, always present) and adding a locked shadow
        # entry for the new account.
        distro="any",
        check_titles=(
            "Ensure root is the only UID 0 account",
            "Verify No UID 0 Accounts Exist Other Than root",
            "Configure root and system accounts and environment Page 637 Internal Only - General 5.4.2.1 Ensure root is the only UID 0 account",
            "Configure root and system accounts and environment Page 671  5.4.2.1 Ensure root is the only UID 0 account",
            "Configure root and system accounts and environment Page 677 Internal Only - General 5.4.2.1 Ensure root is the only UID 0 account",
            "Ensure no duplicate UIDs exist",
        ),
        document=_BOTH_DOCS,
        description="a second UID-0 account (evildaemon) added to /etc/passwd",
        commands=(
            "sh -c \"echo 'evildaemon:x:0:33::/nonexistent:/usr/sbin/nologin' >> /etc/passwd\"",
            "sh -c \"echo 'evildaemon:!:19000:0:99999:7:::' >> /etc/shadow\"",
        ),
    ),
    Recipe(
        id="extra-gid0-account",
        distro="any",
        check_titles=(
            "Ensure root is the only GID 0 account",
            # A real login shell (see the comment below on why it can't be
            # nologin) now also sweeps this account into round 4's "local
            # interactive user" scope, and its /nonexistent home doesn't
            # exist -- a real, explained consequence of the same command,
            # confirmed empirically, not a separate bug.
            "Ensure local interactive user home directories are configured",
        ),
        document=_BOTH_DOCS,
        description="a second GID-0 primary group account (evilgroupuser) added to /etc/passwd",
        # Shell is /bin/bash (a valid login shell), not /usr/sbin/nologin --
        # found the hard way that nologin here silently also broke "Ensure
        # accounts without a valid login shell are locked" (no matching
        # shadow lock entry for the new account); UID 1001 is above
        # UID_MIN so a valid shell doesn't trip the separate
        # system-accounts-shell check either, unlike extra-uid0-account's
        # UID-0 account above (which stays nologin + gets a locked shadow
        # entry instead, since UID 0 *is* in scope for that check).
        commands=("sh -c \"echo 'evilgroupuser:x:1001:0::/nonexistent:/bin/bash' >> /etc/passwd\"",),
    ),
    Recipe(
        id="extra-gid0-group",
        distro="any",
        # A second group sharing GID 0 is unavoidably *also* a duplicate
        # GID -- found the hard way running demo.sh for real after
        # round 2 added "Ensure no duplicate GIDs exist": this recipe
        # produced a genuine second FAIL every time it landed on the same
        # container as no compensating recipe, showing up as UNEXPLAINED
        # rather than "today's story". Both titles are real, both are
        # genuinely broken by this one command -- not a title-alias
        # situation like the ssh-max-sessions recipe below, an actually
        # different control that happens to share the same root cause.
        #
        # Found a third the same way after round 4's dot-files check: GID
        # 0's name resolution (facts's `_gid_to_group_name`, one name per
        # GID) picks whichever group *last* in /etc/group claims GID 0 --
        # "evilgroup", appended after "root" -- so root's own real,
        # unmodified, correctly-root-owned dotfiles then compare against
        # the wrong expected group name and FAIL. Not a bug in the dot-
        # files check: a real audit script resolving a GID to a name (e.g.
        # `getent group 0`) hits the exact same ambiguity once two groups
        # share GID 0 -- this recipe genuinely does make root's own group
        # ownership ambiguous, not just root-group's count.
        check_titles=(
            "Ensure group root is the only GID 0 group",
            "Ensure no duplicate GIDs exist",
            "Ensure local interactive user dot files access is configured",
        ),
        document=_BOTH_DOCS,
        description="a second group (evilgroup) added to /etc/group with GID 0",
        commands=("sh -c \"echo 'evilgroup:x:0:' >> /etc/group\"",),
    ),
    Recipe(
        id="empty-shadow-password-field",
        distro="any",
        check_titles=(
            "Ensure /etc/shadow password fields are not empty",
            "Ensure password fields are not empty",
            "Ensure Password Fields are Not Empty",
        ),
        document=_BOTH_DOCS,
        description="an account (baduser) added to /etc/shadow with an empty password field",
        commands=("sh -c \"echo 'baduser::19000:0:99999:7:::' >> /etc/shadow\"",),
    ),
    Recipe(
        id="unshadowed-passwd-account",
        distro="any",
        check_titles=("Ensure accounts in /etc/passwd use shadowed passwords",),
        document=_BOTH_DOCS,
        description="an account (legacyuser) added to /etc/passwd with a password hash in field 2 instead of 'x'",
        # Primary group is 33 (www-data), not the original 1002 -- same
        # "Ensure all groups in /etc/passwd exist in /etc/group" collateral
        # bug fixed elsewhere in this file (1002 doesn't exist in
        # /etc/group). Shell is /bin/bash, not /bin/false -- /bin/false
        # isn't in /etc/shells and silently also broke "Ensure accounts
        # without a valid login shell are locked" (no matching shadow lock
        # entry); UID 1002 is above UID_MIN, so a real shell doesn't
        # introduce any new interaction, and is arguably more realistic
        # for a genuinely legacy, still-logged-into account anyway. The
        # real shell now also sweeps this account into round 4's "local
        # interactive user" scope -- given a real, compliant home
        # directory (owned by legacyuser, mode 750) instead of a
        # /nonexistent-style path, so it doesn't also trip "Ensure local
        # interactive user home directories are configured" as an
        # unrelated second FAIL; confirmed empirically.
        commands=(
            "mkdir -p /home/legacyuser && chown 1002:33 /home/legacyuser && chmod 750 /home/legacyuser && "
            "sh -c \"echo 'legacyuser:"
            "\\$1\\$deadbeef\\$notarealhash:1002:33::/home/legacyuser:/bin/bash' >> /etc/passwd\"",
        ),
    ),
    # --- Round 2 additions (Groups L/Q): sshd_config directives + passwd/
    # group consistency. All verified individually against a live container
    # to break exactly the one named title and nothing else -- e.g. the
    # first attempt at a duplicate-UID recipe reused www-data's real UID
    # (33) with an /usr/sbin/nologin shell, which also silently flipped
    # "Ensure accounts without a valid login shell are locked" (no matching
    # locked shadow entry for the new name); switching to two brand-new
    # fake accounts sharing a UID/GID neither above nor below UID_MIN's
    # boundary in a way that trips the system-account-shell check (1500,
    # comfortably above UID_MIN) avoided every such interaction.
    Recipe(
        id="ssh-max-auth-tries",
        distro="any",
        check_titles=("Ensure sshd MaxAuthTries is configured",),
        document=_BOTH_DOCS,
        description="sshd MaxAuthTries raised to 20 (above the 4-or-less ceiling)",
        commands=("sed -i 's/^MaxAuthTries 4/MaxAuthTries 20/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-client-alive-disabled",
        distro="any",
        check_titles=("Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",),
        document=_BOTH_DOCS,
        description="sshd ClientAliveInterval dropped to 0 (disables the idle-session timeout)",
        commands=("sed -i 's/^ClientAliveInterval 300/ClientAliveInterval 0/' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-banner-disabled",
        distro="any",
        check_titles=("Ensure sshd Banner is configured",),
        document=_BOTH_DOCS,
        description="sshd Banner set to the special value 'none' (disables the pre-login banner)",
        commands=("sed -i 's|^Banner /etc/issue.net|Banner none|' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="ssh-access-unrestricted",
        distro="any",
        check_titles=("Ensure sshd access is configured",),
        document=_BOTH_DOCS,
        description="sshd AllowGroups directive removed (no Allow/Deny Users/Groups restriction left)",
        commands=("sed -i '/^AllowGroups sshusers/d' /etc/ssh/sshd_config",),
    ),
    Recipe(
        id="password-expiration-disabled",
        distro="any",
        check_titles=("Ensure password expiration is configured",),
        document=_BOTH_DOCS,
        description="login.defs PASS_MAX_DAYS raised to 99999 (effectively no expiration)",
        commands=("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t99999/' /etc/login.defs",),
    ),
    Recipe(
        id="duplicate-uid",
        distro="any",
        check_titles=("Ensure no duplicate UIDs exist",),
        document=_BOTH_DOCS,
        description="two new accounts (fakedupuid1/2) added to /etc/passwd sharing UID 1500",
        # Primary group is 33 (www-data), not another fabricated id -- an
        # earlier version used group 1500 too, which only happened to exist
        # when the (independent, not-always-drawn) duplicate-gid recipe was
        # also picked for the same container this run, otherwise silently
        # broke "Ensure all groups in /etc/passwd exist in /etc/group" as
        # an unrelated second FAIL. www-data's GID is guaranteed present on
        # both hardened base images (confirmed empirically) and using it as
        # a *referenced* primary group here doesn't itself create a
        # duplicate /etc/group entry (only /etc/group's own GID column
        # feeds that check).
        #
        # Shell is /usr/sbin/nologin (not /bin/bash, unlike an earlier
        # version) with a locked shadow entry, not a bare /nonexistent
        # home + real shell: a real shell in /etc/shells now sweeps an
        # account into round 4's "local interactive user" definition,
        # which would silently fail "Ensure local interactive user home
        # directories are configured" against a /nonexistent home (a
        # second, unrelated FAIL neither this recipe nor its check_titles
        # mention) -- same class of shared-UID gotcha this recipe's own
        # comment already documents for the primary-group choice above.
        # nologin instead requires a locked shadow entry to avoid tripping
        # "Ensure accounts without a valid login shell are locked"
        # instead -- confirmed empirically against a live container that
        # this combination trips only "Ensure no duplicate UIDs exist".
        commands=(
            "printf 'fakedupuid1:x:1500:33::/nonexistent:/usr/sbin/nologin\\n"
            "fakedupuid2:x:1500:33::/nonexistent:/usr/sbin/nologin\\n' >> /etc/passwd && "
            "printf 'fakedupuid1:!:19000:0:99999:7:::\\n"
            "fakedupuid2:!:19000:0:99999:7:::\\n' >> /etc/shadow",
        ),
    ),
    Recipe(
        id="duplicate-gid",
        distro="any",
        check_titles=("Ensure no duplicate GIDs exist",),
        document=_BOTH_DOCS,
        description="two new groups (fakedupgid1/2) added to /etc/group sharing GID 1500",
        commands=("printf 'fakedupgid1:x:1500:\\nfakedupgid2:x:1500:\\n' >> /etc/group",),
    ),
    Recipe(
        id="shadow-group-not-empty",
        distro="any",
        check_titles=("Ensure shadow group is empty",),
        document=_BOTH_DOCS,
        description="root added as a member of the shadow group in /etc/group",
        commands=("sed -i 's/^shadow:x:42:$/shadow:x:42:root/' /etc/group",),
    ),
]

assert len({r.id for r in RECIPES}) == len(RECIPES), "Recipe ids must be unique"
