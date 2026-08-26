# syntax=docker/dockerfile:1
#
# Ubuntu 20.04 -- hardened base image for quickdemo.sh's live-demo
# containers (invariant-demo-debian-hardened's sibling; invariant-demo-
# ubuntu-1/2 are this same image with a couple of misconfigs re-applied on
# top by scripts/quickdemo/apply_misconfigs.py at container start, not at
# build time). Same base image as infra/docker/ubuntu-baseline
# (ubuntu:20.04) -- not touched, not built from, entirely separate compose
# file/image name so it never collides with the 6 dev/test containers
# infra/docker-compose.yml and tests/assessment/ depend on.
#
# Goal: PASS every check in the "demo-eligible" subset documented in
# docs/architecture/checks.md and scripts/quickdemo/misconfig_catalog.py --
# the file-permission/ownership, sshd_config, PAM/login.defs/account-content
# checks that are pure config, plus (round 2 addition) a handful of real
# packages (ufw/sudo/auditd/aide) whose entire point IS package presence --
# there's no "pure config" way to pass a package-presence check. None of
# these 4 start a service (no systemd in this container anyway); they're
# installed purely so `installed_packages` reflects them. Every other CHECK
# in src/invariant/assessment/__init__.py fails here the same structural
# way it fails on the 6 dev/test containers (no cron/libpam-pwquality
# installed, no real auditd rules configured, etc.) -- see checks.md for
# the documented list.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server ufw sudo auditd audispd-plugins aide aide-common \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

# --- sshd_config: same demo-eligible sshd directives as the Debian image,
# same values -- see that Dockerfile's comment for why each value was
# chosen; confirmed to apply identically on ubuntu:20.04's older
# OpenSSH_8.2p1 (DisableForwarding included, since Debian/Ubuntu both
# backport it ahead of upstream OpenSSH 8.7 -- confirmed via `sshd -T`). The
# last 4 lines are round 2's Group L additions -- see the Debian
# Dockerfile's comment for why PermitEmptyPasswords/HostbasedAuthentication/
# GSSAPIAuthentication need no directive here.
RUN cat >> /etc/ssh/sshd_config <<'EOF'
PermitRootLogin no
PermitUserEnvironment no
IgnoreRhosts yes
LoginGraceTime 30
MaxSessions 10
LogLevel VERBOSE
UsePAM yes
DisableForwarding yes
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
MaxStartups 10:30:60
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 3
Banner /etc/issue.net
AllowGroups sshusers
EOF

# --- file permissions/ownership: the 15 demo-eligible Group A/D checks.
# /etc/passwd-, /etc/group-, /etc/gshadow-, /etc/shadow-, /etc/motd don't
# ship on a bare ubuntu:20.04 image at all (confirmed empirically, unlike
# debian:11 which already has the first three) -- `touch` creates them
# without clobbering content if a future base image does ship them.
RUN touch /etc/passwd- /etc/group- /etc/gshadow- /etc/shadow- /etc/motd \
    && chmod 644 /etc/issue /etc/issue.net /etc/passwd /etc/passwd- /etc/group /etc/group- /etc/shells /etc/motd \
    && chown root:root /etc/issue /etc/issue.net /etc/passwd /etc/passwd- /etc/group /etc/group- /etc/shells /etc/motd \
    && chmod 640 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- \
    && chown root:shadow /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- \
    && chmod 600 /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key \
    && chmod 644 /etc/ssh/ssh_host_*_key.pub \
    && chown root:root /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
    && chmod 700 /etc/cron.d /etc/cron.daily \
    && chown root:root /etc/cron.d /etc/cron.daily

# --- PAM (common-auth/common-account/common-password) + login.defs: same
# pam_unix/pam_faillock/pam_pwhistory family as the Debian image. Default
# common-password here uses "sha512" instead of Debian 11's "yescrypt" --
# matches _evaluate_pam_unix_strong_password_hashing's own documented
# ubuntu_linux_20_04 special case (sha512 only, yescrypt not accepted).
RUN sed -i 's/pam_unix\.so nullok/pam_unix.so/' /etc/pam.d/common-auth \
    && echo 'auth        required            pam_faillock.so' >> /etc/pam.d/common-auth \
    && echo 'account     required            pam_faillock.so' >> /etc/pam.d/common-account \
    && sed -i 's/pam_unix\.so obscure sha512/pam_unix.so obscure sha512 use_authtok/' /etc/pam.d/common-password \
    && echo 'password    requisite           pam_pwhistory.so' >> /etc/pam.d/common-password \
    && sed -i 's/^UMASK\s.*/UMASK\t\t027/' /etc/login.defs \
    && sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs \
    && sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs

# --- sudo (round 2 Group L/N/P additions): see the Debian Dockerfile's
# comment -- same "Ensure sudo commands use pty" scope limitation.
RUN echo 'Defaults        use_pty' >> /etc/sudoers

# pwquality.conf/pwhistory.conf aren't shipped without libpam-pwquality
# (not installed -- see above), but the CIS controls that grep them (Group
# G) are pure text-file checks independent of whether the enforcing module
# is actually loaded, so writing them by hand is a legitimate config-only
# demo of "what compliant values look like", same as every other file here.
RUN cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
maxsequence = 3
difok = 2
enforce_for_root
EOF
RUN cat > /etc/security/pwhistory.conf <<'EOF'
remember = 24
enforce_for_root
use_authtok
EOF

CMD ["sleep", "infinity"]
