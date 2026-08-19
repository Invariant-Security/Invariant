# Debian 11 -- clean baseline for the bxsec demo. Should PASS both
# assessed controls (5.1.20 sshd PermitRootLogin, 7.1.5 /etc/shadow perms).
FROM debian:11

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

RUN echo "PermitRootLogin no" >> /etc/ssh/sshd_config \
    && chmod 640 /etc/shadow \
    && chown root:shadow /etc/shadow

CMD ["sleep", "infinity"]
