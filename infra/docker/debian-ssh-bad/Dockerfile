# Debian 12 -- SSH root login enabled on purpose (fails control 5.1.20,
# "Ensure sshd PermitRootLogin is disabled"). /etc/shadow perms are correct.
FROM debian:12

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config \
    && chmod 640 /etc/shadow \
    && chown root:shadow /etc/shadow

CMD ["sleep", "infinity"]
