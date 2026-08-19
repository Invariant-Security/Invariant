# Ubuntu 24.04 -- /etc/shadow world-readable on purpose (fails control
# 7.1.5, "Ensure access to /etc/shadow is configured"). sshd is correct.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

RUN echo "PermitRootLogin no" >> /etc/ssh/sshd_config \
    && chmod 644 /etc/shadow

CMD ["sleep", "infinity"]
