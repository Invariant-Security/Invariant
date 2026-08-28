# Ubuntu 24.04 -- /etc/shadow world-readable on purpose (fails control
# 7.1.5, "Ensure access to /etc/shadow is configured"). sshd is correct.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

RUN echo "PermitRootLogin no" >> /etc/ssh/sshd_config \
    && echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config \
    && echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config \
    && echo "LoginGraceTime 30" >> /etc/ssh/sshd_config \
    && chmod 644 /etc/shadow

# infra/docker-compose.yml tmpfs-mounts /home (checks-backlog.md Group C's
# partition family) -- that shadows this image's own baked-in /home/ubuntu
# (ubuntu:24.04 ships a real "ubuntu" interactive user, ownership/mode
# 750 ubuntu:ubuntu, confirmed empirically) with an empty directory at
# container start, which would otherwise turn "Ensure local interactive
# user home directories are configured" (external_id 7.2.9) from PASS to
# FAIL. Recreated at container start (a build-time RUN can't reach past
# the mount, which only exists once the container runs), same
# mode/ownership the base image itself uses.
CMD ["sh", "-c", "mkdir -p /home/ubuntu && chown ubuntu:ubuntu /home/ubuntu && chmod 750 /home/ubuntu && exec sleep infinity"]
