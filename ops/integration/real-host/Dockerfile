ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        openssh-client \
        openssh-server \
        procps \
        psmisc \
        python3 \
        python3-apt \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash sysadm \
    && mkdir -p /home/sysadm/.ssh /run/sshd /etc/ai-sysadm /var/log/apt \
    && touch /home/sysadm/.ssh/authorized_keys \
    && chown -R sysadm:sysadm /home/sysadm/.ssh \
    && chmod 700 /home/sysadm/.ssh \
    && chmod 600 /home/sysadm/.ssh/authorized_keys \
    && printf '%s\n' 'sysadm ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ai-sysadm-integration \
    && chmod 0440 /etc/sudoers.d/90-ai-sysadm-integration \
    && printf '%s\n' \
        'PubkeyAuthentication yes' \
        'PasswordAuthentication no' \
        'PermitRootLogin no' \
        'StrictModes no' \
        > /etc/ssh/sshd_config.d/90-ai-sysadm-integration.conf \
    && ssh-keygen -A

RUN printf '%s\n' \
        'Listing...' \
        'linux-image-generic/6.8.0.40-security [upgradable from: 6.8.0.31]' \
        'openssl/3.0.13-security [upgradable from: 3.0.12]' \
        'curl/8.5.1 [upgradable from: 8.5.0]' \
        > /etc/ai-sysadm/upgradable-packages.txt \
    && printf '%s\n' \
        'Start-Date: 2026-06-24  00:00:00' \
        'Commandline: apt-get upgrade' \
        'Upgrade: openssl:amd64 (3.0.12, 3.0.13)' \
        'End-Date: 2026-06-24  00:00:01' \
        > /var/log/apt/history.log

COPY ops/integration/real-host/bin/apt /usr/local/bin/apt
COPY ops/integration/real-host/bin/journalctl /usr/local/bin/journalctl
COPY ops/integration/real-host/bin/systemctl /usr/local/bin/systemctl

RUN chmod 0755 /usr/local/bin/apt /usr/local/bin/journalctl /usr/local/bin/systemctl

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
