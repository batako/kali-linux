FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /var/run/sshd && \
    useradd -m -s /bin/bash kali && \
    echo "kali:kali" | chpasswd && \
    useradd -m -s /bin/bash testuser && \
    echo "testuser:testpass" | chpasswd && \
    echo "root:root" | chpasswd

COPY services/ssh/sshd_config /etc/ssh/sshd_config
COPY services/ssh/banner.txt /etc/issue.net

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
