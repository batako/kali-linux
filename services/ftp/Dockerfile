FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        vsftpd && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ftpuser -s /bin/bash ftpuser && \
    echo "ftpuser:ftpuser" | chpasswd && \
    mkdir -p /var/run/vsftpd/empty && \
    mkdir -p /srv/ftp/anonymous/upload /srv/ftp/local && \
    chown -R ftp:nogroup /srv/ftp/anonymous && \
    chmod 0555 /srv/ftp/anonymous && \
    chmod 0777 /srv/ftp/anonymous/upload && \
    chown -R ftpuser:ftpuser /srv/ftp/local

COPY services/ftp/vsftpd.conf /etc/vsftpd.conf
COPY services/ftp/welcome.txt /srv/ftp/anonymous/README.txt
COPY services/ftp/auth-note.txt /srv/ftp/local/auth-note.txt

EXPOSE 21 21100-21110

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
