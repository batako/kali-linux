FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        samba && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/samba/public /srv/samba/private /var/run/samba && \
    useradd -M -s /usr/sbin/nologin smbuser && \
    chown -R nobody:nogroup /srv/samba/public && \
    chmod 0777 /srv/samba/public && \
    chown -R smbuser:smbuser /srv/samba/private && \
    chmod 0770 /srv/samba/private

COPY services/smb/smb.conf /etc/samba/smb.conf
COPY services/smb/public-readme.txt /srv/samba/public/README.txt
COPY services/smb/private-readme.txt /srv/samba/private/README.txt
COPY services/smb/entrypoint.sh /usr/local/bin/smb-entrypoint.sh

RUN chmod +x /usr/local/bin/smb-entrypoint.sh

EXPOSE 139 445

ENTRYPOINT ["/usr/local/bin/smb-entrypoint.sh"]
