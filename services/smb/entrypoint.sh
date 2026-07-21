#!/bin/sh
set -eu

(echo "smbpass"; echo "smbpass") | smbpasswd -a -s smbuser

exec /usr/sbin/smbd --foreground --no-process-group
