# ========================
# recon system
# ========================

export RECON_DATA="/opt/recon/data"
export RECON_DB="$RECON_DATA/recon.db"
# db.py reads RECON_DB_PATH (preferred) for DB location
export RECON_DB_PATH="$RECON_DB"
export RECON_APP="/opt/recon/recon.py"

recon-init() {
  mkdir -p "$RECON_DATA"

  python3 "$RECON_APP" init

  echo "[+] recon initialized"
  echo "[+] db: $RECON_DB"
  echo "[*] file outputs (logs, exports): cs <name> first (or CASE_LOOSE=1)"
}

net-scan() {
  if [[ $# -lt 1 ]]; then
    echo "usage: net-scan <cidr>"
    return 1
  fi

  python3 "$RECON_APP" net-scan "$1"
}

net-view() {
  python3 "$RECON_APP" net-view
}
