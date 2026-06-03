# ========================
# recon system
# ========================

export RECON_HOME="/workspace/recon"
export RECON_DB="$RECON_HOME/recon.db"
# db.py reads RECON_DB_PATH (preferred) for DB location
export RECON_DB_PATH="$RECON_DB"
export RECON_APP="/opt/recon/recon.py"

target-set() {
  if [[ $# -lt 1 ]]; then
    echo "usage: target-set <ip>"
    return 1
  fi

  export IP="$1"

  echo "[+] target set: $1"
}

target-show() {
  if [[ -n "${IP:-}" ]]; then
    echo "$IP"
    return 0
  fi
  echo "(no target set)"
  return 1
}

target-clear() {
  unset IP
  echo "[+] target cleared"
}

recon-init() {
  mkdir -p "$RECON_HOME/scans"
  mkdir -p "$RECON_HOME/exports"
  mkdir -p "$RECON_HOME/notes"

  python3 "$RECON_APP" init

  echo "[+] recon initialized"
  echo "[+] db: $RECON_DB"
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

host-scan() {
  if [[ $# -lt 2 ]]; then
    echo "usage: host-scan <ip> <quick|full>"
    return 1
  fi

  python3 "$RECON_APP" host-scan "$1" "$2"
}

host-view() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: host-view <ip>"
    return 1
  fi

  python3 "$RECON_APP" host-view "$ip"
}

host-summary() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: host-summary <ip>"
    return 1
  fi

  python3 "$RECON_APP" host-summary "$ip" --json
}

task-view() {
  python3 "$RECON_APP" task-view
}

task-done() {
  if [[ $# -lt 1 ]]; then
    echo "usage: task-done <id>"
    return 1
  fi

  python3 "$RECON_APP" task-done "$1"
}

task-run() {
  if [[ $# -lt 1 ]]; then
    echo "usage: task-run <id>"
    return 1
  fi

  python3 "$RECON_APP" task-run "$1"
}

host-run-next() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: host-run-next <ip>"
    return 1
  fi

  python3 "$RECON_APP" host-run-next "$ip"
}

exec-run() {
  local ip=""
  local cmd_start=1

  local silence=""

  if [[ "${1:-}" == "-s" ]]; then
    silence="-s"
    shift
  fi

  # If first arg looks like an IP, treat it as ip; otherwise fall back to current target.
  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: exec-run [-s] [ip] <command...>"
    return 1
  fi

  python3 "$RECON_APP" exec-run $silence "$ip" "$@"
}

# Short aliases for daily use (same as exec-run / exec-run -s)
x() {
  exec-run "$@"
}

xs() {
  exec-run -s "$@"
}

exec-cache() {
  local ip=""
  local silence=""

  if [[ "${1:-}" == "-s" ]]; then
    silence="-s"
    shift
  fi

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: exec-cache [-s] [ip] <command...>"
    return 1
  fi

  python3 "$RECON_APP" exec-cache $silence "$ip" "$@"
}

# cache-or-run: skip if already done for this ip+command
xc() {
  exec-cache "$@"
}

xcs() {
  exec-cache -s "$@"
}

exec-list() {
  # usage: exec-list [-l] [ip]   default: current target ($IP)
  python3 "$RECON_APP" exec-list "$@"
}

exec-view() {
  if [[ $# -lt 1 ]]; then
    echo "usage: exec-view <exec_id> [--tail N]"
    return 1
  fi
  python3 "$RECON_APP" exec-view "$@"
}

el() {
  exec-list "$@"
}

ev() {
  exec-view "$@"
}

artifact-add() {
  local ip=""
  local kind=""
  local value=""
  local key=""

  # usage: artifact-add [ip] <kind> <value> [key]
  if [[ $# -ge 4 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"; kind="$2"; value="$3"; key="${4:-}"
  else
    ip="${IP:-}"
    kind="$1"; value="$2"; key="${3:-}"
  fi

  if [[ -z "$ip" || -z "$kind" || -z "$value" ]]; then
    echo "usage: artifact-add [ip] <kind> <value> [key]"
    return 1
  fi

  python3 "$RECON_APP" artifact-add "$ip" "$kind" "$value" "$key"
}

creds-add() {
  local ip=""
  local user=""
  local pass=""

  # usage: creds-add [ip] <username> <password>
  if [[ $# -ge 3 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"; user="$2"; pass="$3"
  else
    ip="${IP:-}"
    user="$1"; pass="$2"
  fi

  if [[ -z "$ip" || -z "$user" || -z "$pass" ]]; then
    echo "usage: creds-add [ip] <username> <password>"
    return 1
  fi

  python3 "$RECON_APP" creds-add "$ip" "$user" "$pass"
}

artifact-list() {
  # usage: artifact-list [ip]
  if [[ $# -ge 1 ]]; then
    python3 "$RECON_APP" artifact-list "$1"
  else
    python3 "$RECON_APP" artifact-list
  fi
}

artifact-del() {
  if [[ $# -lt 1 ]]; then
    echo "usage: artifact-del <artifact_id>"
    return 1
  fi
  python3 "$RECON_APP" artifact-del "$1"
}
