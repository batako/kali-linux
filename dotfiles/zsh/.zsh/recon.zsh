# ========================
# recon system
# ========================

export RECON_HOME="/workspace/recon"
export RECON_DB="$RECON_HOME/recon.db"
# db.py reads RECON_DB_PATH (preferred) for DB location
export RECON_DB_PATH="$RECON_DB"
export RECON_APP="/opt/recon/recon.py"

_case-target-file() {
  [[ -n "${CASE_HOME:-}" ]] && echo "$CASE_HOME/target"
}

# Load IP from cases/<case>/target into $IP
target-load() {
  local f ip
  f="$(_case-target-file)" || return 1
  [[ -f "$f" ]] || return 1
  ip="$(head -1 "$f" | tr -d '[:space:]')"
  [[ "$ip" =~ $(_recon-ip-re) ]] || return 1
  export IP="$ip"
  return 0
}

# Persist $IP for current case
target-save() {
  local ip="${1:-${IP:-}}"
  local f
  [[ "$ip" =~ $(_recon-ip-re) ]] || return 1
  f="$(_case-target-file)" || return 1
  print -r -- "$ip" >"$f"
  return 0
}

# Resolve target IP: $IP, else cases/<case>/target
target-current() {
  if [[ -n "${IP:-}" ]]; then
    echo "$IP"
    return 0
  fi
  target-load && echo "$IP"
}

_case-on-enter() {
  if (( $+functions[_ftp-shell-reset-case] )); then
    _ftp-shell-reset-case
  fi
  if target-load; then
    echo "[+] target: $IP  ($CASE_HOME/target)"
  fi
  if [[ -f "${CASE_HOME:-}/ftp-shell" ]]; then
    echo "[+] ftp-shell: $CASE_HOME/ftp-shell"
  fi
}

target-set() {
  if [[ $# -lt 1 ]]; then
    echo "usage: target-set <ip>  (alias: ts)"
    echo "  with cs <case>: saved to cases/<case>/target"
    return 1
  fi

  if [[ ! "$1" =~ $(_recon-ip-re) ]]; then
    echo "usage: target-set <ipv4>"
    return 1
  fi

  export IP="$1"

  if [[ -n "${CASE_HOME:-}" ]]; then
    target-save "$1"
    echo "[+] target set: $1  (saved → $CASE_HOME/target)"
  else
    echo "[+] target set: $1  (session only — cs <case> to persist)"
  fi
}

target-show() {
  local f
  if target-current >/dev/null; then
    echo "$IP"
    f="$(_case-target-file 2>/dev/null)"
    [[ -n "$f" && -f "$f" ]] && echo "[*] file: $f"
    return 0
  fi
  echo "(no target — ts <ip> or cs <case> with cases/<case>/target)"
  return 1
}

target-clear() {
  local f
  unset IP
  f="$(_case-target-file 2>/dev/null)"
  [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  echo "[+] target cleared"
}

ts() { target-set "$@" }

recon-init() {
  mkdir -p "$RECON_HOME"

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

_creds-add() {
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
    echo "usage: creds-add | ca [ip] <username> <password>"
    return 1
  fi

  python3 "$RECON_APP" creds-add "$ip" "$user" "$pass"
}

# noglob は関数内では遅い（呼び出し前に zsh が ? / ??? 等を展開する）→ alias で付与
unfunction ca creds-add creds-rm cr 2>/dev/null
setopt aliases
alias creds-add='noglob _creds-add'
alias ca='noglob _creds-add'

creds-list() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: creds-list [ip]"
    return 1
  fi
  python3 "$RECON_APP" creds-list "$ip"
}

# usage: creds-rm [ip] [username]   (no username → all creds for ip)
_creds-rm() {
  local ip="" user=""

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    user="${2:-}"
  elif [[ $# -ge 1 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
  elif [[ $# -ge 1 ]]; then
    ip="${IP:-}"
    user="$1"
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" ]]; then
    echo "usage: creds-rm | cr [ip] [username]"
    echo "  cr                    # delete all creds for \$IP"
    echo "  cr anonymous          # delete one user on \$IP"
    return 1
  fi

  if [[ -n "$user" ]]; then
    python3 "$RECON_APP" creds-rm "$ip" "$user"
  else
    python3 "$RECON_APP" creds-rm "$ip"
  fi
}

alias creds-rm='noglob _creds-rm'
alias cr='noglob _creds-rm'

cl() {
  creds-list "$@"
}

artifact-list() {
  # usage: artifact-list [-l] [ip]   default: current target ($IP)
  python3 "$RECON_APP" artifact-list "$@"
}

al() {
  artifact-list "$@"
}

artifact-del() {
  if [[ $# -lt 1 ]]; then
    echo "usage: artifact-del <artifact_id>"
    return 1
  fi
  python3 "$RECON_APP" artifact-del "$1"
}
