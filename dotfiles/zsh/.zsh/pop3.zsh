# ========================
# POP3 client (recon creds + cl)
# ========================

_pop3-default-port() {
  local ip="$1"
  if [[ -n "$ip" && -n "${RECON_APP:-}" ]]; then
    local p
    p="$(RECON_APP="$RECON_APP" python3 -c "
import os, sys
sys.path.insert(0, os.path.dirname(os.environ['RECON_APP']))
from db import fetch_merged_open_ports
ip = sys.argv[1]
for row in fetch_merged_open_ports(ip):
    port = int(row[0])
    svc = (row[3] or '').lower()
    if port in (110, 995) or 'pop3' in svc:
        print(port)
        break
" "$ip" 2>/dev/null)" || true
    [[ -n "$p" ]] && { echo "$p"; return 0 }
  fi
  echo 110
}

_pop3-local-user() {
  local user="$1"
  [[ "$user" == *@* ]] && user="${user%%@*}"
  echo "$user"
}

_pop3-log-path() {
  local host="$1" user="$2"
  local logs ts
  logs="$(case-logs-dir 2>/dev/null)" || return 1
  ts="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$logs"
  echo "$logs/pop3_${host}_${user}_${ts}.log"
}

_pop3-client-py() {
  echo "${ZDOTDIR:-$HOME/.zsh}/pop3_client.py"
}

_pop3-dump-dir() {
  local user="$1"
  local base
  base="$(case-exports-dir 2>/dev/null)" || base="."
  echo "${base}/pop3_${user}"
}

_pop3-run-client() {
  local ip="$1" port="$2" user="$3" pass="${4:-${POP3_PASS:-}}" interactive="${5:-1}"
  shift 5
  local -a cmds=("$@")
  local py="$(_pop3-client-py)"

  [[ -z "$pass" ]] && {
    echo "[-] pop3: empty password" >&2
    return 1
  }
  [[ -f "$py" ]] || {
    echo "[-] pop3 client not found: $py" >&2
    return 1
  }

  POP3_HOST="$ip" \
  POP3_PORT="$port" \
  POP3_USER="$(_pop3-local-user "$user")" \
  POP3_PASS="$pass" \
  POP3_INTERACTIVE="$interactive" \
  POP3_DUMP_DIR="${POP3_DUMP_DIR:-}" \
  POP3_CMDS="$(printf '%s\n' "${cmds[@]}")" \
  python3 "$py"
}

_pop3-help() {
  echo "usage: pop3 [-l] [-p port] [user] [ip]"
  echo "       pop3-list [-p port] [user] [ip]"
  echo "       pop3-get <user> <msg#> [ip]"
  echo "       pop3-dump [-o dir] [-p port] [user] [ip]"
  echo "  alias: p3 / p3l / p3g / p3d"
  echo "  bulk login: hydrapop3 -L users.txt -P passes.txt"
  echo "  uses creds-list + \$IP when ip omitted"
  echo "  -l / --log   session log → cases/.../logs/pop3_*"
  echo "  -p port      default: open 110/tcp from recon.db, else 110"
  echo "examples:"
  echo "  creds-add seina <pass>"
  echo "  pop3 seina              # login + interactive (LIST, RETR, ...)"
  echo "  pop3-list seina        # LIST + STAT"
  echo "  pop3-get seina 1       # retrieve message 1"
  echo "  pop3-dump seina        # LIST + RETR all → exports/pop3_seina/"
}

pop3-login() {
  local log=false port="" ip="" user="" pass=""
  local -a pos=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      -p)
        port="$2"
        shift 2
        ;;
      -h|--help)
        _pop3-help
        return 0
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        _pop3-help >&2
        return 1
        ;;
      *)
        pos+=("$1")
        shift
        ;;
    esac
  done

  _recon-parse-user-ip "${pos[@]}" || {
    _pop3-help >&2
    return 1
  }
  ip="$_RECON_IP"
  user="$_RECON_USER"
  [[ -z "$port" ]] && port="$(_pop3-default-port "$ip")"

  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip" 0)" || return 1
  fi

  if ! pass="$(_recon-creds-for-user "$ip" "$user")"; then
    echo "[-] no saved creds for ${user}@${ip} (creds-add ${user} <pass>)" >&2
    return 1
  fi
  [[ -z "$pass" ]] && {
    echo "[-] empty password in db for ${user}@${ip}" >&2
    return 1
  }

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1
  echo "[+] pop3: ${user}@${ip}:${port}" >&2

  if $log; then
    local logfile zdot py
    logfile="$(_pop3-log-path "$ip" "$user")" || return 1
    zdot="${ZDOTDIR:-$HOME/.zsh}"
    py="$(_pop3-client-py)"
    echo "[+] logging: $logfile" >&2
    POP3_PASS="$pass" script -q -f "$logfile" -c \
      "zsh -fc 'source ${(q)zdot}/pop3.zsh; POP3_PASS=\"\$POP3_PASS\" _pop3-run-client ${(q)ip} ${port} ${(q)user} \"\$POP3_PASS\" 1'"
    echo "[+] session log saved: $logfile"
    return $?
  fi

  _pop3-run-client "$ip" "$port" "$user" "$pass" 1
}

pop3-list() {
  local port="" ip="" user="" pass=""
  local -a pos=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p)
        port="$2"
        shift 2
        ;;
      -h|--help)
        _pop3-help
        return 0
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        pos+=("$1")
        shift
        ;;
    esac
  done

  _recon-parse-user-ip "${pos[@]}" || {
    _pop3-help >&2
    return 1
  }
  ip="$_RECON_IP"
  user="$_RECON_USER"
  [[ -z "$port" ]] && port="$(_pop3-default-port "$ip")"
  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip" 0)" || return 1
  fi
  pass="$(_recon-creds-for-user "$ip" "$user")" || {
    echo "[-] no saved creds for ${user}@${ip}" >&2
    return 1
  }

  echo "[+] pop3-list: ${user}@${ip}:${port}" >&2
  _pop3-run-client "$ip" "$port" "$user" "$pass" 0 LIST STAT
}

pop3-get() {
  local msg="" port="" ip="" user="" pass=""
  local -a pos=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p)
        port="$2"
        shift 2
        ;;
      -h|--help)
        _pop3-help
        return 0
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        pos+=("$1")
        shift
        ;;
    esac
  done

  if (( ${#pos[@]} < 2 )); then
    echo "usage: pop3-get [-p port] <user> <msg#> [ip]" >&2
    return 1
  fi

  if [[ "${pos[-1]}" =~ $(_recon-ip-re) ]]; then
    ip="${pos[-1]}"
    pos=("${pos[@]:0:$(( ${#pos[@]} - 1 ))}")
  fi

  user="${pos[1]}"
  msg="${pos[2]}"

  if [[ ! "$msg" =~ '^[0-9]+$' ]]; then
    echo "usage: pop3-get [-p port] <user> <msg#> [ip]" >&2
    return 1
  fi

  [[ -z "$ip" ]] && ip="$(_recon-ip-default 2>/dev/null)" || {
    echo "[-] no target ip — target-set <ip> first" >&2
    return 1
  }
  [[ -z "$port" ]] && port="$(_pop3-default-port "$ip")"

  pass="$(_recon-creds-for-user "$ip" "$user")" || {
    echo "[-] no saved creds for ${user}@${ip}" >&2
    return 1
  }

  echo "[+] pop3-get: ${user}@${ip}:${port} msg=${msg}" >&2
  _pop3-run-client "$ip" "$port" "$user" "$pass" 0 "RETR ${msg}"
}

pop3-dump() {
  local port="" ip="" user="" pass="" outdir=""
  local -a pos=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p)
        port="$2"
        shift 2
        ;;
      -o)
        outdir="$2"
        shift 2
        ;;
      -h|--help)
        _pop3-help
        return 0
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        pos+=("$1")
        shift
        ;;
    esac
  done

  _recon-parse-user-ip "${pos[@]}" || {
    echo "usage: pop3-dump [-o dir] [-p port] [user] [ip]" >&2
    return 1
  }
  ip="$_RECON_IP"
  user="$_RECON_USER"
  [[ -z "$port" ]] && port="$(_pop3-default-port "$ip")"

  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip" 0)" || return 1
  fi

  pass="$(_recon-creds-for-user "$ip" "$user")" || {
    echo "[-] no saved creds for ${user}@${ip}" >&2
    return 1
  }

  [[ -z "$outdir" ]] && outdir="$(_pop3-dump-dir "$user")"
  mkdir -p "$outdir" || return 1

  echo "[+] pop3-dump: ${user}@${ip}:${port} → ${outdir}" >&2
  POP3_DUMP_DIR="$outdir" _pop3-run-client "$ip" "$port" "$user" "$pass" 0
}

pop3() {
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _pop3-help
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null
  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  if _recon-parse-user-ip "${args[@]}" 2>/dev/null; then
    if [[ -n "$_RECON_IP" || -n "$_RECON_USER" ]]; then
      pop3-login "${args[@]}"
      return $?
    fi
  fi

  if [[ ${#args[@]} -eq 0 ]] && [[ -n "${IP:-}" ]] && _recon-has-creds "$IP"; then
    pop3-login "${args[@]}"
    return $?
  fi

  _pop3-help >&2
  return 1
}

alias p3='pop3'
alias p3l='pop3-list'
alias p3g='pop3-get'
alias p3d='pop3-dump'
