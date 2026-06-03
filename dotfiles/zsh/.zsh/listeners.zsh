# ========================
# listener
# ========================

_listen-log-path() {
  local port="$1"
  local logs
  logs="$(case-logs-dir)" || return 1
  local ip="${IP:-notarget}"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$logs"
  echo "$logs/revshell_${ip}_${port}_${ts}.log"
}

listen() {
  local log=false
  local port="4444"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      -h|--help)
        echo "usage: listen [-l] [port]"
        echo "  start netcat listener (default: 4444)"
        echo "  -l  record to cases/<name>/logs/ (requires cs <name>, or CASE_LOOSE=1)"
        return 0
        ;;
      *)
        port="$1"
        shift
        ;;
    esac
  done

  echo "[*] listening on $port"

  if $log; then
    local logfile
    logfile="$(_listen-log-path "$port")"
    echo "[+] logging: $logfile"
    script -q -f "$logfile" -c "nc -lvnp $port"
    echo "[+] session log saved: $logfile"
  else
    nc -lvnp "$port"
  fi
}

_listen() {
  _arguments \
    '-l[record session log]' \
    '1:port:(4444 5555 6666)'
}

compdef _listen listen
