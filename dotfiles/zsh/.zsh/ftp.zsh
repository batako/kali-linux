# ========================
# FTP client helpers
# ========================

_ftp-log-host() {
  local a
  for a in "$@"; do
    if [[ "$a" == -* ]]; then
      continue
    fi
    if [[ "$a" == *@* ]]; then
      echo "${a##*@}"
      return 0
    fi
    if [[ "$a" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]] || [[ "$a" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]]; then
      echo "$a"
      return 0
    fi
  done
  echo "${IP:-notarget}"
}

_ftp-log-path() {
  local host="$1"
  local label="${2:-session}"
  local logs
  logs="$(case-logs-dir)" || return 1
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$logs"
  echo "$logs/ftp_${host}_${label}_${ts}.log"
}

_ftp-run-logged() {
  local label="$1"
  shift
  local host logfile

  host="$(_ftp-log-host "$@")"
  logfile="$(_ftp-log-path "$host" "$label")" || return 1

  echo "[+] logging: $logfile"
  script -q -f "$logfile" -c "command ftp ${(q)@}"
  echo "[+] session log saved: $logfile"
}

# Wrap system ftp; pass -l to record the interactive session under cases/<name>/logs/
ftp() {
  local log=false
  local args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      -h|--help)
        echo "usage: ftp [-l] [ftp-options...] [host]"
        echo "  same as /usr/bin/ftp; -l writes a session log (requires cs <name>, or CASE_LOOSE=1)"
        echo "  examples:"
        echo "    ftp -l anonymous@10.10.10.10"
        echo "    ftp -l -A 10.10.10.10"
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  if $log; then
    if [[ ${#args[@]} -eq 0 ]]; then
      echo "usage: ftp [-l] [ftp-options...] [host]" >&2
      return 1
    fi
    _ftp-run-logged session "${args[@]}"
  else
    command ftp "${args[@]}"
  fi
}

# Anonymous FTP (ftpa = ftp -l anonymous@target when -l is set)
ftpa() {
  local log=false
  local target=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      -h|--help)
        echo "usage: ftpa [-l] [ip]"
        echo "  connect as anonymous@host (default host: \$IP)"
        echo "  -l  record to cases/<name>/logs/ (requires cs <name>, or CASE_LOOSE=1)"
        return 0
        ;;
      *)
        target="$1"
        shift
        ;;
    esac
  done

  target="${target:-${IP:-}}"
  if [[ -z "$target" ]]; then
    echo "usage: ftpa [-l] [ip]  (or: target-set <ip> first)"
    return 1
  fi

  if $log; then
    _ftp-run-logged anon "anonymous@${target}"
  else
    command ftp "anonymous@${target}"
  fi
}

_ftpa() {
  _arguments \
    '-l[record session log]' \
    '1:ip:($IP)'
}

compdef _ftpa ftpa
