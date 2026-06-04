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

_ftp-connect-creds() {
  local ip="$1" user="$2" pass="$3"
  local logfile="$4"
  shift 4
  local -a extra=("$@")

  # .netrc auto-login keeps an interactive ftp session (heredoc + "prompt" exited immediately)
  local netrc
  netrc="$(mktemp "${TMPDIR:-/tmp}/ftp-netrc.XXXXXX")"
  chmod 600 "$netrc"
  {
    print -r "default login $user password $pass"
    print -r "machine $ip login $user password $pass"
  } >"$netrc"

  local -a cmd=(command ftp)
  (( ${#extra[@]} )) && cmd+=("${extra[@]}")
  cmd+=("$ip")

  if [[ -n "$logfile" ]]; then
    echo "[+] logging: $logfile"
    NETRC="$netrc" script -q -f "$logfile" -c "${(q)cmd}"
    echo "[+] session log saved: $logfile"
  else
    NETRC="$netrc" "${cmd[@]}"
  fi
  rm -f "$netrc"
}

ftp-login() {
  local log=false
  local -a rest=() pos=() a
  local ip="" user="" pass=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      *)
        if [[ "$1" == -* ]]; then
          rest+=("$1")
        else
          pos+=("$1")
        fi
        shift
        ;;
    esac
  done

  _recon-parse-user-ip "${pos[@]}" || {
    echo "usage: ftp [-l] [user] [ip]  (or: target-set <ip> first)" >&2
    return 1
  }
  ip="$_RECON_IP"
  user="$_RECON_USER"

  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip")" || return 1
  fi

  if ! pass="$(_recon-creds-for-user "$ip" "$user")"; then
    echo "[-] no saved creds for ${user}@${ip} (cl / hydraftp / hydrassh first)" >&2
    command ftp "${rest[@]}" "${pos[@]}"
    return 1
  fi

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1

  echo "[+] connecting: ftp://${user}@${ip}" >&2

  local logfile=""
  if $log; then
    logfile="$(_ftp-log-path "$ip" "${user}")" || return 1
  fi

  _ftp-connect-creds "$ip" "$user" "$pass" "$logfile" "${rest[@]}"
}

# Wrap system ftp; uses recon creds when available (like ssh)
ftp() {
  local log=false
  local anon=false
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      -A)
        anon=true
        args+=("$1")
        shift
        ;;
      -h|--help)
        echo "usage: ftp [-l] [ftp-options...] [host]"
        echo "  saved creds (hydrassh/hydraftp/cl): ftp / ftp user / ftp user@ip"
        echo "  anonymous: ftp -A <host>  or  ftpa"
        echo "  plain: command ftp ..."
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  if ! $anon; then
    local ip="" a
    for a in "${args[@]}"; do
      if [[ "$a" == *@* ]]; then
        ip="${a#*@}"
        break
      fi
      if [[ "$a" =~ $(_recon-ip-re) ]]; then
        ip="$a"
        break
      fi
    done
    [[ -z "$ip" ]] && ip="${IP:-}"

    if [[ -n "$ip" ]] && _recon-has-creds "$ip"; then
      local -a login_args=()
      $log && login_args+=(-l)
      login_args+=("${args[@]}")
      ftp-login "${login_args[@]}"
      return $?
    fi
  fi

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
