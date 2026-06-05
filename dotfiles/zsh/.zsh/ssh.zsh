# ========================
# SSH (recon creds + sshpass)
# ========================

_ssh-bin() {
  whence -p ssh 2>/dev/null || echo /usr/bin/ssh
}

_scp-bin() {
  whence -p scp 2>/dev/null || echo /usr/bin/scp
}

_ssh-log-path() {
  local host="$1"
  local user="${2:-session}"
  local logs
  logs="$(case-logs-dir)" || return 1
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$logs"
  echo "$logs/ssh_${host}_${user}_${ts}.log"
}

# Strip --log / -l (session log; same as ftp -l). Login user comes from args or cl.
_ssh-consume-flags() {
  _SSH_LOG=false
  _SSH_HELP=false
  local -a out=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --log|-l)
        _SSH_LOG=true
        shift
        ;;
      -h|--help)
        echo "usage: ssh [-l] [-i key] [user] [ip]"
        echo "  saved creds: ssh / ssh user / ssh -i keyfile"
        echo "  -l / --log: session log → cases/.../logs/ssh_<host>_<user>_*.log"
        echo "  login name: ssh user / ssh user@ip (not ssh -l; use command ssh -l user for OpenSSH)"
        echo "  plain: command ssh ..."
        _SSH_HELP=true
        return 0
        ;;
      *)
        out+=("$1")
        shift
        ;;
    esac
  done

  _SSH_ARGS=("${out[@]}")
}

_ssh-run-session() {
  local logfile="$1"
  shift
  local -a cmd=("$@")

  if [[ -n "$logfile" ]]; then
    echo "[+] logging: $logfile"
    script -q -f "$logfile" -c "$(print -r -- ${(q)cmd[@]})"
    echo "[+] session log saved: $logfile"
  else
    "${cmd[@]}"
  fi
}

# Parse ssh args; sets _SSH_IDENTITY, _SSH_USER, _SSH_IP, _SSH_REST[]
_ssh-parse-args() {
  local -a rest=() pos=()
  local a

  _SSH_IDENTITY=""
  _SSH_USER=""
  _SSH_IP=""
  _SSH_REST=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -i)
        _SSH_IDENTITY="$2"
        shift 2
        ;;
      -o|-b|-c|-F|-J|-L|-m|-p|-R|-W|-w)
        rest+=("$1" "$2")
        shift 2
        ;;
      -*)
        rest+=("$1")
        shift
        ;;
      *)
        pos+=("$1")
        shift
        ;;
    esac
  done

  _SSH_REST=("${rest[@]}")

  case ${#pos[@]} in
    0)
      _SSH_IP="${IP:-}"
      ;;
    1)
      if [[ "${pos[1]}" == *@* ]]; then
        _SSH_USER="${pos[1]%%@*}"
        _SSH_IP="${pos[1]#*@}"
      elif [[ "${pos[1]}" =~ $(_recon-ip-re) ]]; then
        _SSH_IP="${pos[1]}"
      else
        _SSH_USER="${pos[1]}"
        _SSH_IP="${IP:-}"
      fi
      ;;
    *)
      _SSH_USER="${pos[1]}"
      _SSH_IP="${pos[2]}"
      ;;
  esac
}

ssh-key-login() {
  local pass="" key_abs logfile=""

  _ssh-parse-args "${_SSH_ARGS[@]}" || {
    echo "usage: ssh [--log] -i <keyfile> [user] [ip]" >&2
    return 1
  }

  if [[ -z "$_SSH_IDENTITY" ]]; then
    echo "[-] ssh-key-login: missing -i keyfile" >&2
    return 1
  fi
  if [[ ! -f "$_SSH_IDENTITY" ]]; then
    echo "[-] key not found: $_SSH_IDENTITY" >&2
    return 1
  fi

  chmod 600 "$_SSH_IDENTITY" 2>/dev/null
  key_abs="$(realpath "$_SSH_IDENTITY" 2>/dev/null || echo "$_SSH_IDENTITY")"

  if [[ -z "$_SSH_IP" ]]; then
    _SSH_IP="$(target-current 2>/dev/null)" || {
      echo "[-] no target ip (ts <ip> or cs <case> with target file)" >&2
      return 1
    }
  fi

  if [[ -z "$_SSH_USER" ]]; then
    _SSH_USER="$(_recon-guess-user-from-key "$_SSH_IDENTITY")" || {
      echo "[-] could not guess user from key (try: ssh -i $_SSH_IDENTITY user@\$IP)" >&2
      return 1
    }
  fi

  if $_SSH_LOG; then
    logfile="$(_ssh-log-path "$_SSH_IP" "$_SSH_USER")" || return 1
  fi

  if ! pass="$(_recon-creds-for-user "$_SSH_IP" "$_SSH_USER")"; then
    echo "[-] no saved creds for ${_SSH_USER}@${_SSH_IP} (cl empty? run sshkey-crack)" >&2
    if [[ -n "$logfile" ]]; then
      _ssh-run-session "$logfile" command ssh -i "$key_abs" "${_SSH_REST[@]}" -tt "${_SSH_USER}@${_SSH_IP}"
    else
      command ssh -i "$key_abs" "${_SSH_REST[@]}" "${_SSH_USER}@${_SSH_IP}"
    fi
    return 1
  fi
  if [[ -z "$pass" ]]; then
    echo "[-] empty passphrase in db for ${_SSH_USER}@${_SSH_IP}" >&2
    return 1
  fi

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[-] sshpass not installed" >&2
    return 1
  fi

  python3 "$RECON_APP" ssh-last-set "$_SSH_IP" "$_SSH_USER" >/dev/null 2>&1

  echo "[+] ssh key: ${key_abs}" >&2
  echo "[+] connecting: ${_SSH_USER}@${_SSH_IP} (passphrase from cl)" >&2

  local -a cmd=(
    sshpass -P "Enter passphrase for key" -p "$pass" "$(_ssh-bin)"
    -o StrictHostKeyChecking=accept-new
    -o ConnectTimeout=15
    -o PreferredAuthentications=publickey
    -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no
    -i "$key_abs"
  )
  (( ${#_SSH_REST[@]} )) && cmd+=("${_SSH_REST[@]}")
  cmd+=(-tt "${_SSH_USER}@${_SSH_IP}")

  _ssh-run-session "$logfile" "${cmd[@]}"
}

ssh-login() {
  local ip="" user="" pass="" logfile=""
  local -a rest=()
  local -a pos=()
  local a

  for a in "${_SSH_ARGS[@]}"; do
    if [[ "$a" == -* ]]; then
      rest+=("$a")
    else
      pos+=("$a")
    fi
  done

  _recon-parse-user-ip "${pos[@]}" || {
    echo "usage: ssh [--log] [user] [ip]" >&2
    return 1
  }
  ip="$_RECON_IP"
  user="$_RECON_USER"
  (( ${#pos[@]} > 2 )) && rest+=("${pos[@]:3}")

  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip" 1)" || return 1
  fi

  if [[ "$user" == anonymous ]]; then
    echo "[-] ssh: anonymous is FTP-only (use: ftpa)" >&2
    return 1
  fi

  if $_SSH_LOG; then
    logfile="$(_ssh-log-path "$ip" "$user")" || return 1
  fi

  if ! pass="$(_recon-creds-for-user "$ip" "$user")"; then
    echo "[-] no saved creds for ${user}@${ip}" >&2
    if [[ -n "$logfile" ]]; then
      _ssh-run-session "$logfile" command ssh "${rest[@]}" -tt "${user}@${ip}"
    else
      command ssh "${rest[@]}" "${user}@${ip}"
    fi
    return 1
  fi
  if [[ -z "$pass" ]]; then
    echo "[-] empty password in db for ${user}@${ip}" >&2
    return 1
  fi

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[-] sshpass not installed" >&2
    return 1
  fi

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1

  echo "[+] connecting: ${user}@${ip}" >&2

  local -a cmd=(
    sshpass -p "$pass" "$(_ssh-bin)"
    -o StrictHostKeyChecking=accept-new
    -o PreferredAuthentications=password
    -o PubkeyAuthentication=no
  )
  (( ${#rest[@]} )) && cmd+=("${rest[@]}")
  cmd+=(-tt "${user}@${ip}")

  _ssh-run-session "$logfile" "${cmd[@]}"
}

ssh() {
  local ip="" a

  _ssh-consume-flags "$@"
  $_SSH_HELP && return 0

  if [[ ${#_SSH_ARGS[@]} -eq 0 && "$_SSH_LOG" == false ]]; then
    ip="$(target-current 2>/dev/null)"
    if [[ -n "$ip" ]] && _recon-has-ssh-creds "$ip"; then
      ssh-login
      return $?
    fi
    command ssh
    return $?
  fi

  if [[ "${_SSH_ARGS[*]}" == *-i* ]]; then
    ssh-key-login
    return $?
  fi

  for a in "${_SSH_ARGS[@]}"; do
    if [[ "$a" != -* && "$a" == *@* ]]; then
      ip="${a#*@}"
      break
    fi
    if [[ "$a" != -* && "$a" =~ $(_recon-ip-re) ]]; then
      ip="$a"
      break
    fi
  done
  [[ -z "$ip" ]] && ip="$(target-current 2>/dev/null)"

  if [[ -n "$ip" ]] && _recon-has-ssh-creds "$ip"; then
    ssh-login
    return $?
  fi

  if $_SSH_LOG; then
    local host user logfile
    _ssh-parse-args "${_SSH_ARGS[@]}" || {
      echo "[-] ssh --log: need user@ip or target-set <ip>" >&2
      return 1
    }
    host="$_SSH_IP"
    [[ -z "$host" ]] && host="$(_recon-ip-default 2>/dev/null)"
    user="${_SSH_USER:-session}"
    [[ -z "$host" ]] && { echo "[-] ssh --log: no target ip (ts/ta/cs)" >&2; return 1; }
    logfile="$(_ssh-log-path "$host" "$user")" || return 1
    _ssh-run-session "$logfile" command ssh "${_SSH_ARGS[@]}"
    return $?
  fi

  command ssh "${_SSH_ARGS[@]}"
}

ssh-list() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: ssh-list [ip]"
    return 1
  fi
  python3 "$RECON_APP" creds-list "$ip"
}

_ssh-get-help() {
  echo "usage: ssh-get | sget [-o dir] [-r] [user] [ip] <remote> [remote...]"
  echo "  download via scp using cl creds (sshpass)"
  echo "  remote: path on target (e.g. ~/file, tryhackme.asc, /etc/passwd)"
  echo "  -o dir   local destination (default: .)"
  echo "  -r       scp -r (directory)"
  echo "examples:"
  echo "  sget tryhackme.asc credential.pgp"
  echo "  sget -o workspace/cases/tomghost ~/tryhackme.asc"
  echo "  sget skyfuck ~/credential.pgp"
}

# True when name is a saved cred user for ip (not a remote filename).
_ssh-get-is-cred-user() {
  local ip="$1" name="$2"
  [[ -n "$ip" && -n "$name" ]] || return 1
  _recon-creds-for-user "$ip" "$name" >/dev/null 2>&1
}

# Sets _SSH_GET_USER _SSH_GET_IP _SSH_GET_REMOTES[] from positionals.
_ssh-get-parse() {
  local -a pos=("${(@)1}")
  _SSH_GET_USER=""
  _SSH_GET_IP=""
  _SSH_GET_REMOTES=()

  if (( ${#pos[@]} == 0 )); then
    return 1
  fi

  if [[ "${pos[1]}" =~ $(_recon-ip-re) ]]; then
    _SSH_GET_IP="${pos[1]}"
    pos=("${pos[@]:2}")
  fi

  if (( ${#pos[@]} >= 2 )) && [[ "${pos[2]}" =~ $(_recon-ip-re) ]]; then
    _SSH_GET_USER="${pos[1]}"
    _SSH_GET_IP="${pos[2]}"
    pos=("${pos[@]:3}")
  elif (( ${#pos[@]} >= 2 )) && _ssh-get-is-cred-user "${_SSH_GET_IP:-$(_recon-ip-default 2>/dev/null)}" "${pos[1]}"; then
    _SSH_GET_USER="${pos[1]}"
    pos=("${pos[@]:2}")
  fi

  _SSH_GET_REMOTES=("${pos[@]}")
  (( ${#_SSH_GET_REMOTES[@]} > 0 ))
}

ssh-get() {
  local dest="." recursive=false
  local -a pos=() a
  local ip="" user="" pass=""
  local -a scp_args=() remote_specs=() r

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _ssh-get-help
        return 0
        ;;
      -o)
        dest="$2"
        shift 2
        ;;
      -r)
        recursive=true
        shift
        ;;
      --)
        shift
        pos+=("$@")
        break
        ;;
      -*)
        echo "[-] ssh-get: unknown option: $1" >&2
        _ssh-get-help >&2
        return 1
        ;;
      *)
        pos+=("$1")
        shift
        ;;
    esac
  done

  _ssh-get-parse "${pos[@]}" || {
    _ssh-get-help >&2
    return 1
  }

  ip="${_SSH_GET_IP:-}"
  user="${_SSH_GET_USER:-}"
  if [[ -z "$ip" ]]; then
    ip="$(_recon-ip-default 2>/dev/null)" || {
      echo "[-] no target ip (ts <ip> or cs <case> with target file)" >&2
      return 1
    }
  fi

  if [[ -z "$user" ]]; then
    local last=""
    last="$(python3 "$RECON_APP" ssh-last-get "$ip" 2>/dev/null)"
    if [[ -n "$last" ]] && ! _recon-skip-ssh-user "$last" \
        && _recon-creds-for-user "$ip" "$last" >/dev/null 2>&1; then
      user="$last"
    fi
  fi

  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip" 1)" || return 1
  fi

  if _recon-skip-ssh-user "$user"; then
    echo "[-] ssh-get: invalid login user: $user (ca <user> <pass> first)" >&2
    return 1
  fi

  if ! pass="$(_recon-creds-for-user "$ip" "$user")"; then
    echo "[-] no saved creds for ${user}@${ip} (cl empty?)" >&2
    return 1
  fi
  if [[ -z "$pass" ]]; then
    echo "[-] empty password in db for ${user}@${ip}" >&2
    return 1
  fi

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[-] sshpass not installed" >&2
    return 1
  fi

  mkdir -p "$dest" || return 1
  dest="$(cd "$dest" && pwd)"

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1

  $recursive && scp_args+=(-r)

  for r in "${_SSH_GET_REMOTES[@]}"; do
    remote_specs+=("${user}@${ip}:${r}")
  done

  echo "[+] get: ${user}@${ip} → $dest" >&2
  for r in "${_SSH_GET_REMOTES[@]}"; do
    echo "    ${r}" >&2
  done

  sshpass -p "$pass" "$(_scp-bin)" \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=15 \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "${scp_args[@]}" \
    "${remote_specs[@]}" \
    "$dest/"
}

alias sget='ssh-get'
