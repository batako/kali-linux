# ========================
# WebDAV helper (no-auth / creds-list / explicit auth)
# ========================

_dav-printable-cmd() {
  local -a cmd=("$@")
  local -a rendered=()
  local arg
  for arg in "${cmd[@]}"; do
    if [[ "$arg" =~ '^[A-Za-z0-9_./:=+-]+$' ]]; then
      rendered+=("$arg")
    else
      rendered+=("${(qq)arg}")
    fi
  done
  print -r -- "${(j: :)rendered}"
}

_dav-default-host() {
  local ip
  ip="$(_recon-ip-default 2>/dev/null)" || return 1
  print -r -- "$ip"
}

_dav-creds-host() {
  local host="$1"
  local bare="${host%%:*}"
  if [[ "$bare" =~ $(_recon-ip-re) ]]; then
    print -r -- "$bare"
    return 0
  fi
  _recon-ip-default 2>/dev/null
}

_dav-build-url() {
  local spec="$1" scheme="$2" host="$3"
  local port="" path=""

  if [[ -z "$spec" ]]; then
    print -r -- "${scheme}://${host}/"
    return 0
  fi

  case "$spec" in
    http://*|https://*)
      print -r -- "$spec"
      return 0
      ;;
    :*)
      port="${spec#*:}"
      if [[ "$port" == */* ]]; then
        path="/${port#*/}"
        port="${port%%/*}"
      else
        path="/"
      fi
      [[ -n "$port" ]] || return 1
      print -r -- "${scheme}://${host}:${port}${path}"
      return 0
      ;;
    /*)
      print -r -- "${scheme}://${host}${spec}"
      return 0
      ;;
    *)
      print -r -- "${scheme}://${host}/${spec}"
      return 0
      ;;
  esac
}

_dav-parse-auth() {
  local spec="$1" host="$2"

  _DAV_AUTH_USER=""
  _DAV_AUTH_PASS=""

  [[ -n "$spec" ]] || return 0

  if [[ "$spec" == *:* ]]; then
    _DAV_AUTH_USER="${spec%%:*}"
    _DAV_AUTH_PASS="${spec#*:}"
    return 0
  fi

  _DAV_AUTH_USER="$spec"
  local creds_host
  creds_host="$(_dav-creds-host "$host")" || {
    echo "[-] dav: no IP context for creds lookup; use -u user:pass or target-set <ip>" >&2
    return 1
  }

  if ! _DAV_AUTH_PASS="$(_recon-creds-for-user "$creds_host" "$_DAV_AUTH_USER" 2>/dev/null)"; then
    echo "[-] dav: no saved creds for ${_DAV_AUTH_USER}@${creds_host} (use cl / creds-add or -u user:pass)" >&2
    return 1
  fi
}

_dav-auth-probe-headers() {
  local url="$1"
  local insecure="${2:-false}"
  local method="${3:-OPTIONS}"
  shift 3
  local -a probe_headers=("$@")
  local -a cmd=(curl -sS -D - -o /dev/null -X "$method" --max-time 5)
  [[ "$insecure" == true ]] && cmd+=(-k)
  (( ${#probe_headers[@]} )) && cmd+=("${probe_headers[@]}")
  cmd+=("$url")
  "${cmd[@]}" 2>/dev/null
}

_dav-auth-required-from-headers() {
  local headers="${1:l}"
  [[ "$headers" == *"www-authenticate:"* ]] && return 0
  [[ "$headers" == *$'\nhttp/1.1 401 '* || "$headers" == http/1.1\ 401\ * ]] && return 0
  [[ "$headers" == *$'\nhttp/2 401 '* || "$headers" == http/2\ 401\ * ]] && return 0
  return 1
}

_dav-auth-flag-from-headers() {
  local low="${1:l}"
  [[ "$low" == *"www-authenticate:"* ]] || return 0

  if [[ "$low" == *"www-authenticate: ntlm"* ]] && [[ "$low" != *"www-authenticate: basic"* ]] && [[ "$low" != *" basic realm="* ]]; then
    print -r -- --ntlm
    return 0
  fi
  return 0
}

_dav-auth-flag() {
  local url="$1"
  local insecure="${2:-false}"
  local method="${3:-OPTIONS}"
  shift 3
  local -a probe_headers=("$@")
  local headers low
  headers="$(_dav-auth-probe-headers "$url" "$insecure" "$method" "${probe_headers[@]}")" || return 0
  low="${headers:l}"
  _dav-auth-flag-from-headers "$low"
}

_dav-auth-check-status() {
  local url="$1" insecure="$2" method="$3" auth_flag="$4" user="$5" pass="$6"
  shift 6
  local -a req_headers=("$@")
  local -a cmd=(curl -sS -o /dev/null -w '%{http_code}' -X "$method" --max-time 8)
  [[ "$insecure" == true ]] && cmd+=(-k)
  [[ -n "$auth_flag" ]] && cmd+=("$auth_flag")
  (( ${#req_headers[@]} )) && cmd+=("${req_headers[@]}")
  cmd+=(-u "${user}:${pass}" "$url")
  "${cmd[@]}" 2>/dev/null
}

_dav-save-creds() {
  local host="$1" user="$2" pass="$3"
  local ip
  ip="$(_dav-creds-host "$host")" || return 1
  python3 "$RECON_APP" creds-add "$ip" "$user" "$pass" --comment "WebDAV auto" >/dev/null 2>&1
}

_dav-last-get() {
  local ip="$1"
  python3 "$RECON_APP" dav-last-get "$ip" 2>/dev/null
}

_dav-last-set() {
  local ip="$1" user="$2"
  python3 "$RECON_APP" dav-last-set "$ip" "$user" >/dev/null 2>&1
}

_dav-try-saved-auth() {
  local url="$1" host="$2" insecure="$3" method="$4" auth_flag="$5"
  shift 5
  local -a req_headers=("$@")
  local ip json users chosen_user pass code i choice last idx attempted_saved=false
  local -a filtered=()

  ip="$(_dav-creds-host "$host")" || return 1
  json="$(_recon-creds-json "$ip")"
  [[ -n "$json" && "$json" != "[]" ]] || return 1

  users=("${(@f)$(print -r -- "$json" | python3 -c '
import json, sys
for row in json.load(sys.stdin):
    user = row.get("username", "")
    if user in {"", "anonymous", "exports", "logs"}:
        continue
    print(user)
')}")

  for chosen_user in "${users[@]}"; do
    [[ -n "$chosen_user" ]] && filtered+=("$chosen_user")
  done
  users=("${filtered[@]}")

  (( ${#users[@]} )) || return 1

  if (( ${#users[@]} == 1 )); then
    chosen_user="${users[1]}"
    attempted_saved=true
  else
    if [[ ! -t 0 ]]; then
      return 1
    fi

    last="$(_dav-last-get "$ip")"

    echo "[*] $ip — choose account:" >&2
    i=1
    for chosen_user in "${users[@]}"; do
      if [[ -n "$last" && "$chosen_user" == "$last" ]]; then
        echo "  $i) $chosen_user (last)" >&2
        idx="$i"
      else
        echo "  $i) $chosen_user" >&2
      fi
      (( i++ ))
    done
    [[ -z "$idx" ]] && echo "[*] Enter = try defaults" >&2

    if [[ -n "$idx" ]]; then
      read "choice?#? [$idx]: "
      [[ -z "$choice" ]] && choice="$idx"
    else
      read "choice?#? "
      [[ -z "$choice" ]] && return 1
    fi

    if [[ "$choice" =~ '^[0-9]+$' ]] && (( choice >= 1 && choice <= ${#users[@]} )); then
      chosen_user="${users[choice]}"
      attempted_saved=true
    else
      echo "[-] invalid choice" >&2
      return 1
    fi
  fi

  pass="$(_recon-creds-for-user "$ip" "$chosen_user" 2>/dev/null)" || return 1
  [[ -n "$pass" ]] || return 1

  code="$(_dav-auth-check-status "$url" "$insecure" "$method" "$auth_flag" "$chosen_user" "$pass" "${req_headers[@]}")"
  if [[ "$code" =~ '^(2|3)[0-9][0-9]$' ]]; then
    _DAV_AUTH_USER="$chosen_user"
    _DAV_AUTH_PASS="$pass"
    _dav-last-set "$ip" "$chosen_user"
    echo "[*] auth: ${chosen_user}@${ip} (creds-list)" >&2
    return 0
  fi

  if $attempted_saved; then
    echo "[-] auth failed: ${chosen_user}@${ip} (creds-list)" >&2
    return 2
  fi

  return 1
}

_dav-try-default-auth() {
  local url="$1" host="$2" insecure="$3" method="$4" auth_flag="$5"
  shift 5
  local -a req_headers=("$@")
  local pair user pass code ip
  local -a defaults=(
    "wampp:xampp"
    "webdav:webdav"
    "jigsaw:jigsaw"
  )

  ip="$(_dav-creds-host "$host")" || ip="$host"

  for pair in "${defaults[@]}"; do
    user="${pair%%:*}"
    pass="${pair#*:}"
    code="$(_dav-auth-check-status "$url" "$insecure" "$method" "$auth_flag" "$user" "$pass" "${req_headers[@]}")"
    if [[ "$code" =~ '^(2|3)[0-9][0-9]$' ]]; then
      _DAV_AUTH_USER="$user"
      _DAV_AUTH_PASS="$pass"
      _dav-save-creds "$host" "$user" "$pass"
      _dav-last-set "$ip" "$user"
      echo "[*] auth: ${user}@${ip} (saved to creds-list)" >&2
      return 0
    fi
  done

  return 1
}

_dav-help() {
  _toolkit-echo "usage: dav <subcommand> [options] ..." "使い方: dav <subcommand> [options] ..."
  _toolkit-echo "  subcommands: ls get put cat mkdir rm mv" "  subcommands: ls get put cat mkdir rm mv"
  _toolkit-echo "  auth: no auth by default; if challenged, choose from creds-list first, or try wampp/xampp, webdav/webdav, jigsaw/jigsaw and save to cl" "  認証: 既定は認証なし。認証要求があれば、まず creds-list から選択し、未選択なら wampp/xampp, webdav/webdav, jigsaw/jigsaw を試し、成功時は cl に保存"
  _toolkit-echo "  if -u user omits pass, resolve it from creds-list / cl" "  -u user で pass を省略した場合は creds-list / cl から補完"
  _toolkit-echo "  path forms: /webdav/, notes.txt, :8080/webdav/, http://host/webdav/" "  パス形式: /webdav/, notes.txt, :8080/webdav/, http://host/webdav/"
  _toolkit-echo "  default host: current target IP from target-set / cases set" "  既定ホスト: target-set / cases set の現在 target IP"
  _toolkit-echo "options:" "オプション:"
  _toolkit-echo "  --http / --https      force scheme for non-URL specs (default: http)" "  --http / --https      URL 以外の指定でスキーム固定（既定: http）"
  _toolkit-echo "  -u, --user USER[:PASS]  auth user (auto-detect Basic vs NTLM)" "  -u, --user USER[:PASS]  認証ユーザー（Basic / NTLM を自動判定）"
  _toolkit-echo "  -n, --dry-run         print the curl command only (do not run)" "  -n, --dry-run         curl コマンドだけ表示（実行しない）"
  _toolkit-echo "  -k, --insecure        pass -k to curl" "  -k, --insecure        curl に -k を渡す"
  _toolkit-echo "examples:" "例:"
  _toolkit-echo "  dav ls /webdav/" "  dav ls /webdav/"
  _toolkit-echo "  dav ls :8080/webdav/ -n" "  dav ls :8080/webdav/ -n"
  _toolkit-echo "  dav get /webdav/notes.txt" "  dav get /webdav/notes.txt"
  _toolkit-echo "  dav put shell.php /webdav/shell.php -u wampp" "  dav put shell.php /webdav/shell.php -u wampp"
  _toolkit-echo "  dav cat https://\$IP/webdav/flag.txt -u admin:admin" "  dav cat https://\$IP/webdav/flag.txt -u admin:admin"
}

dav() {
  local subcmd="${1:-}"
  local scheme="http"
  local auth_spec=""
  local auth_flag=""
  local auth_probe_method="OPTIONS"
  local auth_probe_text=""
  local dry_run=false
  local insecure=false
  local need_host=true
  local host="" url="" local_path="" dst_url="" src_url=""
  local -a curl_base=() headers=() args=() positionals=() auth_probe_headers=()

  if [[ -z "$subcmd" || "$subcmd" == "-h" || "$subcmd" == "--help" ]]; then
    _dav-help
    return 0
  fi
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _dav-help
        return 0
        ;;
      --http)
        scheme="http"
        shift
        ;;
      --https)
        scheme="https"
        shift
        ;;
      -u|--user)
        auth_spec="$2"
        shift 2
        ;;
      -n|--dry-run)
        dry_run=true
        shift
        ;;
      -k|--insecure)
        insecure=true
        shift
        ;;
      --header|-H)
        headers+=("$1" "$2")
        shift 2
        ;;
      --)
        shift
        while [[ $# -gt 0 ]]; do
          args+=("$1")
          shift
        done
        ;;
      -*)
        args+=("$1")
        shift
        ;;
      *)
        positionals+=("$1")
        shift
        ;;
    esac
  done

  case "$subcmd" in
    ls)
      [[ "${positionals[1]:-}" == http://* || "${positionals[1]:-}" == https://* ]] && need_host=false
      ;;
    get|cat|mkdir|rm)
      [[ "${positionals[1]:-}" == http://* || "${positionals[1]:-}" == https://* ]] && need_host=false
      ;;
    put)
      [[ "${positionals[2]:-}" == http://* || "${positionals[2]:-}" == https://* ]] && need_host=false
      ;;
    mv)
      if [[ "${positionals[1]:-}" == http://* || "${positionals[1]:-}" == https://* ]]; then
        if [[ "${positionals[2]:-}" == http://* || "${positionals[2]:-}" == https://* ]]; then
          need_host=false
        fi
      fi
      ;;
  esac

  host="$(_dav-default-host 2>/dev/null)"
  if $need_host && [[ -z "$host" ]]; then
    echo "[-] dav: no target ip (target-set <ip> or pass a full URL)" >&2
    return 1
  fi

  curl_base=(curl -sS)
  $insecure && curl_base+=(-k)
  (( ${#headers[@]} )) && curl_base+=("${headers[@]}")
  (( ${#args[@]} )) && curl_base+=("${args[@]}")

  case "$subcmd" in
    ls)
      if (( ${#positionals[@]} > 1 )); then
        echo "usage: dav ls [path|url]" >&2
        return 1
      fi
      url="$(_dav-build-url "${positionals[1]:-}" "$scheme" "$host")" || {
        echo "[-] dav ls: invalid path/url" >&2
        return 1
      }
      auth_probe_method="PROPFIND"
      auth_probe_headers=(-H "Depth: 1")
      ;;
    get)
      if (( ${#positionals[@]} < 1 || ${#positionals[@]} > 2 )); then
        echo "usage: dav get <remote-path|url> [local-path]" >&2
        return 1
      fi
      url="$(_dav-build-url "${positionals[1]}" "$scheme" "$host")" || {
        echo "[-] dav get: invalid remote path/url" >&2
        return 1
      }
      auth_probe_method="GET"
      local_path="${positionals[2]:-${positionals[1]:t}}"
      [[ -n "$local_path" ]] || local_path="download.bin"
      ;;
    put)
      if (( ${#positionals[@]} != 2 )); then
        echo "usage: dav put <local-path> <remote-path|url>" >&2
        return 1
      fi
      local_path="${positionals[1]}"
      [[ -f "$local_path" ]] || {
        echo "[-] dav put: local file not found: $local_path" >&2
        return 1
      }
      url="$(_dav-build-url "${positionals[2]}" "$scheme" "$host")" || {
        echo "[-] dav put: invalid remote path/url" >&2
        return 1
      }
      auth_probe_method="PROPFIND"
      auth_probe_headers=(-H "Depth: 0")
      ;;
    cat)
      if (( ${#positionals[@]} != 1 )); then
        echo "usage: dav cat <remote-path|url>" >&2
        return 1
      fi
      url="$(_dav-build-url "${positionals[1]}" "$scheme" "$host")" || {
        echo "[-] dav cat: invalid remote path/url" >&2
        return 1
      }
      auth_probe_method="GET"
      ;;
    mkdir)
      if (( ${#positionals[@]} != 1 )); then
        echo "usage: dav mkdir <remote-dir|url>" >&2
        return 1
      fi
      url="$(_dav-build-url "${positionals[1]}" "$scheme" "$host")" || {
        echo "[-] dav mkdir: invalid remote path/url" >&2
        return 1
      }
      auth_probe_method="PROPFIND"
      auth_probe_headers=(-H "Depth: 0")
      ;;
    rm)
      if (( ${#positionals[@]} != 1 )); then
        echo "usage: dav rm <remote-path|url>" >&2
        return 1
      fi
      url="$(_dav-build-url "${positionals[1]}" "$scheme" "$host")" || {
        echo "[-] dav rm: invalid remote path/url" >&2
        return 1
      }
      auth_probe_method="PROPFIND"
      auth_probe_headers=(-H "Depth: 0")
      ;;
    mv)
      if (( ${#positionals[@]} != 2 )); then
        echo "usage: dav mv <src-path|url> <dst-path|url>" >&2
        return 1
      fi
      src_url="$(_dav-build-url "${positionals[1]}" "$scheme" "$host")" || {
        echo "[-] dav mv: invalid source path/url" >&2
        return 1
      }
      dst_url="$(_dav-build-url "${positionals[2]}" "$scheme" "$host")" || {
        echo "[-] dav mv: invalid destination path/url" >&2
        return 1
      }
      auth_probe_method="PROPFIND"
      auth_probe_headers=(-H "Depth: 0")
      ;;
    *)
      echo "[-] dav: unknown subcommand: $subcmd" >&2
      echo "    subcommands: ls get put cat mkdir rm mv" >&2
      return 1
      ;;
  esac

  if [[ "$subcmd" == "mv" ]]; then
    if [[ -n "$auth_spec" ]]; then
      _dav-parse-auth "$auth_spec" "${${src_url#*://}%%/*}" || return 1
      auth_flag="$(_dav-auth-flag "$src_url" "$insecure" "$auth_probe_method" "${auth_probe_headers[@]}")"
      [[ -n "$auth_flag" ]] && curl_base+=("$auth_flag")
      curl_base+=(-u "${_DAV_AUTH_USER}:${_DAV_AUTH_PASS}")
    elif ! $dry_run; then
      auth_probe_text="$(_dav-auth-probe-headers "$src_url" "$insecure" "$auth_probe_method" "${auth_probe_headers[@]}")"
      if _dav-auth-required-from-headers "$auth_probe_text"; then
        auth_flag="$(_dav-auth-flag-from-headers "$auth_probe_text")"
        _dav-try-saved-auth "$src_url" "${${src_url#*://}%%/*}" "$insecure" "$auth_probe_method" "$auth_flag" "${auth_probe_headers[@]}"
        local saved_status=$?
        if (( saved_status == 0 )); then
          [[ -n "$auth_flag" ]] && curl_base+=("$auth_flag")
          curl_base+=(-u "${_DAV_AUTH_USER}:${_DAV_AUTH_PASS}")
        elif (( saved_status == 1 )) && _dav-try-default-auth "$src_url" "${${src_url#*://}%%/*}" "$insecure" "$auth_probe_method" "$auth_flag" "${auth_probe_headers[@]}"; then
          [[ -n "$auth_flag" ]] && curl_base+=("$auth_flag")
          curl_base+=(-u "${_DAV_AUTH_USER}:${_DAV_AUTH_PASS}")
        elif (( saved_status == 2 )); then
          return 1
        else
          echo "[-] dav: authentication required and default creds failed" >&2
          return 1
        fi
      fi
    fi
    local -a cmd=("${curl_base[@]}" -X MOVE -H "Destination: ${dst_url}" "$src_url")
    if $dry_run; then
      print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
      return 0
    fi
    "${cmd[@]}"
    return $?
  fi

  if [[ -n "$auth_spec" ]]; then
    _dav-parse-auth "$auth_spec" "${${url#*://}%%/*}" || return 1
    auth_flag="$(_dav-auth-flag "$url" "$insecure" "$auth_probe_method" "${auth_probe_headers[@]}")"
    [[ -n "$auth_flag" ]] && curl_base+=("$auth_flag")
    curl_base+=(-u "${_DAV_AUTH_USER}:${_DAV_AUTH_PASS}")
  elif ! $dry_run; then
    auth_probe_text="$(_dav-auth-probe-headers "$url" "$insecure" "$auth_probe_method" "${auth_probe_headers[@]}")"
    if _dav-auth-required-from-headers "$auth_probe_text"; then
      auth_flag="$(_dav-auth-flag-from-headers "$auth_probe_text")"
      _dav-try-saved-auth "$url" "${${url#*://}%%/*}" "$insecure" "$auth_probe_method" "$auth_flag" "${auth_probe_headers[@]}"
      local saved_status=$?
      if (( saved_status == 0 )); then
        [[ -n "$auth_flag" ]] && curl_base+=("$auth_flag")
        curl_base+=(-u "${_DAV_AUTH_USER}:${_DAV_AUTH_PASS}")
      elif (( saved_status == 1 )) && _dav-try-default-auth "$url" "${${url#*://}%%/*}" "$insecure" "$auth_probe_method" "$auth_flag" "${auth_probe_headers[@]}"; then
        [[ -n "$auth_flag" ]] && curl_base+=("$auth_flag")
        curl_base+=(-u "${_DAV_AUTH_USER}:${_DAV_AUTH_PASS}")
      elif (( saved_status == 2 )); then
        return 1
      else
        echo "[-] dav: authentication required and default creds failed" >&2
        return 1
      fi
    fi
  fi

  case "$subcmd" in
    ls)
      local -a cmd=("${curl_base[@]}" -X PROPFIND -H "Depth: 1" "$url")
      if $dry_run; then
        print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
        return 0
      fi
      "${cmd[@]}"
      ;;
    get)
      local -a cmd=("${curl_base[@]}" -o "$local_path" "$url")
      if $dry_run; then
        print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
        return 0
      fi
      "${cmd[@]}"
      ;;
    put)
      local -a cmd=("${curl_base[@]}" -T "$local_path" "$url")
      if $dry_run; then
        print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
        return 0
      fi
      "${cmd[@]}"
      ;;
    cat)
      local -a cmd=("${curl_base[@]}" "$url")
      if $dry_run; then
        print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
        return 0
      fi
      "${cmd[@]}"
      ;;
    mkdir)
      local -a cmd=("${curl_base[@]}" -X MKCOL "$url")
      if $dry_run; then
        print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
        return 0
      fi
      "${cmd[@]}"
      ;;
    rm)
      local -a cmd=("${curl_base[@]}" -X DELETE "$url")
      if $dry_run; then
        print -r -- "$(_dav-printable-cmd "${cmd[@]}")"
        return 0
      fi
      "${cmd[@]}"
      ;;
  esac
}
