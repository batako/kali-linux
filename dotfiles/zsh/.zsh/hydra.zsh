# ========================
# hydra helpers
# ========================

_hydraweb-usage() {
  echo "usage:"
  echo "  hydraweb [target] <path> <user> <F|S> <text> <user_field> [pass_field] [extra_post] [cookie]"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  cookie: sent as H=Cookie: ... (e.g. PHPSESSID=abc; security=low)"
  echo
  echo "examples:"
  echo "  hydraweb /login.php Rick F \"Invalid username or password\" username password"
  echo "  hydraweb /login.php admin F \"failed\" username password sub=Login \"PHPSESSID=abc; security=low\""
  echo "  hydraweb 10.10.10.10 /login.php R1ckR0n43 S \"ingredient\" username password \"sub=Login\""
  echo
  echo "extra_post default: sub=Login  (matches login.php submit button)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra)"
}

hydraweb() {
  local target path user mode text userfield passfield extra_post cookie form

  if [[ $# -ge 1 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    if [[ $# -lt 6 ]]; then
      _hydraweb-usage
      return 1
    fi
    target="$1"
    shift
  else
    if [[ $# -lt 5 ]]; then
      _hydraweb-usage
      return 1
    fi
    target="${IP:-}"
    if [[ -z "$target" ]]; then
      echo "no target: target-set <ip> or pass IP as first arg" >&2
      return 1
    fi
  fi

  path="$1"
  user="$2"
  mode="$3"
  text="$4"
  userfield="$5"
  passfield="${6:-password}"
  extra_post="${7:-sub=Login}"
  cookie="${8:-}"

  form="${path}:${userfield}=^USER^&${passfield}=^PASS^"
  if [[ -n "$extra_post" ]]; then
    form="${form}&${extra_post}"
  fi
  if [[ -n "$cookie" ]]; then
    form="${form}:H=Cookie: ${cookie}"
  fi
  form="${form}:${mode}=${text}"

  echo "[*] hydra form: ${form}"
  [[ -n "$cookie" ]] && echo "[*] cookie: ${cookie}"
  echo "[*] target: http://$target  user: $user"
  echo "[*] wordlist: $RECON_PASSLIST"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/hydraweb.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  /usr/bin/hydra -l "$user" \
    -P "$RECON_PASSLIST" \
    -t 32 -f -V \
    "$target" http-post-form \
    "$form" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

# usage: _hydra-parse-args <default_user> [args...]
# sets: _HYDRA_TARGET _HYDRA_USER _HYDRA_WORDLIST
_hydra-parse-args() {
  local default_user="$1"
  shift
  local -a args=("$@")

  _HYDRA_WORDLIST="$RECON_PASSLIST"
  _HYDRA_TARGET=""
  _HYDRA_USER=""

  if [[ -n "${args[-1]}" && -f "${args[-1]:A}" ]]; then
    _HYDRA_WORDLIST="${args[-1]:A}"
    if (( ${#args[@]} > 1 )); then
      args=("${args[1,-2]}")
    else
      args=()
    fi
  fi

  if [[ ${#args[@]} -ge 2 && "${args[1]}" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    _HYDRA_TARGET="${args[1]}"
    _HYDRA_USER="${args[2]}"
  elif [[ ${#args[@]} -eq 2 ]]; then
    _HYDRA_TARGET="${args[1]}"
    _HYDRA_USER="${args[2]}"
  elif [[ ${#args[@]} -eq 1 ]]; then
    _HYDRA_TARGET="${IP:-}"
    _HYDRA_USER="${args[1]}"
  elif [[ ${#args[@]} -eq 0 ]]; then
    _HYDRA_TARGET="${IP:-}"
    _HYDRA_USER="$default_user"
  else
    return 1
  fi

  [[ -n "$_HYDRA_TARGET" && -n "$_HYDRA_USER" ]]
}

_hydra-run-service() {
  local service="$1"
  local target="$2"
  local user="$3"
  local wordlist="$4"
  local threads="$5"
  local log_prefix="$6"
  local port="${7:-}"

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local target_label="${service}://$target"
  [[ -n "$port" ]] && target_label="${target_label}:$port"
  echo "[*] target: $target_label  user: $user"
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/${log_prefix}.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  local -a hydra_cmd=(hydra -l "$user" -P "$wordlist" -t "$threads" -f -V)
  [[ -n "$port" ]] && hydra_cmd+=(-s "$port")
  hydra_cmd+=("$target" "$service")

  "${hydra_cmd[@]}" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

_hydrassh-usage() {
  echo "usage: hydrassh [-p port] [target] <user> [wordlist]"
  echo "  default wordlist: \$RECON_PASSLIST"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra → cl)"
  echo
  echo "examples:"
  echo "  hydrassh root"
  echo "  hydrassh -p 6498 boring"
  echo "  hydrassh 10.10.10.10 admin ./wordlist.txt"
}

hydrassh() {
  local port="" threads=32
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p[0-9]*)
        port="${1#-p}"
        shift
        ;;
      -p)
        port="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -h|--help)
        _hydrassh-usage
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  if [[ ${#args[@]} -eq 0 ]]; then
    _hydrassh-usage >&2
    return 1
  fi

  _hydra-parse-args "" "${args[@]}" || {
    _hydrassh-usage >&2
    return 1
  }

  _hydra-run-service ssh "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" "$threads" hydrassh "$port"
}

hydraftp() {
  _hydra-parse-args anonymous "$@" || {
    echo "usage: hydraftp [target] [user] [wordlist]"
    echo "  default user: anonymous"
    echo "  omit target when \$IP is set (target-set <ip>)"
    echo "  examples:"
    echo "    hydraftp                    # anonymous @ \$IP"
    echo "    hydraftp ./locks.txt        # anonymous + wordlist"
    echo "    hydraftp ftpuser ./locks.txt"
    return 1
  }

  _hydra-run-service ftp "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" 16 hydraftp
}

# usage: hydrapop3 [target] -L users.txt -P passes.txt
#        hydrapop3 [target] <user> [wordlist]   (single user, like hydrassh)
hydrapop3() {
  local target="" userfile="" passfile="" threads=16
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -L)
        userfile="$2"
        shift 2
        ;;
      -P)
        passfile="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -h|--help)
        echo "usage: hydrapop3 [target] -L users.txt -P passes.txt"
        echo "       hydrapop3 [target] <user> [wordlist]"
        echo "  hits saved to creds-list via creds-import-hydra"
        echo "  examples:"
        echo "    hydrapop3 -L users.txt -P passes.txt"
        echo "    hydrapop3 seina \$RECON_PASSLIST"
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  if [[ -n "$userfile" && -n "$passfile" ]]; then
    target="${args[1]:-${IP:-}}"
    [[ -z "$target" ]] && {
      echo "[-] no target ip — target-set <ip> first" >&2
      return 1
    }
    [[ -f "$userfile" && -f "$passfile" ]] || {
      echo "[-] userlist or passlist not found" >&2
      return 1
    }
    echo "[*] target: pop3://$target  -L ${userfile:t}  -P ${passfile:t}" >&2
    local log rc
    log="$(mktemp "${TMPDIR:-/tmp}/hydrapop3.XXXXXX")"
    trap 'rm -f "$log"' EXIT INT TERM
    hydra -L "$userfile" -P "$passfile" -t "$threads" -f -V \
      "$target" pop3 2>&1 | tee "$log"
    rc=${pipestatus[1]}
    python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"
    return $rc
  fi

  _hydra-parse-args "" "${args[@]}" || {
    echo "usage: hydrapop3 [target] -L users.txt -P passes.txt" >&2
    echo "       hydrapop3 [target] <user> [wordlist]" >&2
    return 1
  }

  _hydra-run-service pop3 "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" "$threads" hydrapop3
}

_hydra-run-http-get() {
  local target="$1"
  local user="$2"
  local wordlist="$3"
  local threads="$4"
  local log_prefix="$5"
  local port="$6"
  local url_path="$7"
  local user_flag="$8"   # -l or -L
  local user_arg="$9"

  url_path="${url_path:-/}"
  [[ "$url_path" != /* ]] && url_path="/${url_path}"

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local target_label="http://${target}${port:+:$port}${url_path}"
  if [[ "$user_flag" == -L ]]; then
    echo "[*] target: $target_label  -L ${user_arg:t}"
  else
    echo "[*] target: $target_label  user: $user"
  fi
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/${log_prefix}.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  local -a hydra_cmd=(hydra "$user_flag" "$user_arg" -P "$wordlist" -t "$threads" -f -V)
  [[ -n "$port" ]] && hydra_cmd+=(-s "$port")
  hydra_cmd+=("$target" http-get "$url_path")

  "${hydra_cmd[@]}" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

_hydrabasic-usage() {
  echo "usage: hydrabasic [-p port] [target] <user> [path] [wordlist]"
  echo "       hydrabasic [-p port] [target] -L users.txt [-P wordlist] [path]"
  echo "  HTTP Basic Auth (hydra http-get)"
  echo "  default path: /   default wordlist: \$RECON_PASSLIST"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra → cl)"
  echo
  echo "examples:"
  echo "  hydrabasic barry"
  echo "  hydrabasic barry /admin/"
  echo "  hydrabasic -p 8080 barry /protected/ ./wordlist.txt"
  echo "  hydrabasic -L users.txt -P passes.txt /"
}

hydrabasic() {
  local port="" threads=16
  local userfile="" passfile="" url_path="/"
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p[0-9]*)
        port="${1#-p}"
        shift
        ;;
      -p)
        port="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -L)
        userfile="$2"
        shift 2
        ;;
      -P)
        passfile="$2"
        shift 2
        ;;
      -h|--help)
        _hydrabasic-usage
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  if [[ -n "$userfile" ]]; then
    local target="${args[1]:-${IP:-}}"
    [[ -z "$target" ]] && {
      echo "[-] no target ip — target-set <ip> first" >&2
      _hydrabasic-usage >&2
      return 1
    }
    [[ -f "$userfile" ]] || {
      echo "[-] userlist not found: $userfile" >&2
      return 1
    }
    passfile="${passfile:-$RECON_PASSLIST}"
    if [[ ${#args[@]} -ge 1 && "${args[1]}" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
      target="${args[1]}"
      [[ ${#args[@]} -ge 2 && "${args[2]}" == /* ]] && url_path="${args[2]}"
    elif [[ ${#args[@]} -ge 1 && "${args[1]}" == /* ]]; then
      url_path="${args[1]}"
    fi
    _hydra-run-http-get "$target" "" "$passfile" "$threads" hydrabasic "$port" "$url_path" -L "$userfile"
    return $?
  fi

  local wordlist="$RECON_PASSLIST"
  if [[ -n "${args[-1]}" && -f "${args[-1]:A}" ]]; then
    wordlist="${args[-1]:A}"
    if (( ${#args[@]} > 1 )); then
      args=("${args[1,-2]}")
    else
      args=()
    fi
  fi

  local target="" user=""
  if [[ ${#args[@]} -ge 2 && "${args[1]}" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    target="${args[1]}"
    user="${args[2]}"
    args=("${args[3,-1]}")
  elif [[ ${#args[@]} -ge 1 ]]; then
    target="${IP:-}"
    user="${args[1]}"
    args=("${args[2,-1]}")
  else
    _hydrabasic-usage >&2
    return 1
  fi

  [[ -n "$target" && -n "$user" ]] || {
    echo "[-] need target and user (target-set <ip> or pass IP)" >&2
    _hydrabasic-usage >&2
    return 1
  }

  if [[ ${#args[@]} -ge 1 && "${args[1]}" == /* ]]; then
    url_path="${args[1]}"
  fi

  _hydra-run-http-get "$target" "$user" "$wordlist" "$threads" hydrabasic "$port" "$url_path" -l "$user"
}
