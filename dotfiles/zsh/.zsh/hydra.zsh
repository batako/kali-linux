# ========================
# hydra helpers
# ========================

hydraweb() {
  if [[ $# -lt 6 ]]; then
    echo "usage:"
    echo "  hydraweb <target> <path> <user> <F|S> <text> <user_field> [pass_field] [extra_post]"
    echo
    echo "examples:"
    echo "  hydraweb 10.10.10.10 /login.php Rick F \"Invalid username or password\" username password"
    echo "  hydraweb 10.10.10.10 /login.php R1ckR0n43 S \"ingredient\" username password \"sub=Login\""
    echo
    echo "extra_post default: sub=Login  (matches login.php submit button)"
    return 1
  fi

  local target="$1"
  local path="$2"
  local user="$3"
  local mode="$4"
  local text="$5"
  local userfield="$6"
  local passfield="${7:-password}"
  local extra_post="${8:-sub=Login}"

  local form="${path}:${userfield}=^USER^&${passfield}=^PASS^"
  if [[ -n "$extra_post" ]]; then
    form="${form}&${extra_post}"
  fi
  form="${form}:${mode}=${text}"

  echo "[*] hydra form: ${form}"

  /usr/bin/hydra -l "$user" \
    -P "$RECON_PASSLIST" \
    -t 16 -f -V \
    "$target" http-post-form \
    "$form"
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

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  echo "[*] target: ${service}://$target  user: $user"
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/${log_prefix}.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  hydra -l "$user" \
    -P "$wordlist" \
    -t "$threads" \
    -f -V \
    "${service}://$target" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

hydrassh() {
  if [[ $# -lt 1 ]]; then
    echo "usage: hydrassh [target] <user> [wordlist]"
    echo "  default wordlist: \$RECON_PASSLIST"
    echo "  omit target when \$IP is set (target-set <ip>)"
    return 1
  fi

  _hydra-parse-args "" "$@" || {
    echo "usage: hydrassh [target] <user> [wordlist]  (or: target-set <ip> first)"
    return 1
  }

  _hydra-run-service ssh "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" 32 hydrassh
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
