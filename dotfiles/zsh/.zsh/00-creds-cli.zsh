# ========================
# shared recon creds (cl / ssh / ftp)
# ========================

_recon-ip-re() {
  echo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

# IPv4 or FQDN (team.thm) — not bare short names like "admin"
_recon-looks-like-host() {
  local s="$1"
  [[ -n "$s" && "$s" != *@* && "$s" != */* ]] || return 1
  [[ "$s" =~ $(_recon-ip-re) ]] && return 0
  [[ "$s" == *.* && "$s" =~ '^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z0-9-]+$' ]] && return 0
  return 1
}

# $IP → cases/<room>/target (lazy load when CASE is set)
_recon-ip-default() {
  if [[ -n "${IP:-}" ]]; then
    echo "$IP"
    return 0
  fi
  if (( $+functions[target-load] )) && target-load; then
    echo "$IP"
    return 0
  fi
  return 1
}

_recon-creds-json() {
  python3 "$RECON_APP" creds-list --json "$1" 2>/dev/null
}

export RECON_BORG_CREDS_USER="${RECON_BORG_CREDS_USER:-borg}"

# FTP anonymous — hydraftp default user; not used for ssh auto-login
export FTP_ANON_USER="${FTP_ANON_USER:-anonymous}"

_recon-creds-json-filter() {
  local exclude_anon="${1:-0}"
  python3 -c "
import json, sys
exclude_anon = sys.argv[1] == '1'
rows = json.load(sys.stdin)
if exclude_anon:
    rows = [r for r in rows if r.get('username') != 'anonymous']
print(json.dumps(rows))
" "$exclude_anon"
}

_recon-has-creds() {
  local ip="$1" json
  json="$(_recon-creds-json "$ip")"
  [[ -n "$json" && "$json" != "[]" ]]
}

_recon-has-ssh-creds() {
  local ip="$1" json
  json="$(_recon-creds-json "$ip" | _recon-creds-json-filter 1)"
  [[ -n "$json" && "$json" != "[]" ]]
}

# Not SSH login accounts (case dirs / FTP-only); skip in ssh/sget user pickers
_recon-skip-ssh-user() {
  case "$1" in
    exports|logs|anonymous|"") return 0 ;;
  esac
  return 1
}

_recon-pick-user() {
  local ip="$1"
  local exclude_anon="${2:-0}"
  local json users i choice last idx u
  local -a filtered=()

  json="$(_recon-creds-json "$ip" | _recon-creds-json-filter "$exclude_anon")"
  if [[ -z "$json" || "$json" == "[]" ]]; then
    return 1
  fi

  users=("${(@f)$(print -r -- "$json" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(r['username'])
")}")

  for u in "${users[@]}"; do
    _recon-skip-ssh-user "$u" && continue
    filtered+=("$u")
  done
  users=("${filtered[@]}")

  if (( ${#users[@]} == 0 )); then
    echo "[-] no ssh login creds for $ip (creds-list has only reserved names? creds-add <user> <pass>)" >&2
    return 1
  fi

  if (( ${#users[@]} == 1 )); then
    echo "${users[1]}"
    return 0
  fi

  last="$(python3 "$RECON_APP" ssh-last-get "$ip" 2>/dev/null)"

  echo "[*] $ip — choose account:" >&2
  i=1
  for u in "${users[@]}"; do
    if [[ -n "$last" && "$u" == "$last" ]]; then
      echo "  $i) $u (last)" >&2
      idx="$i"
    else
      echo "  $i) $u" >&2
    fi
    (( i++ ))
  done

  if [[ -n "$idx" ]]; then
    read "choice?#? [$idx]: "
    [[ -z "$choice" ]] && choice="$idx"
  else
    read "choice?#? "
  fi

  if [[ "$choice" =~ '^[0-9]+$' ]] && (( choice >= 1 && choice <= ${#users[@]} )); then
    echo "${users[choice]}"
    return 0
  fi

  echo "[-] invalid choice" >&2
  return 1
}

_recon-creds-for-user() {
  local ip="$1" user="$2"
  print -r -- "$(_recon-creds-json "$ip")" | python3 -c "
import json, sys
user = sys.argv[1]
for r in json.load(sys.stdin):
    if r['username'] == user:
        print(r['password'])
        sys.exit(0)
sys.exit(1)
" "$user"
}

_recon-parse-user-ip() {
  # sets _RECON_USER _RECON_IP from positional args; returns 1 on missing ip
  local -a pos=("$@")
  _RECON_USER=""
  _RECON_IP=""

  case ${#pos[@]} in
    0)
      _RECON_IP="$(_recon-ip-default 2>/dev/null)"
      ;;
    1)
      if [[ "${pos[1]}" == *@* ]]; then
        _RECON_USER="${pos[1]%%@*}"
        _RECON_IP="${pos[1]#*@}"
      elif _recon-looks-like-host "${pos[1]}"; then
        _RECON_IP="${pos[1]}"
      else
        _RECON_USER="${pos[1]}"
        _RECON_IP="$(_recon-ip-default 2>/dev/null)"
      fi
      ;;
    2)
      if _recon-looks-like-host "${pos[1]}"; then
        _RECON_IP="${pos[1]}"
        _RECON_USER="${pos[2]}"
      else
        _RECON_USER="${pos[1]}"
        _RECON_IP="${pos[2]}"
      fi
      ;;
    *)
      _RECON_USER="${pos[1]}"
      _RECON_IP="${pos[2]}"
      ;;
  esac

  [[ -n "$_RECON_IP" ]]
}

# james_rsa -> james; id_rsa / secretKey need explicit user or cl
_recon-guess-user-from-key() {
  local key="$1"
  local base="${key:t}"
  base="${base%.pem}"

  case "$base" in
    *_rsa|*_dsa|*_ed25519|*_ecdsa)
      base="${base%_rsa}"
      base="${base%_dsa}"
      base="${base%_ed25519}"
      base="${base%_ecdsa}"
      ;;
    *)
      return 1
      ;;
  esac

  [[ "$base" == id || "$base" == identity ]] && return 1
  [[ -n "$base" ]] && { echo "$base"; return 0 }
  return 1
}

# Resolve login user for ssh -i (ssh-last, cl, key name if cred exists, picker)
_recon-user-for-ssh-key() {
  local ip="$1" key="$2"
  local u guessed json
  local -a users=()

  u="$(python3 "$RECON_APP" ssh-last-get "$ip" 2>/dev/null)"
  if [[ -n "$u" ]] && ! _recon-skip-ssh-user "$u" \
      && _recon-creds-for-user "$ip" "$u" >/dev/null 2>&1; then
    echo "$u"
    return 0
  fi

  json="$(_recon-creds-json "$ip" | _recon-creds-json-filter 1)"
  if [[ -n "$json" && "$json" != "[]" ]]; then
    users=("${(@f)$(print -r -- "$json" | python3 -c "
import json, sys
skip = {'exports', 'logs', 'anonymous', ''}
for r in json.load(sys.stdin):
    u = r['username']
    if u not in skip:
        print(u)
")}")
  fi
  if (( ${#users[@]} == 1 )); then
    echo "${users[1]}"
    return 0
  fi

  guessed="$(_recon-guess-user-from-key "$key" 2>/dev/null)"
  if [[ -n "$guessed" ]] && _recon-creds-for-user "$ip" "$guessed" >/dev/null 2>&1; then
    echo "$guessed"
    return 0
  fi

  _recon-pick-user "$ip" 1
}
