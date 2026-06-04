# ========================
# shared recon creds (cl / ssh / ftp)
# ========================

_recon-ip-re() {
  echo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

# $IP → cases/<case>/target (lazy load when case is set)
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

# FTP anonymous — stored for cl / ftp; not used for ssh auto-login
export FTP_ANON_USER="${FTP_ANON_USER:-anonymous}"
export FTP_ANON_PASS="${FTP_ANON_PASS:-anonymous@}"

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

_recon-pick-user() {
  local ip="$1"
  local exclude_anon="${2:-0}"
  local json users i choice last idx

  json="$(_recon-creds-json "$ip" | _recon-creds-json-filter "$exclude_anon")"
  if [[ -z "$json" || "$json" == "[]" ]]; then
    return 1
  fi

  users=("${(@f)$(print -r -- "$json" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(r['username'])
")}")

  if (( ${#users[@]} == 0 )); then
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
  local -a pos=("${(@)1}")
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
      elif [[ "${pos[1]}" =~ $(_recon-ip-re) ]]; then
        _RECON_IP="${pos[1]}"
      else
        _RECON_USER="${pos[1]}"
        _RECON_IP="$(_recon-ip-default 2>/dev/null)"
      fi
      ;;
    2)
      if [[ "${pos[1]}" =~ $(_recon-ip-re) ]]; then
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

# james_rsa -> james; id_rsa needs explicit user elsewhere
_recon-guess-user-from-key() {
  local key="$1"
  local base="${key:t}"
  base="${base%.pem}"
  base="${base%_rsa}"
  base="${base%_dsa}"
  base="${base%_ed25519}"
  base="${base%_ecdsa}"
  [[ "$base" == id || "$base" == identity ]] && return 1
  [[ -n "$base" ]] && { echo "$base"; return 0 }
  return 1
}
