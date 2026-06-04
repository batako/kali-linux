# ========================
# shared recon creds (cl / ssh / ftp)
# ========================

_recon-ip-re() {
  echo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

_recon-creds-json() {
  python3 "$RECON_APP" creds-list --json "$1" 2>/dev/null
}

_recon-has-creds() {
  local ip="$1" json
  json="$(_recon-creds-json "$ip")"
  [[ -n "$json" && "$json" != "[]" ]]
}

_recon-pick-user() {
  local ip="$1"
  local json users i choice last idx

  json="$(_recon-creds-json "$ip")"
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
      _RECON_IP="${IP:-}"
      ;;
    1)
      if [[ "${pos[1]}" == *@* ]]; then
        _RECON_USER="${pos[1]%%@*}"
        _RECON_IP="${pos[1]#*@}"
      elif [[ "${pos[1]}" =~ $(_recon-ip-re) ]]; then
        _RECON_IP="${pos[1]}"
      else
        _RECON_USER="${pos[1]}"
        _RECON_IP="${IP:-}"
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
