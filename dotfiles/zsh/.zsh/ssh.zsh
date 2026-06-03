# ========================
# SSH (recon creds + sshpass)
# ========================

_ssh-bin() {
  whence -p ssh 2>/dev/null || echo /usr/bin/ssh
}

_ssh-ip-re() {
  echo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

_ssh-creds-json() {
  python3 "$RECON_APP" creds-list --json "$1" 2>/dev/null
}

_ssh-has-creds() {
  local ip="$1" json
  json="$(_ssh-creds-json "$ip")"
  [[ -n "$json" && "$json" != "[]" ]]
}

_ssh-pick-user() {
  local ip="$1"
  local json users i choice last idx

  json="$(_ssh-creds-json "$ip")"
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

_ssh-creds-for-user() {
  local ip="$1" user="$2"
  print -r -- "$(_ssh-creds-json "$ip")" | python3 -c "
import json, sys
user = sys.argv[1]
for r in json.load(sys.stdin):
    if r['username'] == user:
        print(r['password'])
        break
" "$user"
}

ssh-login() {
  local ip="" user="" pass=""
  local -a rest=()
  local -a pos=()
  local a

  if [[ "${1:-}" == -* ]]; then
    command ssh "$@"
    return
  fi

  for a in "$@"; do
    if [[ "$a" == -* ]]; then
      rest+=("$a")
    else
      pos+=("$a")
    fi
  done

  case ${#pos[@]} in
    0)
      ip="${IP:-}"
      ;;
    1)
      if [[ "${pos[1]}" == *@* ]]; then
        user="${pos[1]%%@*}"
        ip="${pos[1]#*@}"
      elif [[ "${pos[1]}" =~ $(_ssh-ip-re) ]]; then
        ip="${pos[1]}"
      else
        user="${pos[1]}"
        ip="${IP:-}"
      fi
      ;;
    2)
      if [[ "${pos[1]}" =~ $(_ssh-ip-re) ]]; then
        ip="${pos[1]}"
        user="${pos[2]}"
      else
        user="${pos[1]}"
        ip="${pos[2]}"
      fi
      ;;
    *)
      user="${pos[1]}"
      ip="${pos[2]}"
      rest+=("${pos[@]:3}")
      ;;
  esac

  if [[ -z "$ip" ]]; then
    echo "usage: ssh [user] [ip]  (or: target-set <ip> first)" >&2
    echo "  saved creds: ssh / ssh user / ssh user@ip — plain: command ssh ..." >&2
    return 1
  fi

  if [[ -z "$user" ]]; then
    user="$(_ssh-pick-user "$ip")" || return 1
  fi

  pass="$(_ssh-creds-for-user "$ip" "$user")"
  if [[ -z "$pass" ]]; then
    echo "[-] no saved password for ${user}@${ip}" >&2
    command ssh "${user}@${ip}" "${rest[@]}"
    return 1
  fi

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[-] sshpass not installed" >&2
    return 1
  fi

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1

  echo "[+] connecting: ${user}@${ip}" >&2
  SSHPASS="$pass" sshpass -e "$(_ssh-bin)" \
    -o StrictHostKeyChecking=accept-new \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "${user}@${ip}" "${rest[@]}"
}

ssh() {
  local ip="" a

  if [[ "${1:-}" == -* ]]; then
    command ssh "$@"
    return
  fi

  for a in "$@"; do
    if [[ "$a" != -* && "$a" == *@* ]]; then
      ip="${a#*@}"
      break
    fi
    if [[ "$a" != -* && "$a" =~ $(_ssh-ip-re) ]]; then
      ip="$a"
      break
    fi
  done
  [[ -z "$ip" ]] && ip="${IP:-}"

  if [[ -n "$ip" ]] && _ssh-has-creds "$ip"; then
    ssh-login "$@"
    return $?
  fi

  command ssh "$@"
}

ssh-list() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: ssh-list [ip]"
    return 1
  fi
  python3 "$RECON_APP" creds-list "$ip"
}
