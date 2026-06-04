# ========================
# SSH (recon creds + sshpass)
# ========================

_ssh-bin() {
  whence -p ssh 2>/dev/null || echo /usr/bin/ssh
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

  _recon-parse-user-ip "${pos[@]}" || {
    echo "usage: ssh [user] [ip]  (or: target-set <ip> first)" >&2
    echo "  saved creds: ssh / ssh user / ssh user@ip — plain: command ssh ..." >&2
    return 1
  }
  ip="$_RECON_IP"
  user="$_RECON_USER"
  (( ${#pos[@]} > 2 )) && rest+=("${pos[@]:3}")

  if [[ -z "$user" ]]; then
    user="$(_recon-pick-user "$ip")" || return 1
  fi

  if ! pass="$(_recon-creds-for-user "$ip" "$user")"; then
    echo "[-] no saved creds for ${user}@${ip}" >&2
    command ssh "${user}@${ip}" "${rest[@]}"
    return 1
  fi
  if [[ -z "$pass" ]]; then
    echo "[-] empty password in db for ${user}@${ip} — use command ssh" >&2
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
    if [[ "$a" != -* && "$a" =~ $(_recon-ip-re) ]]; then
      ip="$a"
      break
    fi
  done
  [[ -z "$ip" ]] && ip="${IP:-}"

  if [[ -n "$ip" ]] && _recon-has-creds "$ip"; then
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
