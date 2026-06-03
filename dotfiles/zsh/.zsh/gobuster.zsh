# ========================
# gobuster helpers
# ========================

GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
GB_THREADS=40

gb-normalize-url() {
  local url="$1"

  # http/https補完
  if [[ "$url" != http*://* ]]; then
    url="http://$url"
  fi

  echo "$url"
}

gb-resolve-target() {
  local target="${1:-${IP:-}}"

  if [[ -z "$target" ]]; then
    echo "usage: target-set <ip>  or pass url/ip as argument" >&2
    return 1
  fi

  echo "$target"
}

gb-set-web() {
  echo "Select Gobuster wordlist:"
  echo "1) raft-small"
  echo "2) raft-medium"
  echo "3) raft-large"
  echo "4) dirbuster-medium"
  echo "5) combined (heavy)"
  read -r choice

  case "$choice" in
    1)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
      ;;
    2)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
      ;;
    3)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
      ;;
    4)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
      ;;
    5)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/combined_directories.txt"
      ;;
    *)
      echo "invalid"
      return 1
      ;;
  esac

  echo "[+] GB_WORDLIST set to:"
  echo "$GB_WORDLIST"
}

gb-set-dns() {
  echo "Select DNS wordlist:"
  echo "1) fast (5000)"
  echo "2) normal (20000)"
  echo "3) heavy (100k bitquark)"
  echo "4) full (combined)"
  echo "5) aggressive (jhaddix)"

  read -r c

  case "$c" in
    1)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
      ;;
    2)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
      ;;
    3)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
      ;;
    4)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/combined_subdomains.txt"
      ;;
    5)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
      ;;
    *)
      echo "invalid"
      return 1
      ;;
  esac

  echo "[+] GB_DNS_WORDLIST set:"
  echo "$GB_DNS_WORDLIST"
}

gb-set-threads() {
  echo "Select threads:"
  echo "1) safe   (10)"
  echo "2) normal (30)"
  echo "3) fast   (60)"
  echo "4) max    (100)"
  read -r c

  case "$c" in
    1) export GB_THREADS=10 ;;
    2) export GB_THREADS=30 ;;
    3) export GB_THREADS=60 ;;
    4) export GB_THREADS=100 ;;
    *) echo "invalid"; return 1 ;;
  esac

  echo "[+] GB_THREADS = $GB_THREADS"
}

gb-dir() {
  local url=""
  local extensions=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -x|--ext)
        extensions="$2"
        shift 2
        ;;
      *)
        url="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$url" ]]; then
    url="$(gb-resolve-target)" || return 1
  fi

  url="$(gb-normalize-url "$url")"

  echo "========================"
  echo "[DIR] $url"
  echo "[*] WORDLIST: $GB_WORDLIST"
  echo "[*] THREADS: $GB_THREADS"
  echo "[*] EXTENSIONS: ${extensions:-none}"
  echo "========================"

  local args=(
    -u "$url"
    -w "$GB_WORDLIST"
    -t "$GB_THREADS"
    -q
  )

  if [[ -n "$extensions" ]]; then
    args+=(--extensions "$extensions")
  fi

  gobuster dir "${args[@]}"
}

gb-dns() {
  local domain=""

  if [[ $# -ge 1 ]]; then
    domain="$1"
  else
    domain="${IP:-}"
  fi

  if [[ -z "$domain" ]]; then
    echo "usage: gb-dns [domain]  (or: target-set <ip>)"
    return 1
  fi

  echo "========================"
  echo "[DNS] $domain"
  echo "[*] WORDLIST: $GB_DNS_WORDLIST"
  echo "========================"

  gobuster dns \
    --domain "$domain" \
    -w "$GB_DNS_WORDLIST" \
    -t "$GB_THREADS" \
    -q
}

gb-vhost() {
  local ip=""

  if [[ $# -ge 1 ]]; then
    ip="$1"
  else
    ip="$(gb-resolve-target)" || return 1
  fi

  echo "=============================="
  echo "[VHOST]"
  echo "[*] TARGET IP: $ip"
  echo "[*] WORDLIST: $GB_WORDLIST"
  echo "[*] THREADS: $GB_THREADS"
  echo "=============================="

  echo "[HTTP] http://$ip"
  echo "------------------------------"

  gobuster vhost \
    -u "http://$ip" \
    -w "$GB_WORDLIST" \
    -t "$GB_THREADS" \
    -q

  echo "------------------------------"
  echo "[HTTPS] https://$ip"
  echo "------------------------------"

  gobuster vhost \
    -u "https://$ip" \
    -k \
    -w "$GB_WORDLIST" \
    -t "$GB_THREADS" \
    -q
}
