# ========================
# gobuster helpers
# ========================

# gb-vhost only; dir scans use scout -d / scout -ds
GB_VHOST_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
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
  local target="${1:-}"

  if [[ -z "$target" ]]; then
    target="${IP:-}"
    [[ -z "$target" ]] && target="$(target-current 2>/dev/null)"
  fi

  if [[ -z "$target" ]]; then
    echo "usage: target-set <ip>  or pass url/ip as argument" >&2
    return 1
  fi

  echo "$target"
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

gb-dirs() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "deprecated: use scout -ds (alias: s -ds)"
    echo ""
    echo "usage: scout -ds [-p ctf|fast|deep] [-w id]... [-t N] [-x ext] [-n] [path|url]"
    echo "  presets (catalog):"
    echo "    ctf  — common + raft-small-directories + quickhits (default)"
    echo "    fast — common + quickhits"
    echo "    deep — ctf + raft-small-files (4 jobs; use lower -t)"
    echo ""
    echo "examples:"
    echo "  s -ds"
    echo "  s -ds /island"
    echo "  s -ds -p fast -n"
    return 0
  fi
  echo "[!] gb-dirs is deprecated — use: scout -ds (s -ds)" >&2
  scout -ds "$@"
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
  echo "[*] WORDLIST: $GB_VHOST_WORDLIST"
  echo "[*] THREADS: $GB_THREADS"
  echo "=============================="

  echo "[HTTP] http://$ip"
  echo "------------------------------"

  gobuster vhost \
    -u "http://$ip" \
    -w "$GB_VHOST_WORDLIST" \
    -t "$GB_THREADS" \
    -q

  echo "------------------------------"
  echo "[HTTPS] https://$ip"
  echo "------------------------------"

  gobuster vhost \
    -u "https://$ip" \
    -k \
    -w "$GB_VHOST_WORDLIST" \
    -t "$GB_THREADS" \
    -q
}
