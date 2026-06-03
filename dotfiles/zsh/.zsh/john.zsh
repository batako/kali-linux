# ========================
# john / hash helpers
# ========================

_ssh2john_path() {
  if [[ -f /usr/share/john/ssh2john.py ]]; then
    echo /usr/share/john/ssh2john.py
    return 0
  fi
  local p
  p="$(command -v ssh2john.py 2>/dev/null)" && [[ -n "$p" ]] && echo "$p" && return 0
  p="$(command -v ssh2john 2>/dev/null)" && [[ -n "$p" ]] && echo "$p" && return 0
  return 1
}

# ssh2john + john wordlist crack for private keys
# usage: sshkey-crack [-f] <keyfile> [wordlist]
#   x "sshkey-crack id_rsa"
# -f: ignore prior crack in this hash's pot and run wordlist again
sshkey-crack() {
  local force=0
  if [[ "${1:-}" == "-f" ]]; then
    force=1
    shift
  fi

  if [[ $# -lt 1 ]]; then
    echo "usage: sshkey-crack [-f] <keyfile> [wordlist]"
    echo "  default wordlist: \$RECON_PASSLIST"
    return 1
  fi

  local key="$1"
  local wordlist="${2:-$RECON_PASSLIST}"

  if [[ ! -f "$key" ]]; then
    echo "key not found: $key"
    return 1
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local ssh2john
  ssh2john="$(_ssh2john_path)" || {
    echo "ssh2john not found (install john)"
    return 1
  }

  if ! command -v john >/dev/null 2>&1; then
    echo "john not found (install john)"
    return 1
  fi

  local out_dir="${RECON_HOME:-/workspace/recon}/exports"
  mkdir -p "$out_dir"

  local base="${key:t}"
  local hash_file="${out_dir}/${base}.john"
  local pot_file="${hash_file}.pot"

  echo "[*] key:      $key"
  echo "[*] hash:     $hash_file"
  echo "[*] pot:      $pot_file"
  echo "[*] wordlist: $wordlist"
  echo ""

  python3 "$ssh2john" "$key" >"$hash_file" || return 1

  _sshkey_show() {
    john --pot="$pot_file" --show "$hash_file" 2>/dev/null | sed '/^$/d'
  }

  # Global ~/.john/john.pot may already have this hash (manual john hash.txt runs).
  local global_show
  global_show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
  if [[ -n "$global_show" && "$global_show" != *"0 password hashes cracked"* ]]; then
    echo "[+] already cracked (global john pot):"
    echo "$global_show"
    echo ""
    echo "[i] isolated re-crack: sshkey-crack -f $key"
    echo "[i] or show manual hash: john --show hash.txt"
    return 0
  fi

  local prior
  prior="$(_sshkey_show)"
  if [[ -n "$prior" && "$prior" != *"0 password hashes cracked"* && $force -eq 0 ]]; then
    echo "[+] already cracked (this key's pot):"
    echo "$prior"
    echo ""
    echo "[i] run again: sshkey-crack -f $key"
    return 0
  fi

  [[ $force -eq 1 ]] && rm -f "$pot_file"

  john "$hash_file" --wordlist="$wordlist" --pot="$pot_file"
  local rc=$?

  echo ""
  echo "[+] cracked (if any):"
  _sshkey_show

  echo ""
  echo "[+] hash file: $hash_file"

  return $rc
}
