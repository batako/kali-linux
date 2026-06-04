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

_sshkey_pass_from_show() {
  local show="$1"
  print -r -- "$show" | python3 -c "
import sys
for line in sys.stdin:
    line = line.strip()
    if not line or '0 password hashes' in line:
        continue
    if ':' in line:
        print(line.split(':', 1)[1])
        break
"
}

_sshkey_import_creds() {
  local key="$1" user="$2" pass="$3"
  local ip="${IP:-}"
  local creds_status
  local key_abs

  if [[ -f "$key" ]]; then
    chmod 600 "$key" 2>/dev/null
    key_abs="$(realpath "$key" 2>/dev/null || echo "$key")"
  else
    key_abs="$key"
  fi

  if [[ -z "$ip" ]]; then
    echo "[-] creds not saved: ts <ip> first, or cs <case> (cases/<case>/target)" >&2
    return 1
  fi
  if [[ -z "$user" || -z "$pass" ]]; then
    return 1
  fi

  creds_status="$(python3 "$RECON_APP" creds-add "$ip" "$user" "$pass" 2>&1)" || return 1

  echo ""
  echo "----- recon -----"
  case "$creds_status" in
    unchanged) echo "[=] creds unchanged: ${user}@${ip}" ;;
    updated)   echo "[~] creds updated: ${user}@${ip}" ;;
    *)         echo "[+] creds saved: ${user}@${ip}" ;;
  esac
  echo "    login:    $user"
  echo "    password: $pass"
  echo "    key:      $key_abs"
  echo "[i] connect: ssh -i $key_abs ${user}@${ip}  (passphrase from cl)"
}

# ssh2john + john wordlist crack for private keys
# usage: sshkey-crack [-f] [-u user] <keyfile> [wordlist]
#   x "sshkey-crack id_rsa"
# -f: ignore prior crack in this hash's pot and run wordlist again
# -u: username for creds (default: guess from key name, e.g. james_rsa -> james)
# on success: creds-add for $IP (cl / ssh)
sshkey-crack() {
  local force=0
  local creds_user=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f) force=1; shift ;;
      -u) creds_user="$2"; shift 2 ;;
      -h|--help)
        echo "usage: sshkey-crack [-f] [-u user] <keyfile> [wordlist]"
        echo "  default wordlist: \$RECON_PASSLIST"
        echo "  on crack: creds-add for \$IP (shows in cl)"
        return 0
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -lt 1 ]]; then
    echo "usage: sshkey-crack [-f] [-u user] <keyfile> [wordlist]"
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

  local out_dir
  out_dir="$(case-exports-dir)" || return 1
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
    local show
    show="$(john --pot="$pot_file" --show "$hash_file" 2>/dev/null | sed '/^$/d')"
    if [[ -z "$show" || "$show" == *"0 password hashes cracked"* ]]; then
      show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
    fi
    print -r -- "$show"
  }

  _sshkey_apply_creds() {
    local show="$1"
    local pass user

    pass="$(_sshkey_pass_from_show "$show")"
    [[ -z "$pass" ]] && return 0

    user="${creds_user:-$(_recon-guess-user-from-key "$key")}" || {
      echo "[-] creds not saved: could not guess username (use: sshkey-crack -u <user> $key)" >&2
      return 0
    }
    _sshkey_import_creds "$key" "$user" "$pass"
  }

  # Global ~/.john/john.pot may already have this hash (manual john hash.txt runs).
  local global_show
  global_show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
  if [[ -n "$global_show" && "$global_show" != *"0 password hashes cracked"* && $force -eq 0 ]]; then
    echo "[+] already cracked (global john pot):"
    echo "$global_show"
    _sshkey_apply_creds "$global_show"
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
    _sshkey_apply_creds "$prior"
    echo ""
    echo "[i] run again: sshkey-crack -f $key"
    return 0
  fi

  [[ $force -eq 1 ]] && rm -f "$pot_file"

  john "$hash_file" --wordlist="$wordlist" --pot="$pot_file"
  local rc=$?

  echo ""
  local cracked
  cracked="$(_sshkey_show)"
  echo "[+] cracked (if any):"
  print -r -- "$cracked"

  if [[ -n "$cracked" && "$cracked" != *"0 password hashes cracked"* ]]; then
    _sshkey_apply_creds "$cracked"
  fi

  echo ""
  echo "[+] hash file: $hash_file"

  return $rc
}

_zip2john_path() {
  local p
  p="$(command -v zip2john 2>/dev/null)" && [[ -n "$p" ]] && echo "$p" && return 0
  if [[ -f /usr/share/john/zip2john.py ]]; then
    echo /usr/share/john/zip2john.py
    return 0
  fi
  return 1
}

# zip2john + john; extract with 7z on success
# usage: zip-crack [-f] [-n] <zipfile> [wordlist]
#   x "zip-crack 8702.zip"
# -f: ignore prior crack in this zip's pot and run wordlist again
# -n: crack only, do not run 7z extract
zip-crack() {
  local force=0
  local do_extract=1

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f) force=1; shift ;;
      -n) do_extract=0; shift ;;
      -h|--help)
        echo "usage: zip-crack [-f] [-n] <zipfile> [wordlist]"
        echo "  default wordlist: \$RECON_PASSLIST"
        echo "  -f  force re-crack (ignore this zip's pot)"
        echo "  -n  crack only (no 7z extract)"
        echo "  on success: 7z x -p<pass> -o <exports>/<zip-basename>/"
        return 0
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -lt 1 ]]; then
    echo "usage: zip-crack [-f] [-n] <zipfile> [wordlist]"
    return 1
  fi

  local zip="$1"
  local wordlist="${2:-$RECON_PASSLIST}"

  if [[ ! -f "$zip" ]]; then
    echo "zip not found: $zip"
    return 1
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local zip2john
  zip2john="$(_zip2john_path)" || {
    echo "zip2john not found (install john)"
    return 1
  }

  if ! command -v john >/dev/null 2>&1; then
    echo "john not found (install john)"
    return 1
  fi

  if (( do_extract )) && ! command -v 7z >/dev/null 2>&1; then
    echo "7z not found (install 7zip)"
    return 1
  fi

  local out_dir
  out_dir="$(case-exports-dir)" || return 1
  mkdir -p "$out_dir"

  local base="${zip:t}"
  local hash_file="${out_dir}/${base}.john"
  local pot_file="${hash_file}.pot"
  local extract_dir="${out_dir}/${base:r}"

  echo "[*] zip:      $zip"
  echo "[*] hash:     $hash_file"
  echo "[*] pot:      $pot_file"
  echo "[*] wordlist: $wordlist"
  (( do_extract )) && echo "[*] extract:  $extract_dir (7z)"
  echo ""

  "$zip2john" "$zip" >"$hash_file" || return 1

  _zip_crack_show() {
    john --pot="$pot_file" --show "$hash_file" 2>/dev/null | sed '/^$/d'
  }

  _zip_crack_password() {
    local show
    show="$(_zip_crack_show)"
    if [[ -z "$show" || "$show" == *"0 password hashes cracked"* ]]; then
      show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
    fi
    print -r -- "$show" | python3 -c "
import sys
for line in sys.stdin:
    line = line.strip()
    if not line or '0 password hashes' in line:
        continue
    parts = line.split(':')
    if len(parts) >= 2 and parts[1]:
        print(parts[1])
        break
"
  }

  local global_show
  global_show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
  if [[ -n "$global_show" && "$global_show" != *"0 password hashes cracked"* ]]; then
    echo "[+] already cracked (global john pot):"
    echo "$global_show"
    local pass
    pass="$(_zip_crack_password)"
    if (( do_extract )) && [[ -n "$pass" ]]; then
      mkdir -p "$extract_dir"
      echo ""
      echo "[*] extracting with 7z..."
      7z x "$zip" -p"$pass" -o"$extract_dir" -y
      echo "[+] extracted to: $extract_dir"
      ls -la "$extract_dir"
    fi
    echo ""
    echo "[i] isolated re-crack: zip-crack -f $zip"
    return 0
  fi

  local prior
  prior="$(_zip_crack_show)"
  if [[ -n "$prior" && "$prior" != *"0 password hashes cracked"* && $force -eq 0 ]]; then
    echo "[+] already cracked (this zip's pot):"
    echo "$prior"
    local pass
    pass="$(_zip_crack_password)"
    if (( do_extract )) && [[ -n "$pass" ]]; then
      mkdir -p "$extract_dir"
      echo ""
      echo "[*] extracting with 7z..."
      7z x "$zip" -p"$pass" -o"$extract_dir" -y
      echo "[+] extracted to: $extract_dir"
      ls -la "$extract_dir"
    fi
    echo ""
    echo "[i] run again: zip-crack -f $zip"
    return 0
  fi

  [[ $force -eq 1 ]] && rm -f "$pot_file"

  john "$hash_file" --wordlist="$wordlist" --pot="$pot_file"
  local rc=$?

  echo ""
  echo "[+] cracked (if any):"
  _zip_crack_show

  local pass
  pass="$(_zip_crack_password)"
  if [[ -n "$pass" ]]; then
    echo ""
    echo "[+] zip password: $pass"
    if (( do_extract )); then
      mkdir -p "$extract_dir"
      echo "[*] extracting with 7z..."
      if 7z x "$zip" -p"$pass" -o"$extract_dir" -y; then
        echo "[+] extracted to: $extract_dir"
        ls -la "$extract_dir"
      else
        echo "[-] 7z extract failed" >&2
        rc=1
      fi
    fi
  elif (( rc == 0 )); then
    echo "[-] john finished but no password found" >&2
    rc=1
  fi

  echo ""
  echo "[+] hash file: $hash_file"

  return $rc
}
