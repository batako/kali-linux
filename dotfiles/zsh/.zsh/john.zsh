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

_john_pass_from_show() {
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

_sshkey_pass_from_show() {
  _john_pass_from_show "$1"
}

# Remove per-run john inputs/cache under exports/ (creds live in cl; global ~/.john/john.pot unchanged).
_john_cleanup_workfiles() {
  local hash_file="$1"
  [[ -n "$hash_file" ]] || return 0
  rm -f "$hash_file" "${hash_file}.pot"
}

# gpg2john --show: keyname:passphrase:::uid::file  (not split(':',1))
_gpg_pass_from_show() {
  local show="$1"
  print -r -- "$show" | python3 -c "
import sys
for line in sys.stdin:
    line = line.strip()
    if not line or 'password hash' in line:
        continue
    parts = line.split(':')
    if len(parts) >= 2 and parts[1]:
        print(parts[1])
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

  python3 "$RECON_APP" ssh-last-set "$ip" "$user" >/dev/null 2>&1

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
  echo "[i] connect: ssh -i $key_abs  (passphrase + user from cl)"
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
    local pass user ip

    pass="$(_sshkey_pass_from_show "$show")"
    [[ -z "$pass" ]] && return 0

    if [[ -n "$creds_user" ]]; then
      user="$creds_user"
    else
      user="$(_recon-guess-user-from-key "$key" 2>/dev/null)"
      if [[ -z "$user" ]]; then
        ip="$(_recon-ip-default 2>/dev/null)"
        [[ -n "$ip" ]] && user="$(python3 "$RECON_APP" ssh-last-get "$ip" 2>/dev/null)"
      fi
    fi
    if [[ -z "$user" ]]; then
      echo "[-] creds not saved: could not guess username (use: sshkey-crack -u <user> $key)" >&2
      echo "[i] passphrase: $pass" >&2
      return 0
    fi
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
    _john_cleanup_workfiles "$hash_file"
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
    _john_cleanup_workfiles "$hash_file"
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

  _john_cleanup_workfiles "$hash_file"
  return $rc
}

_hash_crack_first_line() {
  local raw="${1//$'\r'/}"
  local line
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] && print -r -- "$line" && return 0
  done <<<"$raw"
  return 1
}

_hash_crack_slug() {
  local line="$1"
  local user="${line%%:*}"
  if [[ "$line" == *:* && -n "$user" && "$user" != *'$'* && "$user" != *'/'* ]]; then
    echo "${user//[^a-zA-Z0-9._-]/_}.john"
  else
    local slug="${line//[^a-zA-Z0-9._-]/_}"
    echo "hash_${slug:0:48}.john"
  fi
}

_hash_crack_hash_value() {
  local line="$1"
  if [[ "$line" == *:* ]]; then
    print -r -- "${line#*:}"
  else
    print -r -- "$line"
  fi
}

_hash_crack_john_line() {
  local hash_line="$1" creds_user="$2"
  local hash_val="${hash_line#*:}"

  if [[ "$hash_line" == *:* ]]; then
    if [[ "$hash_val" =~ ^[a-fA-F0-9]{32}$ && "${hash_line%%:*}" == *' '* ]]; then
      print -r -- "$hash_val"
      return 0
    fi
    print -r -- "$hash_line"
    return 0
  fi

  if [[ -n "$creds_user" ]]; then
    print -r -- "${creds_user// /_}:${hash_line}"
  else
    print -r -- "$hash_line"
  fi
}

_hash_crack_guess_formats() {
  local hash_val="$1"
  python3 -c "
import re, sys
h = sys.argv[1].strip()
formats = []
if h.startswith('\$apr1\$') or h.startswith('\$1\$'):
    formats = ['md5crypt']
elif h.startswith('\$2a\$') or h.startswith('\$2y\$') or h.startswith('\$2b\$'):
    formats = ['bcrypt']
elif h.startswith('\$6\$'):
    formats = ['sha512crypt']
elif h.startswith('\$5\$'):
    formats = ['sha256crypt']
elif h.startswith('{SSHA}') or h.startswith('{SHA}'):
    formats = ['nsldap', 'raw-SHA1']
elif h.startswith('*') and len(h) == 41:
    formats = ['mysql-sha1', 'mysql']
elif re.fullmatch(r'[a-fA-F0-9]{32}', h):
    formats = ['Raw-MD5', 'dynamic=md5(\$p)', 'NT']
elif re.fullmatch(r'[a-fA-F0-9]{40}', h):
    formats = ['Raw-SHA1']
elif re.fullmatch(r'[a-fA-F0-9]{64}', h):
    formats = ['Raw-SHA256', 'gost']
elif h.startswith('\$6a\$') or h.startswith('\$argon2'):
    formats = ['argon2']
else:
    formats = ['']
for f in formats:
    print(f)
" "$hash_val"
}

_hash_crack_show() {
  local fmt="$1" hf="$2" pf="$3"
  local show="" args=()

  [[ -n "$fmt" ]] && args=(--format="$fmt")
  show="$(john "${args[@]}" --pot="$pf" --show "$hf" 2>/dev/null | sed '/^$/d')"
  if [[ -z "$show" || "$show" == *"0 password hashes cracked"* ]]; then
    show="$(john "${args[@]}" --show "$hf" 2>/dev/null | sed '/^$/d')"
  fi
  print -r -- "$show"
}

_hash_crack_cracked_p() {
  local show="$1"
  [[ -n "$(_john_pass_from_show "$show")" ]]
}

_hash_crack_try_all_formats() {
  local hash_val="$1" hf="$2" pf="$3" wl="$4"
  local fmt tried=0 cracked="" rc=1

  while IFS= read -r fmt; do
    (( tried++ ))
    if [[ -n "$fmt" ]]; then
      echo "[*] john --format=$fmt ..." >&2
      john --format="$fmt" "$hf" --wordlist="$wl" --pot="$pf" 2>&1 \
        | grep -Ev '^(Warning:|Using default|Will run|Press |$| \d+g \d+:|Session completed|Use the )' >&2 || true
    else
      echo "[*] john (auto format) ..." >&2
      john "$hf" --wordlist="$wl" --pot="$pf" 2>&1 \
        | grep -Ev '^(Warning:|Using default|Will run|Press |$| \d+g \d+:|Session completed|Use the )' >&2 || true
    fi
    cracked="$(_hash_crack_show "$fmt" "$hf" "$pf")"
    if _hash_crack_cracked_p "$cracked"; then
      rc=0
      break
    fi
    cracked=""
  done < <(_hash_crack_guess_formats "$hash_val")

  print -r -- "$cracked"
  return $rc
}

_hash_crack_apply_creds() {
  local show="$1" user="$2"
  local pass ip creds_status

  pass="$(_john_pass_from_show "$show")"
  [[ -z "$pass" ]] && return 0

  user="${user:-${show%%:*}}"
  [[ "$user" == '?' ]] && user=""
  [[ -z "$user" || "$user" == *'$'* ]] && return 0

  ip="${IP:-}"
  if [[ -z "$ip" ]]; then
    echo "[-] creds not saved: ts <ip> first (use: cl)" >&2
    return 0
  fi

  creds_status="$(python3 "$RECON_APP" creds-add "$ip" "$user" "$pass" 2>&1)" || return 1
  echo ""
  echo "----- recon -----"
  case "$creds_status" in
    unchanged) echo "[=] creds unchanged: ${user}@${ip}" ;;
    updated)   echo "[~] creds updated: ${user}@${ip}" ;;
    *)         echo "[+] creds saved: ${user}@${ip}" ;;
  esac
  echo "    password: $pass"
}

# john wordlist crack for a hash line (htpasswd/shadow/etc.)
# usage: hash-crack [-f] [-b] [-u user] [-] <hash|file|url> [wordlist]
#   hash-crack -b http://$IP/etc/squid/passwd   # creds-add as borg@$IP (borg-crack 用)
#   hash-crack 'music_archive:$apr1$...'
#   hash-crack squid.pass
#   curl -sS ... | hash-crack -
# -f: ignore this hash's pot and re-run wordlist
# -b: creds-add ユーザを $RECON_BORG_CREDS_USER（既定 borg）にする
# -u: username when hash is hash-only; also used for creds-add on success
hash-crack() {
  local force=0
  local creds_user=""
  local from_stdin=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f) force=1; shift ;;
      -b) creds_user="${RECON_BORG_CREDS_USER:-borg}"; shift ;;
      -u) creds_user="$2"; shift 2 ;;
      -h|--help)
        echo "usage: hash-crack [-f] [-b] [-u user] [-] <hash|file|url> [wordlist]"
        echo "  default wordlist: \$RECON_PASSLIST"
        echo "  -f  force re-crack (ignore this hash's pot)"
        echo "  -b  save creds as \$RECON_BORG_CREDS_USER (default: borg) for borg-crack"
        echo "  -u  username for hash-only input; creds-add on success"
        echo "  -   read hash line from stdin"
        echo "  auto-tries john --format by hash shape (e.g. 32 hex -> Raw-MD5)"
        echo ""
        echo "examples:"
        echo "  hash-crack -b http://\$IP/etc/squid/passwd"
        echo "  hash-crack 'music_archive:\$apr1\$...'"
        echo "  curl -sS http://\$IP/etc/shadow | hash-crack -"
        return 0
        ;;
      -)
        from_stdin=1
        shift
        break
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $from_stdin -eq 0 && $# -lt 1 ]]; then
    echo "usage: hash-crack [-f] [-b] [-u user] [-] <hash|file|url> [wordlist]"
    return 1
  fi

  local input="${1:-}"
  local wordlist="${2:-$RECON_PASSLIST}"
  if [[ $from_stdin -eq 0 && -f "$input" && $# -ge 2 && -f "$2" ]]; then
    wordlist="$2"
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  if ! command -v john >/dev/null 2>&1; then
    echo "john not found (install john)"
    return 1
  fi

  local hash_src="" hash_line="" source_label=""
  if (( from_stdin )); then
    hash_src="$(cat)"
    source_label="stdin"
  elif [[ "$input" == http://* || "$input" == https://* ]]; then
    hash_src="$(curl -fsSL "$input")" || {
      echo "curl failed: $input" >&2
      return 1
    }
    source_label="$input"
  elif [[ -f "$input" ]]; then
    hash_src="$(<"$input")"
    source_label="$input"
  else
    hash_src="$input"
    source_label="argument"
  fi

  hash_line="$(_hash_crack_first_line "$hash_src")" || {
    echo "[-] empty hash input" >&2
    return 1
  }

  if [[ -z "$creds_user" && "$hash_line" == *:* && "$hash_line" != *'$'* ]]; then
    creds_user="${hash_line%%:*}"
  fi

  local hash_val john_line
  hash_val="$(_hash_crack_hash_value "$hash_line")"
  john_line="$(_hash_crack_john_line "$hash_line" "$creds_user")"

  local out_dir hash_file pot_file base formats=()
  out_dir="$(case-exports-dir)" || return 1
  mkdir -p "$out_dir"

  if [[ -f "$input" && $from_stdin -eq 0 && "$input" != http://* && "$input" != https://* ]]; then
    base="${input:t}.john"
  else
    base="$(_hash_crack_slug "$john_line")"
  fi
  hash_file="${out_dir}/${base}"
  pot_file="${hash_file}.pot"

  print -r -- "$john_line" >"$hash_file"
  formats=("${(@f)$(_hash_crack_guess_formats "$hash_val")}")

  echo "[*] source:   $source_label"
  echo "[*] hash:     $hash_file"
  echo "[*] pot:      $pot_file"
  echo "[*] wordlist: $wordlist"
  if (( ${#formats[@]} )); then
    echo "[*] formats:  ${formats[*]}"
  else
    echo "[*] formats:  (auto)"
  fi
  echo ""

  local fmt global_show=""
  for fmt in "${formats[@]}"; do
    [[ -n "$fmt" ]] || continue
    global_show="$(john --format="$fmt" --show "$hash_file" 2>/dev/null | sed '/^$/d')"
    if _hash_crack_cracked_p "$global_show"; then
      break
    fi
    global_show=""
  done
  if [[ -z "$global_show" ]]; then
    global_show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
  fi
  if _hash_crack_cracked_p "$global_show" && [[ $force -eq 0 ]]; then
    echo "[+] already cracked (global john pot):"
    echo "$global_show"
    _hash_crack_apply_creds "$global_show" "$creds_user"
    echo ""
    echo "[i] isolated re-crack: hash-crack -f ${(q)hash_line}"
    _john_cleanup_workfiles "$hash_file"
    return 0
  fi

  local prior fmt_prior
  prior=""
  for fmt_prior in "${formats[@]}"; do
    prior="$(_hash_crack_show "$fmt_prior" "$hash_file" "$pot_file")"
    if _hash_crack_cracked_p "$prior"; then
      break
    fi
    prior=""
  done
  if [[ -z "$prior" ]]; then
    prior="$(_hash_crack_show "" "$hash_file" "$pot_file")"
  fi
  if _hash_crack_cracked_p "$prior" && [[ $force -eq 0 ]]; then
    echo "[+] already cracked (this hash's pot):"
    echo "$prior"
    _hash_crack_apply_creds "$prior" "$creds_user"
    echo ""
    echo "[i] run again: hash-crack -f ${(q)hash_line}"
    _john_cleanup_workfiles "$hash_file"
    return 0
  fi

  [[ $force -eq 1 ]] && rm -f "$pot_file"

  local cracked rc
  cracked="$(_hash_crack_try_all_formats "$hash_val" "$hash_file" "$pot_file" "$wordlist")"
  rc=$?

  echo ""
  if _hash_crack_cracked_p "$cracked"; then
    echo "[+] cracked:"
    print -r -- "$cracked"
    local pass
    pass="$(_john_pass_from_show "$cracked")"
    [[ -n "$pass" ]] && echo "[+] password: $pass"
    _hash_crack_apply_creds "$cracked" "$creds_user"
  else
    echo "[-] no password found" >&2
    [[ -n "$cracked" ]] && print -r -- "$cracked"
    rc=1
  fi

  _john_cleanup_workfiles "$hash_file"
  return $rc
}

_gpg2john_path() {
  local p
  p="$(command -v gpg2john 2>/dev/null)" && [[ -n "$p" ]] && echo "$p" && return 0
  return 1
}

_gpg_crack_credential_default() {
  local key="$1"
  local dir="${key:h}"
  local f

  for f in credential.pgp credentials.pgp; do
    [[ -f "$dir/$f" ]] && { echo "$dir/$f"; return 0 }
  done
  return 1
}

_gpg_crack_parse_creds() {
  local text="$1"
  print -r -- "$text" | python3 -c "
import sys
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith('-----'):
        continue
    if ':' not in line:
        continue
    user, _, passwd = line.partition(':')
    user, passwd = user.strip(), passwd.strip()
    if user and passwd:
        print(user)
        print(passwd)
        break
"
}

_gpg_crack_import_creds() {
  local user="$1" pass="$2"
  local ip="${IP:-}"
  local creds_status

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
  echo "[i] connect: ssh $user  (or: su $user)"
}

_gpg_crack_decrypt() {
  local key="$1" cred="$2" gpg_pass="$3"
  local gnupg plain user pass

  if [[ ! -f "$cred" ]]; then
    echo "[-] credential file not found: $cred" >&2
    return 1
  fi

  gnupg="$(mktemp -d "${TMPDIR:-/tmp}/gpg-crack.XXXXXX")"
  chmod 700 "$gnupg"

  if ! gpg --homedir "$gnupg" --batch --yes --pinentry-mode loopback \
      --passphrase "$gpg_pass" --import "$key" >/dev/null 2>&1; then
    echo "[-] gpg --import failed (bad passphrase?)" >&2
    rm -rf "$gnupg"
    return 1
  fi

  plain="$(gpg --homedir "$gnupg" --batch --yes --pinentry-mode loopback \
      --passphrase "$gpg_pass" -d "$cred" 2>/dev/null)" || {
    echo "[-] gpg --decrypt failed: $cred" >&2
    rm -rf "$gnupg"
    return 1
  }
  rm -rf "$gnupg"

  echo ""
  echo "[+] decrypted:"
  print -r -- "$plain"

  local -a parsed
  parsed=("${(@f)$(_gpg_crack_parse_creds "$plain")}")
  user="${parsed[1]}"
  pass="${parsed[2]}"
  if [[ -n "$user" && -n "$pass" ]]; then
    _gpg_crack_import_creds "$user" "$pass"
    return 0
  fi

  echo "[-] could not parse user:pass from decrypted text (use: ca <user> <pass>)" >&2
  return 1
}

# gpg2john + john; optional gpg decrypt + creds-add from credential.pgp
# usage: gpg-crack [-f] [-n] [-c credential.pgp] <key.asc> [wordlist]
#   x "gpg-crack tryhackme.asc"
# -f: force re-crack (ignore pot)
# -n: crack only (no gpg --decrypt / creds-add)
# -c: credential file (default: credential.pgp beside key.asc)
gpg-crack() {
  local force=0
  local do_decrypt=1
  local cred_file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f) force=1; shift ;;
      -n) do_decrypt=0; shift ;;
      -c) cred_file="$2"; shift 2 ;;
      -h|--help)
        echo "usage: gpg-crack [-f] [-n] [-c credential.pgp] <key.asc> [wordlist]"
        echo "  default wordlist: \$RECON_PASSLIST"
        echo "  default credential: credential.pgp beside <key.asc>"
        echo "  on success: gpg --decrypt → creds-add (cl) when user:pass in plaintext"
        return 0
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -lt 1 ]]; then
    echo "usage: gpg-crack [-f] [-n] [-c credential.pgp] <key.asc> [wordlist]"
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

  local gpg2john
  gpg2john="$(_gpg2john_path)" || {
    echo "gpg2john not found (install john)"
    return 1
  }

  if ! command -v john >/dev/null 2>&1; then
    echo "john not found (install john)"
    return 1
  fi

  if (( do_decrypt )) && ! command -v gpg >/dev/null 2>&1; then
    echo "gpg not found"
    return 1
  fi

  if (( do_decrypt )) && [[ -z "$cred_file" ]]; then
    cred_file="$(_gpg_crack_credential_default "$key")" || true
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
  (( do_decrypt )) && [[ -n "$cred_file" ]] && echo "[*] cred:     $cred_file"
  echo ""

  "$gpg2john" "$key" >"$hash_file" || return 1

  _gpg_crack_show() {
    local show
    show="$(john --pot="$pot_file" --show "$hash_file" 2>/dev/null | sed '/^$/d')"
    if [[ -z "$show" || "$show" == *"0 password hashes cracked"* ]]; then
      show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
    fi
    print -r -- "$show"
  }

  local global_show
  global_show="$(john --show "$hash_file" 2>/dev/null | sed '/^$/d')"
  if [[ -n "$global_show" && "$global_show" != *"0 password hashes cracked"* && $force -eq 0 ]]; then
    echo "[+] already cracked (global john pot):"
    echo "$global_show"
    local pass
    pass="$(_gpg_pass_from_show "$global_show")"
    [[ -n "$pass" ]] && echo "[+] gpg passphrase: $pass"
    if (( do_decrypt )) && [[ -n "$cred_file" && -n "$pass" ]]; then
      _gpg_crack_decrypt "$key" "$cred_file" "$pass"
    fi
    echo ""
    echo "[i] isolated re-crack: gpg-crack -f $key"
    _john_cleanup_workfiles "$hash_file"
    return 0
  fi

  local prior
  prior="$(_gpg_crack_show)"
  if [[ -n "$prior" && "$prior" != *"0 password hashes cracked"* && $force -eq 0 ]]; then
    echo "[+] already cracked (this key's pot):"
    echo "$prior"
    local pass
    pass="$(_gpg_pass_from_show "$prior")"
    [[ -n "$pass" ]] && echo "[+] gpg passphrase: $pass"
    if (( do_decrypt )) && [[ -n "$cred_file" && -n "$pass" ]]; then
      _gpg_crack_decrypt "$key" "$cred_file" "$pass"
    fi
    echo ""
    echo "[i] run again: gpg-crack -f $key"
    _john_cleanup_workfiles "$hash_file"
    return 0
  fi

  [[ $force -eq 1 ]] && rm -f "$pot_file"

  john "$hash_file" --wordlist="$wordlist" --pot="$pot_file"
  local rc=$?

  echo ""
  local cracked
  cracked="$(_gpg_crack_show)"
  echo "[+] cracked (if any):"
  print -r -- "$cracked"

  local pass
  pass="$(_gpg_pass_from_show "$cracked")"
  if [[ -n "$pass" ]]; then
    echo "[+] gpg passphrase: $pass"
    if (( do_decrypt )) && [[ -n "$cred_file" ]]; then
      _gpg_crack_decrypt "$key" "$cred_file" "$pass" || rc=1
    elif (( do_decrypt )); then
      echo "[-] no credential.pgp beside key (use: gpg-crack -c <file> $key)" >&2
      rc=1
    fi
  elif (( rc == 0 )); then
    echo "[-] john finished but no passphrase found" >&2
    rc=1
  fi

  _john_cleanup_workfiles "$hash_file"
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

_zip_crack_extract() {
  local zip="$1" extract_dir="$2" pass="${3:-}"
  mkdir -p "$extract_dir"
  echo "[*] extracting with 7z..."
  if [[ -n "$pass" ]]; then
    7z x "$zip" -p"$pass" -o"$extract_dir" -y
  else
    7z x "$zip" -o"$extract_dir" -y
  fi
}

_zip_crack_encrypted_p() {
  local zip2john_out="$1"
  [[ -n "$zip2john_out" ]] || return 1
  if print -r -- "$zip2john_out" | grep -qiE 'is not encrypted|not encrypted'; then
    return 1
  fi
  print -r -- "$zip2john_out" | grep -qE 'PKZIP Encr|\$pkzip|\$zip2\$'
}

# zip2john + john; extract with 7z on success
# usage: zip-crack [-f] [-n] <zipfile> [wordlist]
#   x "zip-crack 8702.zip"
# -f: ignore prior crack in this zip's pot and run wordlist again
# -n: crack only, do not run 7z extract
# unencrypted zip: skips john, 7z extract without password
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
        echo "  unencrypted zip: 7z extract without john"
        echo "  on success: 7z x [-p<pass>] -o <exports>/<zip-basename>/"
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

  local zip2john
  zip2john="$(_zip2john_path)" || {
    echo "zip2john not found (install john)"
    return 1
  }

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
  local zip2john_out=""

  echo "[*] zip:      $zip"
  (( do_extract )) && echo "[*] extract:  $extract_dir (7z)"
  echo ""

  zip2john_out="$("$zip2john" "$zip" 2>&1)" || return 1
  print -r -- "$zip2john_out" >"$hash_file"

  if ! _zip_crack_encrypted_p "$zip2john_out"; then
    echo "[+] zip: not encrypted"
    if (( do_extract )); then
      echo ""
      if _zip_crack_extract "$zip" "$extract_dir"; then
        echo "[+] extracted to: $extract_dir"
        ls -la "$extract_dir"
      else
        echo "[-] 7z extract failed" >&2
        _john_cleanup_workfiles "$hash_file"
        return 1
      fi
    fi
    _john_cleanup_workfiles "$hash_file"
    return 0
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  if ! command -v john >/dev/null 2>&1; then
    echo "john not found (install john)"
    return 1
  fi

  echo "[*] hash:     $hash_file"
  echo "[*] pot:      $pot_file"
  echo "[*] wordlist: $wordlist"
  echo ""

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
      if _zip_crack_extract "$zip" "$extract_dir" "$pass"; then
        echo "[+] extracted to: $extract_dir"
        ls -la "$extract_dir"
      else
        echo "[-] 7z extract failed" >&2
        _john_cleanup_workfiles "$hash_file"
        return 1
      fi
    fi
    echo ""
    echo "[i] isolated re-crack: zip-crack -f $zip"
    _john_cleanup_workfiles "$hash_file"
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
      if _zip_crack_extract "$zip" "$extract_dir" "$pass"; then
        echo "[+] extracted to: $extract_dir"
        ls -la "$extract_dir"
      else
        echo "[-] 7z extract failed" >&2
        _john_cleanup_workfiles "$hash_file"
        return 1
      fi
    fi
    echo ""
    echo "[i] run again: zip-crack -f $zip"
    _john_cleanup_workfiles "$hash_file"
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
      if _zip_crack_extract "$zip" "$extract_dir" "$pass"; then
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

  _john_cleanup_workfiles "$hash_file"
  return $rc
}
