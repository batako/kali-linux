# ========================
# steghide helpers
# ========================

_steg-bin() {
  command -v steghide 2>/dev/null
}

_stegcracker-bin() {
  command -v stegcracker 2>/dev/null
}

# Non-interactive steghide info (no TTY — steghide exits 1 on the y/n prompt)
_steg-info() {
  local file="$1"
  local bin out
  bin="$(_steg-bin)" || return 1
  out="$(printf 'y\n' | "$bin" info "$file" 2>&1 </dev/null)" || true
  print -r -- "$out"
  print -r -- "$out" | grep -qE 'format:|capacity:'
}

_steg-has-embedded() {
  local info="$1"
  print -r -- "$info" | grep -qiE \
    'embedded (file|data)|size:[[:space:]]*[0-9]+[[:space:]]*byte|can not uncompress'
}

_steg-out-path() {
  local file="$1"
  local home out

  if home="$(case-home 2>/dev/null)"; then
    mkdir -p "$home/exports"
    out="$home/exports/${file:t:r}.steg.out"
  else
    out="${file:h}/${file:t:r}.steg.out"
  fi
  echo "$out"
}

_steg-log-path() {
  local file="$1"
  local logs ts
  logs="$(case-logs-dir 2>/dev/null)" || return 1
  ts="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$logs"
  echo "$logs/steg_${file:t:r}_${ts}.log"
}

# Wordlist crack via stegcracker, or steghide loop if stegcracker missing
_steg-crack() {
  local file="$1" wordlist="$2" out="$3"
  local bin pass

  bin="$(_stegcracker-bin)"
  if [[ -n "$bin" ]]; then
    echo "[*] stegcracker: $wordlist" >&2
    # progress → stderr (shown live); cracked password → stdout (captured)
    pass="$("$bin" -o "$out" "$file" "$wordlist")" || return 1
    [[ -n "$pass" ]] || return 1
    echo "$pass"
    return 0
  fi

  echo "[!] stegcracker not found — steghide wordlist loop (slow)" >&2
  local steghide="$(_steg-bin)" || return 1
  local n=0
  while read -r pass; do
    (( n++ ))
    (( n % 500 == 0 )) && echo "[*] tried $n passwords (last: $pass)" >&2
    if "$steghide" extract -sf "$file" -p "$pass" -xf "$out" -f 2>/dev/null; then
      echo "$pass"
      return 0
    fi
  done < "$wordlist"
  return 1
}

_steg-show-out() {
  local out="$1" wordlist="${2:-$RECON_PASSLIST}"
  local kind zip_path rc=0

  [[ -f "$out" && -s "$out" ]] || return 1
  kind="$(file -b "$out" 2>/dev/null)"

  echo "[+] type: $kind"
  case "$kind" in
    *Zip\ archive*)
      zip_path="${out:h}/${out:t:r}.zip"
      if [[ "$out" != "$zip_path" ]]; then
        cp -f "$out" "$zip_path"
        echo "[+] copied: $zip_path"
      else
        zip_path="$out"
      fi
      if (( $+functions[zip-crack] )); then
        echo ""
        zip-crack "$zip_path" "$wordlist"
        rc=$?
      else
        echo "[i] next: zip-crack ${zip_path:t}" >&2
      fi
      return $rc
      ;;
    *ASCII*|*text*)
      echo "-----"
      cat "$out"
      ;;
    *)
      echo "[i] binary output — inspect with: file $out"
      ;;
  esac
  return 0
}

# info → (optional crack) → extract
# usage: steg-extract <image> [wordlist]
#   default wordlist: $RECON_PASSLIST
#   output: cases/.../exports/<name>.steg.out (or beside image if no case)
steg-extract() {
  local wordlist="$RECON_PASSLIST"
  local file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: steg-extract <image> [wordlist]"
        echo "  1. steghide info (embedded data check)"
        echo "  2. try empty passphrase extract"
        echo "  3. stegcracker + wordlist if needed"
        echo "  default wordlist: \$RECON_PASSLIST"
        echo "  output: cases/<case>/exports/<name>.steg.out"
        echo "  zip output: auto zip-crack + 7z extract"
        return 0
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        if [[ -z "$file" ]]; then
          file="$1"
        else
          wordlist="$1"
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$file" ]]; then
    echo "usage: steg-extract <image> [wordlist]"
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "[-] file not found: $file" >&2
    return 1
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "[-] wordlist not found: $wordlist" >&2
    return 1
  fi

  local steghide info out pass logfile steg_rc=0
  steghide="$(_steg-bin)" || {
    echo "[-] steghide not installed" >&2
    return 1
  }

  file="$(realpath "$file" 2>/dev/null || echo "$file")"
  out="$(_steg-out-path "$file")"
  rm -f "$out"

  if ! info="$(_steg-info "$file")"; then
    echo "[-] steghide info failed (is steghide installed?)" >&2
    return 1
  fi

  echo "========================"
  echo "[STEG] $file"
  print -r -- "$info"
  echo "========================"

  if logfile="$(_steg-log-path "$file" 2>/dev/null)"; then
    {
      echo "file: $file"
      echo "wordlist: $wordlist"
      echo "out: $out"
      echo "--- steghide info ---"
      print -r -- "$info"
    } >"$logfile"
    echo "[*] log: $logfile" >&2
  fi

  if ! _steg-has-embedded "$info"; then
    echo "[!] no embedded data reported — trying extract anyway" >&2
  fi

  local steg_rc=0
  echo "[*] trying empty passphrase..." >&2
  if "$steghide" extract -sf "$file" -p "" -xf "$out" -f 2>/dev/null && [[ -s "$out" ]]; then
    echo "[+] extracted (no passphrase)"
    echo "[+] out: $out"
    _steg-show-out "$out" "$wordlist" || steg_rc=$?
    return $steg_rc
  fi
  rm -f "$out"

  echo "[*] passphrase required — cracking..." >&2
  if ! pass="$(_steg-crack "$file" "$wordlist" "$out")"; then
    echo "[-] crack failed (wordlist exhausted)" >&2
    return 1
  fi

  if [[ ! -s "$out" ]]; then
    # stegcracker may have written; re-extract if empty
    "$steghide" extract -sf "$file" -p "$pass" -xf "$out" -f 2>/dev/null || true
  fi

  echo "[+] passphrase: $pass"
  echo "[+] out: $out"
  _steg-show-out "$out" "$wordlist" || steg_rc=$?
  return $steg_rc
}

alias stegx='steg-extract'
