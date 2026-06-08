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
  bin="$(_steg-bin)" || {
    echo "[-] steghide not in PATH" >&2
    return 1
  }
  out="$(printf 'y\n' | "$bin" info "$file" 2>&1 </dev/null)" || true
  if print -r -- "$out" | grep -qE 'format:|capacity:'; then
    print -r -- "$out"
    return 0
  fi
  if print -r -- "$out" | grep -qi 'not supported'; then
    echo "[-] steghide: file format not supported" >&2
    print -r -- "$out" >&2
  elif [[ -n "$out" ]]; then
    echo "[-] steghide info:" >&2
    print -r -- "$out" >&2
  else
    echo "[-] steghide info failed (empty output)" >&2
  fi
  return 1
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

# steghide 0.5.x: jpeg, bmp, wav, au only (not png/gif)
_steg-steghide-supported() {
  local file="$1"
  local kind
  kind="$(file -b "$file" 2>/dev/null)" || return 1
  [[ "$kind" == *[Jj][Pp][Ee][Gg]* || "$kind" == *BMP* || "$kind" == *WAV* || "$kind" == *AU\ audio* ]]
}

# fixmagic when header corrupt; echo path to use (original or *_fixed.*)
_steg-prepare-file() {
  local file="$1"
  local analyze fm_status dest

  file="$(realpath "$file" 2>/dev/null || echo "$file")"
  [[ -f "$file" ]] || return 1

  if (( $+functions[_fixmagic-analyze] )); then
    analyze="$(_fixmagic-analyze "$file" 2>/dev/null)" || {
      echo "$file"
      return 0
    }
    IFS=$'\t' read -r _ fm_status _ <<< "${analyze%%$'\n'*}"

    if [[ "$fm_status" == "fix" ]]; then
      dest="$(_fixmagic-out-path "$file")"
      if [[ ! -f "$dest" ]]; then
        echo "[*] corrupt header — running fixmagic" >&2
        fixmagic "$file" || return 1
      else
        echo "[*] using existing: $dest" >&2
      fi
      echo "$dest"
      return 0
    fi
  fi

  echo "$file"
}

_steg-reject-unsupported() {
  local file="$1"
  local kind
  kind="$(file -b "$file" 2>/dev/null)"
  echo "[-] steghide supports JPEG/BMP/WAV/AU only (not PNG/GIF)" >&2
  echo "[*] file: $kind" >&2
  echo "[+] open / inspect: $file" >&2
  echo "[i] corrupt header? fixmagic → image_fixed.png, then open visually" >&2
  echo "[i] for steghide use a JPEG: stegx image.jpg" >&2
  return 1
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
#        steg-extract -p <pass> <image>
#   default wordlist: $RECON_PASSLIST
#   output: cases/.../exports/<name>.steg.out (or beside image if no case)
steg-extract() {
  local wordlist="$RECON_PASSLIST"
  local file="" pass=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: steg-extract <image> [wordlist]"
        echo "       steg-extract -p <pass> <image>"
        echo "  1. fixmagic when header corrupt (auto → *_fixed.*)"
        echo "  2. steghide info + extract (JPEG/BMP/WAV/AU only)"
        echo "  3. -p given: extract with passphrase (skip crack)"
        echo "  4. else: empty pass → stegcracker + wordlist if needed"
        echo "  PNG/GIF: not supported — fixmagic if needed, then inspect visually"
        echo "  default wordlist: \$RECON_PASSLIST"
        echo "  output: cases/<room>/exports/<name>.steg.out"
        echo "  zip output: auto zip-crack + 7z extract"
        echo ""
        echo "alias: stegx"
        return 0
        ;;
      -p)
        pass="$2"
        shift 2
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        if [[ -z "$file" ]]; then
          file="$1"
        elif [[ -z "$pass" ]]; then
          wordlist="$1"
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$file" ]]; then
    echo "usage: steg-extract <image> [wordlist]" >&2
    echo "       steg-extract -p <pass> <image>" >&2
    echo "  alias: stegx" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "[-] file not found: $file" >&2
    return 1
  fi

  if [[ -z "$pass" && ! -f "$wordlist" ]]; then
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

  local work="$(_steg-prepare-file "$file")" || return 1
  if [[ "$work" != "$file" ]]; then
    file="$work"
    out="$(_steg-out-path "$file")"
    rm -f "$out"
  fi

  if ! _steg-steghide-supported "$file"; then
    _steg-reject-unsupported "$file"
    return 1
  fi

  if ! info="$(_steg-info "$file")"; then
    return 1
  fi

  echo "========================"
  echo "[STEG] $file"
  print -r -- "$info"
  echo "========================"

  if logfile="$(_steg-log-path "$file" 2>/dev/null)"; then
    {
      echo "file: $file"
      if [[ -n "$pass" ]]; then
        echo "passphrase: (given)"
      else
        echo "wordlist: $wordlist"
      fi
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

  if [[ -n "$pass" ]]; then
    echo "[*] extracting with given passphrase..." >&2
    if "$steghide" extract -sf "$file" -p "$pass" -xf "$out" -f 2>/dev/null && [[ -s "$out" ]]; then
      echo "[+] passphrase: $pass"
      echo "[+] out: $out"
      _steg-show-out "$out" "$wordlist" || steg_rc=$?
      return $steg_rc
    fi
    echo "[-] extract failed (wrong passphrase?)" >&2
    rm -f "$out"
    return 1
  fi

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
