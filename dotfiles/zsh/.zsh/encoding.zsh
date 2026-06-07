# ========================
# enc / rot / vig — encoding & cipher helpers
# ========================

_enc_squash() {
  tr -d '[:space:]'
}

_b58_bin() {
  whence -p base58 2>/dev/null || echo base58
}

_enc_read() {
  local squash="$1" file="$2"
  shift 2
  local -a positional=("$@")

  if [[ -n "$file" ]]; then
    [[ -f "$file" ]] || { echo "enc: file not found: $file" >&2; return 1; }
    if [[ "$squash" == 1 ]]; then
      <"$file" | _enc_squash
    else
      <"$file"
    fi
    return 0
  fi

  if (( ${#positional[@]} )); then
    if [[ "$squash" == 1 ]]; then
      printf '%s' "${positional[*]}" | _enc_squash
    else
      printf '%s' "${positional[*]}"
    fi
    return 0
  fi

  if [[ ! -t 0 ]]; then
    if [[ "$squash" == 1 ]]; then
      cat | _enc_squash
    else
      cat
    fi
    return 0
  fi

  return 1
}

_b64_decode_bytes() {
  local data="$1"
  if printf '%s' "$data" | base64 -d 2>/dev/null; then
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "$data" | openssl base64 -d -A 2>/dev/null && return 0
  fi
  echo "enc: invalid base64" >&2
  return 1
}

_b64_try_decode() {
  local data="$1"
  if printf '%s' "$data" | base64 -d 2>/dev/null; then
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "$data" | openssl base64 -d -A 2>/dev/null && return 0
  fi
  return 1
}

_b32_decode_bytes() {
  local data="$1"
  if ! command -v base32 >/dev/null 2>&1; then
    echo "enc: base32 not installed (coreutils)" >&2
    return 1
  fi
  if printf '%s' "$data" | base32 -d 2>/dev/null; then
    return 0
  fi
  echo "enc: invalid base32" >&2
  return 1
}

_b32_try_decode() {
  local data="$1" out
  command -v base32 >/dev/null 2>&1 || return 1
  out="$(printf '%s' "$data" | base32 -d 2>/dev/null)" || return 1
  [[ -n "$out" ]] || return 1
  printf '%s' "$out"
}

_b58_decode_bytes() {
  local data="$1"
  local out rc
  if ! command -v base58 >/dev/null 2>&1; then
    echo "enc: base58 not installed (apt install base58)" >&2
    return 1
  fi
  out="$(printf '%s' "$data" | "$(_b58_bin)" -d 2>&1)"
  rc=$?
  if (( rc != 0 )) || [[ -z "$out" ]]; then
    echo "enc: invalid base58" >&2
    [[ -n "$out" ]] && echo "$out" >&2
    return 1
  fi
  printf '%s' "$out"
}

_b58_try_decode() {
  local data="$1" out
  command -v base58 >/dev/null 2>&1 || return 1
  out="$(printf '%s' "$data" | "$(_b58_bin)" -d 2>/dev/null)" || return 1
  [[ -n "$out" ]] || return 1
  printf '%s' "$out"
}

_b62_codec() {
  local data="$1" mode="$2"
  DATA="$data" MODE="$mode" python3 <<'PY'
import os, sys

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
data = os.environ.get("DATA", "")
mode = os.environ.get("MODE", "")

def decode_bytes(s):
    if not s:
        raise ValueError("empty")
    for c in s:
        if c not in ALPHABET:
            raise ValueError("invalid char")
    num = 0
    for c in s:
        num = num * 62 + ALPHABET.index(c)
    if num == 0:
        return b""
    bl = (num.bit_length() + 7) // 8
    return num.to_bytes(bl, "big")

def encode_text(raw):
    if not raw:
        return "0"
    n = int.from_bytes(raw.encode("utf-8"), "big")
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(ALPHABET[r])
    return "".join(reversed(out))

if mode == "d":
    sys.stdout.buffer.write(decode_bytes(data))
elif mode == "e":
    print(encode_text(data), end="")
else:
    sys.exit(1)
PY
}

_b62_decode_bytes() {
  local data="$1"
  _b62_codec "$data" d 2>/dev/null || {
    echo "enc: invalid base62" >&2
    return 1
  }
}

_b62_try_decode() {
  local data="$1" out
  [[ "$data" =~ '^[0-9A-Za-z]+$' ]] || return 1
  out="$(_b62_codec "$data" d 2>/dev/null)" || return 1
  [[ -n "$out" ]] || return 1
  _enc_printable_p "$out" || return 1
  printf '%s' "$out"
}

_b62_encode_bytes() {
  local raw="$1"
  _b62_codec "$raw" e
}

_b10_decode_bytes() {
  local data="$1"
  python3 -c '
import sys

s = sys.argv[1].strip()
if not s.isdigit():
    print("enc: invalid base10 (not all digits)", file=sys.stderr)
    sys.exit(1)
n = int(s)
b = n.to_bytes((n.bit_length() + 7) // 8, "big")
sys.stdout.buffer.write(b)
' "$data"
}

_b10_try_decode() {
  local data="$1" out
  [[ "$data" =~ '^[0-9]+$' ]] || return 1
  out="$(python3 -c '
import sys

s = sys.argv[1]
if not s.isdigit() or s == "0":
    sys.exit(1)
n = int(s)
b = n.to_bytes((n.bit_length() + 7) // 8, "big")
try:
    t = b.decode("utf-8")
except UnicodeDecodeError:
    sys.exit(1)
if not t or not all(c.isprintable() or c in "\n\r\t" for c in t):
    sys.exit(1)
print(t, end="")
' "$data" 2>/dev/null)" || return 1
  [[ -n "$out" ]] || return 1
  printf '%s' "$out"
}

_b10_encode_bytes() {
  local raw="$1"
  python3 -c '
import sys

raw = sys.argv[1]
print(int.from_bytes(raw.encode("utf-8"), "big"))
' "$raw"
}

_enc_hash_kind() {
  local data="${1//[$' \t\r\n']/}"
  python3 -c '
import re, sys
h = sys.argv[1]
if re.fullmatch(r"[0-9a-fA-F]{32}", h):
    print("md5")
elif re.fullmatch(r"[0-9a-fA-F]{40}", h):
    print("sha1")
elif re.fullmatch(r"[0-9a-fA-F]{64}", h):
    print("hash64")
' "$data"
}

_enc_hash_rainbow_lookup() {
  local hash_val="${1//[$' \t\r\n']/}"
  local wl line pass
  local -a tables=(
    /usr/share/seclists/Passwords/Leaked-Databases/md5decryptor-uk.txt
    /usr/share/seclists/Passwords/Leaked-Databases/md5decryptor.org.txt
  )
  for wl in "${tables[@]}"; do
    [[ -f "$wl" ]] || continue
    line="$(grep -i "^${hash_val}:" "$wl" 2>/dev/null | head -1)"
    if [[ -n "$line" ]]; then
      pass="${line#*:}"
      pass="${pass%%:*}"
      [[ -n "$pass" ]] && { printf '%s' "$pass"; return 0; }
    fi
  done
  return 1
}

_enc_hash_online_lookup() {
  local hash_val="${1//[$' \t\r\n']/}" kind="$2"
  [[ "$kind" == md5 ]] || return 1
  HASH="${hash_val:l}" python3 <<'PY'
import os, re, urllib.request

h = os.environ["HASH"].strip().lower()
url = f"https://md5.gromweb.com/?md5={h}"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read().decode("utf-8", "replace")
except Exception:
    raise SystemExit(1)
if "successfully reversed" not in html:
    raise SystemExit(1)
m = re.search(r'class="String"[^>]*>([^<]+)</a>', html)
if not m:
    raise SystemExit(1)
print(m.group(1), end="")
PY
}

_enc_hash_crack_pass() {
  local hash_val="$1" wordlist="${2:-${RECON_PASSLIST:-}}"
  local show pass

  [[ -n "$wordlist" && -f "$wordlist" ]] || return 1
  whence hash-crack >/dev/null 2>&1 || return 1

  echo "[*] hash-crack (${wordlist:t}) ..." >&2
  show="$(hash-crack "$hash_val" "$wordlist" 2>&1)" || true
  pass="$(
    SHOW="$show" python3 <<'PY'
import os, re, sys

text = os.environ.get("SHOW", "")
m = re.search(r"^\[\+\] password: (.+)$", text, re.M)
if m and m.group(1).strip():
    print(m.group(1).strip(), end="")
    sys.exit(0)
for line in text.splitlines():
    line = line.strip()
    if not line or line.startswith("["):
        continue
    if "password hash" in line.lower() or line.startswith("[i]"):
        continue
    if ":" not in line:
        continue
    left, right = line.split(":", 1)
    right = right.strip()
    if not right:
        continue
    if left in ("?", "") or re.fullmatch(r"[0-9a-fA-F]{32}", left) or re.fullmatch(
        r"[0-9a-fA-F]{40}", left
    ) or re.fullmatch(r"[0-9a-fA-F]{64}", left) or left.startswith("$"):
        print(right, end="")
        sys.exit(0)
sys.exit(1)
PY
  )" || return 1
  [[ -n "$pass" ]] || return 1
  printf '%s' "$pass"
}

_enc_hash_reverse() {
  local hash_val="${1//[$' \t\r\n']/}" wordlist="$2" offline="${3:-0}" no_crack="${4:-0}"
  local pass kind wl

  kind="$(_enc_hash_kind "$hash_val")"

  pass="$(_enc_hash_rainbow_lookup "$hash_val")" && {
    printf '%s' "$pass"
    return 0
  }

  if [[ "$offline" -eq 0 && "$kind" == md5 ]]; then
    echo "[*] online md5 lookup..." >&2
    pass="$(_enc_hash_online_lookup "$hash_val" md5)" && {
      printf '%s' "$pass"
      return 0
    }
  fi

  if [[ "$no_crack" -eq 0 ]]; then
    wl="${wordlist:-$RECON_PASSLIST}"
    pass="$(_enc_hash_crack_pass "$hash_val" "$wl")" && {
      printf '%s' "$pass"
      return 0
    }
  fi

  return 1
}

_enc_hash_encode() {
  local kind="$1" raw="$2"
  case "$kind" in
    md5)
      printf '%s' "$raw" | md5sum | awk '{print $1}'
      ;;
    sha1)
      printf '%s' "$raw" | sha1sum | awk '{print $1}'
      ;;
    sha256)
      printf '%s' "$raw" | sha256sum | awk '{print $1}'
      ;;
    *)
      return 1
      ;;
  esac
}

_enc_flag_like_p() {
  DATA="$1" python3 <<'PY'
import os, sys
s = os.environ.get("DATA", "")
u = s.upper()
markers = ("THM{", "TRYHACKME{", "HTB{", "CTF{", "PICOCTF{", "FLAG{", "FLAG")
sys.exit(0 if any(m in u for m in markers) else 1)
PY
}

_enc_printable_p() {
  DATA="$1" python3 <<'PY'
import os, sys
s = os.environ.get("DATA", "")
if not s:
    sys.exit(1)
sys.exit(0 if all(c.isprintable() or c in "\n\r\t" for c in s) else 1)
PY
}

_enc_print_hit() {
  local tag="$1" val="$2"
  if _enc_flag_like_p "$val"; then
    print -r -- ">> $tag  $val"
  else
    print -r -- "$tag  $val"
  fi
}

_enc_hash_pot_lookup() {
  local hash_val="${1//[$' \t\r\n']/}"
  local pot line
  hash_val="${hash_val:l}"
  for pot in ~/.john/john.pot /root/.john/john.pot; do
    [[ -f "$pot" ]] || continue
    line="$(grep -i "^${hash_val}:" "$pot" 2>/dev/null | head -1)"
    if [[ -n "$line" ]]; then
      print -r -- "${line#*:}"
      return 0
    fi
  done
  return 1
}

_hex_try_decode() {
  local data="$1"
  DATA="$data" python3 <<'PY'
import binascii, os, sys

h = os.environ["DATA"]
if len(h) % 2 or not h or not all(c in "0123456789abcdefABCDEF" for c in h):
    sys.exit(1)
try:
    b = binascii.unhexlify(h)
    t = b.decode("utf-8")
except (ValueError, UnicodeDecodeError):
    sys.exit(1)
if not t or not all(c.isprintable() or c in "\n\r\t" for c in t):
    sys.exit(1)
print(t, end="")
PY
}

_bin_try_decode() {
  local data="$1"
  DATA="$data" python3 <<'PY'
import os, sys

s = os.environ["DATA"]
if not s or not all(c in "01" for c in s) or len(s) % 8:
    sys.exit(1)
try:
    b = int(s, 2).to_bytes(len(s) // 8, "big")
    t = b.decode("utf-8")
except (ValueError, UnicodeDecodeError):
    sys.exit(1)
if not t or not all(c.isprintable() or c in "\n\r\t" for c in t):
    sys.exit(1)
print(t, end="")
PY
}

_bin_decode_bytes() {
  local data="$1"
  DATA="${data// /}" python3 <<'PY'
import os, sys

s = os.environ["DATA"]
if not s or not all(c in "01" for c in s) or len(s) % 8:
    print("enc: invalid binary (need 0/1, length multiple of 8)", file=sys.stderr)
    sys.exit(1)
try:
    sys.stdout.buffer.write(int(s, 2).to_bytes(len(s) // 8, "big"))
except ValueError:
    print("enc: invalid binary", file=sys.stderr)
    sys.exit(1)
PY
}

_bin_encode_bytes() {
  local raw="$1" spaced="${2:-1}"
  RAW="$raw" SPACED="$spaced" python3 <<'PY'
import os, sys

raw = os.environ["RAW"]
spaced = os.environ.get("SPACED", "1") == "1"
bits = "".join(f"{b:08b}" for b in raw.encode("utf-8"))
if spaced:
    print(" ".join(bits[i : i + 8] for i in range(0, len(bits), 8)))
else:
    print(bits)
PY
}

_enc_rot_flag_hits() {
  local data="$1"
  DATA="$data" python3 <<'PY'
import os, sys

s = os.environ["DATA"]
if not any(c.isalpha() for c in s) or len(s) > 500:
    sys.exit(0)
markers = ("THM{", "TRYHACKME{", "HTB{", "CTF{", "PICOCTF{", "FLAG{", "FLAG")
for n in range(26):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    plain = "".join(out)
    if any(m in plain.upper() for m in markers):
        print("rot{:02d} {}".format(n, plain))
PY
}

_enc_smart_decode() {
  local data="$1" offline="${2:-0}" wordlist="$3" no_crack="${4:-0}"
  local out kind found=0 tail
  typeset -A seen

  if [[ "$data" != *'$'* && "$data" == *:* ]]; then
    tail="${data##*:}"
    if [[ "$tail" =~ '^[0-9A-Za-z+/=_-]+$' && ${#tail} -ge 4 ]]; then
      data="$tail"
    fi
  fi

  _enc_hit() {
    local tag="$1" val="$2"
    [[ -n "$val" && -z "${seen[$val]:-}" ]] || return 1
    case "$tag" in
      b64|b32|b58|b62|b10|hex|bin)
        _enc_printable_p "$val" || return 1
        ;;
    esac
    seen[$val]=1
    _enc_print_hit "$tag" "$val"
    found=1
  }

  kind="$(_enc_hash_kind "$data")"
  if [[ -n "$kind" ]]; then
    if out="$(_enc_hash_pot_lookup "$data")"; then
      _enc_hit "${kind}(pot)" "$out"
    fi
    if out="$(_enc_hash_reverse "$data" "$wordlist" "$offline" "$no_crack")"; then
      _enc_hit "$kind" "$out"
    fi
    (( found )) && return 0
    echo "enc: $kind hash unresolved (try: enc -d -w other-wordlist)" >&2
    return 1
  fi

  if [[ "$data" =~ '^[01]+$' ]]; then
    if out="$(_bin_try_decode "$data")"; then
      _enc_hit bin "$out"
    fi
    (( found )) && return 0
    echo "enc: no decode matched (bin)" >&2
    return 1
  fi

  if [[ "$data" =~ '^[0-9]+$' ]]; then
    if out="$(_b10_try_decode "$data")"; then
      _enc_hit b10 "$out"
    fi
    (( found )) && return 0
    echo "enc: no decode matched" >&2
    return 1
  fi

  if [[ "$data" =~ '^[0-9a-fA-F]+$' ]] && (( ${#data} % 2 == 0 )); then
    if out="$(_hex_try_decode "$data")"; then
      _enc_hit hex "$out"
    fi
  fi

  if out="$(_b10_try_decode "$data")"; then
    _enc_hit b10 "$out"
  fi
  if out="$(_b64_try_decode "$data")"; then
    _enc_hit b64 "$out"
  fi
  if out="$(_b32_try_decode "$data")"; then
    _enc_hit b32 "$out"
  fi
  if out="$(_b58_try_decode "$data")"; then
    _enc_hit b58 "$out"
  fi
  if out="$(_b62_try_decode "$data")"; then
    _enc_hit b62 "$out"
  fi

  while IFS= read -r out; do
    [[ -n "$out" ]] || continue
    local tag="${out%% *}" rest="${out#* }"
    _enc_hit "$tag" "$rest"
  done < <(_enc_rot_flag_hits "$data")

  (( found )) && return 0

  if [[ "$no_crack" -eq 0 && "$data" == *'$'* ]]; then
    if out="$(_enc_hash_crack_pass "$data" "${wordlist:-$RECON_PASSLIST}")"; then
      _enc_hit crack "$out"
      return 0
    fi
  fi

  echo "enc: no hits (try: rot -a ${(q)data})" >&2
  return 1
}

_enc_try_all_decode() {
  _enc_smart_decode "$@"
}

_enc_try_all_encode() {
  local raw="$1" found=0

  print -n "b10  "
  _b10_encode_bytes "$raw"
  print
  found=1

  print -n "b64  "
  printf '%s' "$raw" | base64 | tr -d '\n'
  print
  found=1

  if command -v base32 >/dev/null 2>&1; then
    print -n "b32  "
    printf '%s' "$raw" | base32 | tr -d '\n'
    print
  else
    echo "b32  (base32 not installed)" >&2
  fi

  if command -v base58 >/dev/null 2>&1; then
    print -n "b58  "
    printf '%s' "$raw" | "$(_b58_bin)" | tr -d '\n'
    print
  else
    echo "b58  (base58 not installed)" >&2
  fi

  print -n "b62  "
  _b62_encode_bytes "$raw"
  print

  print -n "bin  "
  _bin_encode_bytes "$raw"
  print

  (( found )) || return 1
}

# Base64 / Base32 / Base58 / Base10 encode and decode.
# usage: enc -t b64 -d <string>
#        enc -t b58 -e <string>
#        enc -t b64 -d -f <file>
enc() {
  local type="" mode="" file="" data="" raw="" wordlist="" out="" offline=0 no_crack=0
  local -a positional=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: enc -d|-e [input]          smart decode / encode"
        echo "       enc -t b64|b32|b58|b62|b10|bin|md5|sha1|sha256 -d|-e [input]"
        echo "       enc -d -f <file>  |  ... | enc -d"
        echo ""
        echo "enc -d (no -t): auto-try hash / b64 / b32 / b58 / b62 / b10 / hex / bin / rot"
        echo "  >> prefix = flag-like (THM{ HTB{ flag{ ...)"
        echo ""
        echo "options:"
        echo "  -d        decode"
        echo "  -e        encode"
        echo "  -t TYPE   force one type (b64 b32 b58 b62 b10 bin md5 sha1 sha256)"
        echo "  -f FILE   read input from file"
        echo "  -w FILE   wordlist for hash-crack (default: \$RECON_PASSLIST)"
        echo "  --offline skip online md5 lookup"
        echo "  --no-crack skip hash-crack fallback"
        echo ""
        echo "examples:"
        echo "  enc -d QXJlYTUx"
        echo "  enc -d a18672860d0510e5ab6699730763b250"
        echo "  enc -d ObsJmP173N2X6dOrAgEAL0Vu"
        echo "  dec <string>                 alias for enc -d"
        echo ""
        echo "aliases: dec b64d b64e b32d b32e b58d b58e b62d b62e b10d b10e"
        return 0
        ;;
      -t)
        type="${(L)2}"
        shift 2
        ;;
      -d) mode=de; shift ;;
      -e) mode=en; shift ;;
      -f)
        file="$2"
        shift 2
        ;;
      -w)
        wordlist="$2"
        shift 2
        ;;
      --offline)
        offline=1
        shift
        ;;
      --no-crack)
        no_crack=1
        shift
        ;;
      --)
        shift
        positional+=("$@")
        break
        ;;
      -*)
        echo "enc: unknown option: $1" >&2
        return 1
        ;;
      *)
        positional+=("$1")
        shift
        ;;
    esac
  done

  [[ -n "$mode" ]] || {
    echo "enc: requires -d or -e" >&2
    echo "enc: try enc -h" >&2
    return 1
  }

  if [[ -n "$type" ]]; then
    case "$type" in
      b64|base64) type=b64 ;;
      b32|base32) type=b32 ;;
      b58|base58) type=b58 ;;
      b62|base62) type=b62 ;;
      b10|base10|decimal) type=b10 ;;
      bin|binary) type=bin ;;
      md5|sha1|sha256) ;;
      *)
        echo "enc: unknown type: $type (use b64, b32, b58, b62, b10, bin, md5, sha1, or sha256)" >&2
        return 1
        ;;
    esac
  fi

  if [[ "$mode" == de ]]; then
    data="$(_enc_read 1 "$file" "${positional[@]}")" || {
      echo "enc: no input (arg, -f, or stdin)" >&2
      return 1
    }
    [[ -n "$data" ]] || { echo "enc: empty input" >&2; return 1; }

    if [[ -z "$type" ]]; then
      _enc_smart_decode "$data" "$offline" "$wordlist" "$no_crack"
      return $?
    fi

    case "$type" in
      b64) _b64_decode_bytes "$data" && print ;;
      b32) _b32_decode_bytes "$data" && print ;;
      b58) _b58_decode_bytes "$data" && print ;;
      b62) _b62_decode_bytes "$data" && print ;;
      b10) _b10_decode_bytes "$data" && print ;;
      bin) _bin_decode_bytes "$data" && print ;;
      md5|sha1|sha256)
        local kind="$(_enc_hash_kind "$data")"
        [[ "$kind" == "$type" ]] || {
          echo "enc: input is not a valid $type hex hash" >&2
          return 1
        }
        if out="$(_enc_hash_reverse "$data" "$wordlist" "$offline" "$no_crack")"; then
          print -r -- "$out"
        else
          echo "enc: $type hash unresolved (try: enc -d -w other-wordlist)" >&2
          return 1
        fi
        ;;
    esac
    return $?
  fi

  raw="$(_enc_read 0 "$file" "${positional[@]}")" || {
    echo "enc: no input (arg, -f, or stdin)" >&2
    return 1
  }

  if [[ -z "$type" ]]; then
    _enc_try_all_encode "$raw"
    return $?
  fi

  case "$type" in
    b64)
      printf '%s' "$raw" | base64 | tr -d '\n'
      print
      ;;
    b32)
      if ! command -v base32 >/dev/null 2>&1; then
        echo "enc: base32 not installed (coreutils)" >&2
        return 1
      fi
      printf '%s' "$raw" | base32 | tr -d '\n'
      print
      ;;
    b58)
      if ! command -v base58 >/dev/null 2>&1; then
        echo "enc: base58 not installed (apt install base58)" >&2
        return 1
      fi
      printf '%s' "$raw" | "$(_b58_bin)" | tr -d '\n'
      print
      ;;
    b62)
      _b62_encode_bytes "$raw"
      print
      ;;
    b10)
      _b10_encode_bytes "$raw"
      ;;
    bin)
      _bin_encode_bytes "$raw"
      ;;
    md5|sha1|sha256)
      _enc_hash_encode "$type" "$raw"
      ;;
  esac
}

# Caesar / ROT: print all shifts.
# usage: rot -a <string>
#        rot -a -f <file>
rot() {
  local mode="" file="" data=""
  local -a positional=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: rot -a <string>"
        echo "       rot -a -f <file>"
        echo "       ... | rot -a"
        echo "  Caesar cipher: print all 26 shifts (find THM{ / flag prefix)"
        echo ""
        echo "alias: rotall"
        return 0
        ;;
      -a) mode=all; shift ;;
      -f)
        file="$2"
        shift 2
        ;;
      --)
        shift
        positional+=("$@")
        break
        ;;
      -*)
        echo "rot: unknown option: $1" >&2
        return 1
        ;;
      *)
        positional+=("$1")
        shift
        ;;
    esac
  done

  [[ "$mode" == all ]] || {
    echo "rot: pick a mode: -a" >&2
    echo "rot: try rot -h" >&2
    return 1
  }

  data="$(_enc_read 1 "$file" "${positional[@]}")" || {
    echo "rot: no input (arg, -f, or stdin)" >&2
    return 1
  }
  [[ -n "$data" ]] || { echo "rot: empty input" >&2; return 1; }

  python3 -c '
import sys
s = sys.argv[1]
for n in range(26):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    print("{:2d} {}".format(n, "".join(out)))
' "$data"
}

# Vigenere cipher: decrypt / encrypt / brute-force / key recovery.
# usage: vig -a <cipher>
#        vig -d -k KEY <cipher>
#        vig -K -p PLAIN <cipher>
vig() {
  local mode="" key="" plain="" data="" max_len=3 show_all=false
  local file="" positional=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: vig -a <cipher>              brute keys len 1-3 (flag-like hits)"
        echo "       vig -d -k KEY <cipher>       decrypt"
        echo "       vig -e -k KEY <plain>        encrypt"
        echo "       vig -K -p PLAIN <cipher>     recover repeating key"
        echo "       vig -f <file> ...            read input from file"
        echo "       ... | vig -a                 read from stdin"
        echo ""
        echo "modes (pick one):"
        echo "  -a     brute-force short keys"
        echo "  -d     decrypt (requires -k)"
        echo "  -e     encrypt (requires -k)"
        echo "  -K     recover key (requires -p)"
        echo ""
        echo "options:"
        echo "  -k KEY   Vigenere key"
        echo "  -p PLAIN known plaintext prefix (with -K)"
        echo "  -f FILE  input file"
        echo "  -n N     max key length for -a (default 3; 4+ is slow)"
        echo "  --all    with -a: no flag filter"
        echo ""
        echo "examples:"
        echo "  vig -a 'CIPHER{...}'"
        echo "  vig -d -k KEY 'CIPHER{...}'"
        echo "  vig -K -p TRYHACKME 'CIPHER{...}'"
        echo ""
        echo "aliases: vigd vige vigall vigkey"
        return 0
        ;;
      -d) mode=de; shift ;;
      -e) mode=en; shift ;;
      -a) mode=attack; shift ;;
      -K) mode=key; shift ;;
      -k)
        key="${(U)2}"
        shift 2
        ;;
      -p)
        plain="$2"
        shift 2
        ;;
      -f)
        file="$2"
        shift 2
        ;;
      -n)
        max_len="$2"
        shift 2
        ;;
      --all)
        show_all=true
        shift
        ;;
      --)
        shift
        positional+=("$@")
        break
        ;;
      -*)
        echo "vig: unknown option: $1" >&2
        return 1
        ;;
      *)
        positional+=("$1")
        shift
        ;;
    esac
  done

  [[ -n "$mode" ]] || {
    echo "vig: pick a mode: -a | -d | -e | -K" >&2
    echo "vig: try vig -h" >&2
    return 1
  }

  case "$mode" in
    de|en)
      [[ -n "$key" ]] || { echo "vig: -d/-e requires -k KEY" >&2; return 1; }
      ;;
    key)
      [[ -n "$plain" ]] || { echo "vig: -K requires -p PLAIN" >&2; return 1; }
      ;;
  esac

  data="$(_enc_read 1 "$file" "${positional[@]}")" || {
    if [[ "$mode" == key && -n "$plain" ]]; then
      echo "vig: -K needs cipher text (arg, -f, or stdin)" >&2
    else
      echo "vig: no input (arg, -f, or stdin)" >&2
    fi
    return 1
  }
  [[ -n "$data" ]] || { echo "vig: empty input" >&2; return 1; }

  case "$mode" in
    de|en)
      python3 -c '
import sys

def vig(text, key, encrypt):
    key = "".join(c for c in key.upper() if c.isalpha())
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("A")
            if not encrypt:
                shift = -shift
            out.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)

mode = sys.argv[1]
text = sys.argv[2]
key = sys.argv[3]
print(vig(text, key, mode == "en"))
' "$mode" "$data" "$key"
      ;;
    attack)
      python3 -c '
import itertools
import sys

text = sys.argv[1]
max_len = int(sys.argv[2])
show_all = sys.argv[3] == "1"
markers = ("THM{", "TRYHACKME{", "HTB{", "CTF{", "PICOCTF{", "FLAG{")

def vig_decrypt(s, key):
    out = []
    ki = 0
    for c in s:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("A")
            out.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)

def interesting(plain):
    if show_all:
        return True
    upper = plain.upper()
    return any(m in upper for m in markers)

letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
found = 0
for n in range(1, max_len + 1):
    for key_tuple in itertools.product(letters, repeat=n):
        key = "".join(key_tuple)
        plain = vig_decrypt(text, key)
        if interesting(plain):
            print("key {:<{w}}: {}".format(key, plain, w=max_len))
            found += 1

if found == 0:
    print("vig: no flag-like hits (try --all or -n 4)", file=sys.stderr)
    sys.exit(1)
' "$data" "$max_len" "$($show_all && echo 1 || echo 0)"
      ;;
    key)
      plain="${plain//[[:space:]]/}"
      python3 -c '
import sys

cipher = sys.argv[1]
plain = sys.argv[2]
key = []
pi = 0
for c in cipher:
    if c.isalpha():
        while pi < len(plain) and not plain[pi].isalpha():
            pi += 1
        if pi >= len(plain):
            break
        p = plain[pi]
        pi += 1
        shift = (ord(c.upper()) - ord(p.upper())) % 26
        key.append(chr(shift + ord("A")))
    if pi >= len(plain):
        break

if not key:
    print("vig: no key recovered", file=sys.stderr)
    sys.exit(1)

recovered = "".join(key)
period = len(recovered)
for p in range(1, len(recovered) // 2 + 1):
    if len(recovered) % p == 0 and recovered == recovered[:p] * (len(recovered) // p):
        period = p
        break

print(recovered[:period])
if period < len(recovered):
    print("full: {}".format(recovered), file=sys.stderr)
' "$data" "$plain"
      ;;
  esac
}

# backward-compatible aliases
dec() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  enc -d "$@"
}

b64d() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b64 -d -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b64d <string>  (see: enc -t b64 -d ...)" >&2; return 1; }
      enc -t b64 -d
      ;;
    *) enc -t b64 -d "$@" ;;
  esac
}

b64e() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b64 -e -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b64e <string>  (see: enc -t b64 -e ...)" >&2; return 1; }
      enc -t b64 -e
      ;;
    *) enc -t b64 -e "$@" ;;
  esac
}

b58d() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b58 -d -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b58d <string>  (see: enc -t b58 -d ...)" >&2; return 1; }
      enc -t b58 -d
      ;;
    *) enc -t b58 -d "$@" ;;
  esac
}

b62d() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b62 -d -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b62d <string>  (see: enc -t b62 -d ...)" >&2; return 1; }
      enc -t b62 -d
      ;;
    *) enc -t b62 -d "$@" ;;
  esac
}

b62e() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b62 -e -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b62e <string>  (see: enc -t b62 -e ...)" >&2; return 1; }
      enc -t b62 -e
      ;;
    *) enc -t b62 -e "$@" ;;
  esac
}

b32d() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b32 -d -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b32d <string>  (see: enc -t b32 -d ...)" >&2; return 1; }
      enc -t b32 -d
      ;;
    *) enc -t b32 -d "$@" ;;
  esac
}

b32e() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b32 -e -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b32e <string>  (see: enc -t b32 -e ...)" >&2; return 1; }
      enc -t b32 -e
      ;;
    *) enc -t b32 -e "$@" ;;
  esac
}

b10d() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b10 -d -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b10d <string>  (see: enc -t b10 -d ...)" >&2; return 1; }
      enc -t b10 -d
      ;;
    *) enc -t b10 -d "$@" ;;
  esac
}

b10e() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b10 -e -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b10e <string>  (see: enc -t b10 -e ...)" >&2; return 1; }
      enc -t b10 -e
      ;;
    *) enc -t b10 -e "$@" ;;
  esac
}

b58e() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { enc -h; return; }
  case "${1:-}" in
    -f) enc -t b58 -e -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: b58e <string>  (see: enc -t b58 -e ...)" >&2; return 1; }
      enc -t b58 -e
      ;;
    *) enc -t b58 -e "$@" ;;
  esac
}

rotall() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { rot -h; return; }
  case "${1:-}" in
    -f) rot -a -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: rotall <string>  (see: rot -a ...)" >&2; return 1; }
      rot -a
      ;;
    *) rot -a "$@" ;;
  esac
}

vigd() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { vig -h; return; }
  [[ -n "${1:-}" ]] || { echo "usage: vigd <key> <string>  (see: vig -d -k KEY ...)" >&2; return 1; }
  vig -d -k "$1" "${@:2}"
}

vige() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { vig -h; return; }
  [[ -n "${1:-}" ]] || { echo "usage: vige <key> <string>  (see: vig -e -k KEY ...)" >&2; return 1; }
  vig -e -k "$1" "${@:2}"
}

vigall() {
  local args=() unfiltered=false
  [[ $# -eq 0 && ! -t 0 ]] && { vig -a; return; }
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) vig -h; return ;;
      -a) unfiltered=true; shift ;;
      *) args+=("$1"); shift ;;
    esac
  done
  if $unfiltered; then
    vig -a --all "${args[@]}"
  else
    vig -a "${args[@]}"
  fi
}

vigkey() {
  case "${1:-}" in
    -h|--help) vig -h; return ;;
    -f)
      [[ -f "${2:-}" ]] || { echo "vigkey: file not found: ${2:-}" >&2; return 1; }
      vig -K -f "$2" -p "${3:-}"
      ;;
    *)
      vig -K -p "${2:-}" "${1:-}"
      ;;
  esac
}

# Brainfuck interpreter (beef).
# usage: bf <file>
#        bf -f <file>
#        bf -p <code>
#        ... | bf
_bf_run() {
  local out rc
  out="$(beef "$@" 2>&1)"
  rc=$?
  if (( rc == 0 )) && [[ -n "$out" ]]; then
    printf '%s\n' "$out"
  elif (( rc != 0 )); then
    print -r -- "$out" >&2
  fi
  return rc
}

bf() {
  local file="" program=""
  local -a positional=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: bf <file>"
        echo "       bf -f <file>"
        echo "       bf -p <code>"
        echo "       ... | bf"
        echo ""
        echo "Run Brainfuck source with beef (apt: beef)."
        echo "alias: bfdec"
        return 0
        ;;
      -f)
        file="$2"
        shift 2
        ;;
      -p)
        program="$2"
        shift 2
        ;;
      --)
        shift
        positional+=("$@")
        break
        ;;
      -*)
        echo "bf: unknown option: $1" >&2
        return 1
        ;;
      *)
        positional+=("$1")
        shift
        ;;
    esac
  done

  command -v beef >/dev/null 2>&1 || {
    echo "bf: beef not installed (rebuild image or: apt install beef)" >&2
    return 1
  }

  if [[ -n "$program" ]]; then
    _bf_run -p "$program"
    return $?
  fi

  if [[ -n "$file" ]]; then
    [[ -f "$file" ]] || { echo "bf: file not found: $file" >&2; return 1; }
    _bf_run "$file"
    return $?
  fi

  if (( ${#positional[@]} )); then
    if [[ -f "${positional[1]}" ]]; then
      _bf_run "${positional[1]}"
      return $?
    fi
    _bf_run -p "${(j::)positional}"
    return $?
  fi

  if [[ ! -t 0 ]]; then
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/bf.XXXXXX.bf")"
    trap 'rm -f "$tmp"' EXIT INT TERM
    cat >"$tmp"
    _bf_run "$tmp"
    return $?
  fi

  echo "bf: no input (file, -f, -p, or stdin)" >&2
  echo "bf: try bf -h" >&2
  return 1
}

bfdec() {
  [[ "${1:-}" == -h || "${1:-}" == --help ]] && { bf -h; return; }
  bf "$@"
}
