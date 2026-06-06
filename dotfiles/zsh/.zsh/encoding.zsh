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

_enc_try_all_decode() {
  local data="$1" out found=0

  if [[ "$data" =~ '^[0-9]+$' ]]; then
    if out="$(_b10_try_decode "$data")"; then
      print "b10  $out"
      return 0
    fi
    echo "enc: no decode matched (b10)" >&2
    return 1
  fi

  if out="$(_b10_try_decode "$data")"; then
    print "b10  $out"
    found=1
  fi
  if out="$(_b64_try_decode "$data")"; then
    print "b64  $out"
    found=1
  fi
  if out="$(_b32_try_decode "$data")"; then
    print "b32  $out"
    found=1
  fi
  if out="$(_b58_try_decode "$data")"; then
    print "b58  $out"
    found=1
  fi

  (( found )) || {
    echo "enc: no decode matched (b10 / b64 / b32 / b58)" >&2
    return 1
  }
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

  (( found )) || return 1
}

# Base64 / Base32 / Base58 / Base10 encode and decode.
# usage: enc -t b64 -d <string>
#        enc -t b58 -e <string>
#        enc -t b64 -d -f <file>
enc() {
  local type="" mode="" file="" data="" raw=""
  local -a positional=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: enc -d|-e [input]"
        echo "       enc -t b64|b32|b58|b10 -d|-e [input]"
        echo "       enc -d -f <file>"
        echo "       ... | enc -d"
        echo ""
        echo "options:"
        echo "  -d        decode (whitespace ignored)"
        echo "  -e        encode (single line output)"
        echo "  -t TYPE   b64 | b32 | b58 | b10 (omit to try all types)"
        echo "  -f FILE   read input from file"
        echo ""
        echo "examples:"
        echo "  enc -d QXJlYTUx              try all decode"
        echo "  enc -t b10 -d 581695969...   decimal integer -> bytes"
        echo "  enc -e 'hello'               all encode formats"
        echo ""
        echo "aliases: b64d b64e b32d b32e b58d b58e b10d b10e"
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
      b10|base10|decimal) type=b10 ;;
      *)
        echo "enc: unknown type: $type (use b64, b32, b58, or b10)" >&2
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
      _enc_try_all_decode "$data"
      return $?
    fi

    case "$type" in
      b64) _b64_decode_bytes "$data" && print ;;
      b32) _b32_decode_bytes "$data" && print ;;
      b58) _b58_decode_bytes "$data" && print ;;
      b10) _b10_decode_bytes "$data" && print ;;
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
    b10)
      _b10_encode_bytes "$raw"
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
