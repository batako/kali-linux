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
      printf '%s' "${(j: :)positional}" | _enc_squash
    else
      printf '%s' "${(j: :)positional}"
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

_enc_chomp_trailing_eol() {
  local data="$1"
  while [[ "$data" == *$'\n' || "$data" == *$'\r' ]]; do
    data="${data%$'\n'}"
    data="${data%$'\r'}"
  done
  printf '%s' "$data"
}

_vig_print_result() {
  local mode="$1" input_text="$2" output_text="$3"
  if [[ ! -t 1 ]]; then
    printf '%s\n' "$output_text"
    return
  fi

  local needs_pretty=false
  [[ ${#input_text} -gt 48 ]] && needs_pretty=true
  [[ "$input_text" == *" "* ]] && needs_pretty=true
  [[ "$input_text" == *$'\n'* ]] && needs_pretty=true
  [[ "$output_text" == *$'\n'* ]] && needs_pretty=true

  if ! $needs_pretty; then
    printf '%s\n' "$output_text"
    return
  fi

  if _toolkit-lang-ja; then
    printf '[出力]\n%s\n' "$output_text"
  else
    printf '[output]\n%s\n' "$output_text"
  fi
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

_enc_ascii_dec_p() {
  local data="$1"
  [[ "$data" =~ '^[0-9]+$' ]] && return 1
  DATA="$data" python3 -c 'import os,re,sys; s=os.environ["DATA"].strip(); parts=[p for p in re.split(r"[, \t]+",s) if p]; sys.exit(0 if len(parts)>=2 and all(p.isdigit() and 0<=int(p)<=255 for p in parts) else 1)'
}

_enc_ascii_dec_try_decode() {
  local data="$1"
  DATA="$data" python3 -c '
import os, re, sys

s = os.environ["DATA"].strip()
parts = [p for p in re.split(r"[, \t]+", s) if p]
if len(parts) < 2:
    sys.exit(1)
try:
    nums = [int(p) for p in parts]
except ValueError:
    sys.exit(1)
if not all(0 <= n <= 255 for n in nums):
    sys.exit(1)
try:
    t = bytes(nums).decode("utf-8")
except UnicodeDecodeError:
    sys.exit(1)
if not t or not all(c.isprintable() or c in "\n\r\t" for c in t):
    sys.exit(1)
print(t, end="")
'
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

_enc_hash_fmt_kind() {
  local hash_val="$1"
  case "$hash_val" in
    \$2a\$*|\$2b\$*|\$2y\$*) print -r -- bcrypt ;;
    \$apr1\$*|\$1\$*) print -r -- md5crypt ;;
    \$6\$*) print -r -- sha512crypt ;;
    \$5\$*) print -r -- sha256crypt ;;
    \$6a\$*|\$argon2*) print -r -- argon2 ;;
    \{SSHA\}*|\{SHA\}*) print -r -- sha1 ;;
    *)
      local k="$(_enc_hash_kind "$hash_val")"
      case "$k" in
        hash32) print -r -- md5 ;;
        hash64) print -r -- sha256 ;;
        sha1) print -r -- sha1 ;;
        *) [[ -n "$k" ]] && print -r -- "$k" ;;
      esac
      ;;
  esac
}

_enc_hash_log_kind() {
  local kind="$1"
  case "$kind" in
    hash32) print -r -- md5 ;;
    hash64) print -r -- sha256 ;;
    *) print -r -- "$kind" ;;
  esac
}

_enc_hash_builtin_candidates() {
  local data="${1//[$' \t\r\n']/}"
  case "$data" in
    \$2a\$*|\$2b\$*|\$2y\$*) print -r -- bcrypt ;;
    \$apr1\$*|\$1\$*) print -r -- md5crypt ;;
    \$6\$*) print -r -- sha512crypt ;;
    \$5\$*) print -r -- sha256crypt ;;
    \$6a\$*|\$argon2*) print -r -- argon2 ;;
    \{SSHA\}*|\{SHA\}*) print -r -- sha1 ;;
  esac
}

_enc_hash_ambiguous_p() {
  local data="${1//[$' \t\r\n']/}"
  [[ "$data" =~ '^[0-9a-fA-F]{32}$' || "$data" =~ '^[0-9a-fA-F]{40}$' || "$data" =~ '^[0-9a-fA-F]{64}$' ]]
}

_enc_nth_candidates() {
  local data="${1//[$' \t\r\n']/}" nth_bin=""
  command -v name-that-hash >/dev/null 2>&1 && nth_bin="$(command -v name-that-hash)"
  [[ -z "$nth_bin" ]] && command -v nth >/dev/null 2>&1 && nth_bin="$(command -v nth)"
  [[ -n "$nth_bin" ]] || return 1
  HASH="$data" NTH_BIN="$nth_bin" python3 <<'PY'
import os, re, subprocess, sys

h = os.environ["HASH"]
cmd = os.environ.get("NTH_BIN")
if not cmd:
    raise SystemExit(1)
attempts = (
    [cmd, "--text", h],
    [cmd, "-t", h],
    [cmd, h],
)
try:
    proc = None
    for argv in attempts:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if text.strip():
            break
except Exception:
    raise SystemExit(1)

text = (proc.stdout or "") + "\n" + (proc.stderr or "")
seen = set()

def add(name):
    if name and name not in seen:
        seen.add(name)
        print(name)

for raw in text.splitlines():
    line = raw.strip()
    if not line:
        continue
    if line.startswith("Most likely possible hash type:"):
        name = line.split(":", 1)[1].strip()
    elif line.startswith("Possible hash types:"):
        continue
    elif line.startswith("[+]"):
        name = re.sub(r"\s*\[.*$", "", line[3:].strip())
    elif line.startswith("- "):
        name = line[2:].strip()
    elif "|" in line:
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) >= 2 and parts[0].isdigit():
            name = parts[1]
        else:
            continue
    else:
        continue
    low = name.lower()
    if "argon2" in low:
        add("argon2")
    elif "bcrypt" in low:
        add("bcrypt")
    elif "sha-512" in low and "crypt" in low:
        add("sha512crypt")
    elif "sha-256" in low and "crypt" in low:
        add("sha256crypt")
    elif ("md5" in low and "crypt" in low) or "apr1" in low:
        add("md5crypt")
    elif "{ssha}" in low or "{sha}" in low or "sha-1" in low or low == "sha1":
        add("sha1")
    elif "sha-256" in low or low == "sha256":
        add("sha256")
    elif "ntlm" in low:
        add("ntlm")
    elif low == "md4" or re.search(r"\bmd4\b", low):
        add("md4")
    elif low == "md5" or re.search(r"\bmd5\b", low):
        add("md5")
PY
}

_enc_hash_candidates() {
  local data="${1//[$' \t\r\n']/}" c
  local -a out=()
  typeset -A seen

  _enc_add_kind() {
    local kind="$1"
    [[ -n "$kind" && -z "${seen[$kind]:-}" ]] || return 0
    seen[$kind]=1
    out+=("$kind")
  }

  while IFS= read -r c; do
    [[ -n "$c" ]] && _enc_add_kind "$c"
  done < <(_enc_hash_builtin_candidates "$data")

  if _enc_hash_ambiguous_p "$data"; then
    while IFS= read -r c; do
      [[ -n "$c" ]] && _enc_add_kind "$c"
    done < <(_enc_nth_candidates "$data" 2>/dev/null)
  fi

  if [[ "$data" =~ '^[0-9a-fA-F]{32}$' ]]; then
    _enc_add_kind md5
    _enc_add_kind ntlm
    _enc_add_kind md4
  elif [[ "$data" =~ '^[0-9a-fA-F]{40}$' ]]; then
    _enc_add_kind sha1
  elif [[ "$data" =~ '^[0-9a-fA-F]{64}$' ]]; then
    _enc_add_kind sha256
  fi

  printf '%s\n' "${out[@]}"
}

_enc_hash_kind() {
  local data="${1//[$' \t\r\n']/}" first
  first="$(_enc_hash_candidates "$data" | head -1)"
  [[ -n "$first" ]] && print -r -- "$first"
}

_enc_hash_valid_hex() {
  local data="${1//[$' \t\r\n']/}" kind="$2"
  python3 -c '
import re, sys
h, kind = sys.argv[1], sys.argv[2]
lens = {"md4": 32, "md5": 32, "ntlm": 32, "sha1": 40, "sha256": 64}
n = lens.get(kind)
if n and re.fullmatch(rf"[0-9a-fA-F]{{{n}}}", h):
    sys.exit(0)
sys.exit(1)
' "$data" "$kind"
}

_enc_md4_hex() {
  local raw="$1" out hex opt
  for opt in "" "-provider legacy"; do
    out="$(printf '%s' "$raw" | openssl dgst -md4 ${=opt} 2>/dev/null)" || continue
    hex="${out##*= }"
    hex="${hex//[[:space:]]/}"
    [[ -n "$hex" ]] && {
      printf '%s' "$hex"
      return 0
    }
  done
  echo "enc: md4 not available (openssl -provider legacy?)" >&2
  return 1
}

_enc_try_label() {
  case "${1:l}" in
    md4) print -r -- MD4 ;;
    md5) print -r -- MD5 ;;
    ntlm) print -r -- NTLM ;;
    sha1) print -r -- SHA-1 ;;
    sha256) print -r -- SHA-256 ;;
    bcrypt) print -r -- bcrypt ;;
    md5crypt) print -r -- MD5-crypt ;;
    sha512crypt) print -r -- SHA-512-crypt ;;
    sha256crypt) print -r -- SHA-256-crypt ;;
    argon2) print -r -- Argon2 ;;
    *) print -r -- "$1" ;;
  esac
}

# UI/log: flatten whitespace so one table row stays one physical line
_enc_ui_disp_val() {
  local val="${1//$'\r'/}"
  val="${val//$'\n'/ }"
  val="${val//$'\t'/ }"
  while [[ "$val" == *'  '* ]]; do
    val="${val//  / }"
  done
  val="${val# }"
  val="${val% }"
  print -rn -- "$val"
}

typeset -gA _ENC_UI_STATE
typeset -ga _ENC_UI_KEYS
typeset -g _ENC_UI_LINES=0
typeset -g _ENC_UI_STATUS_LINES=0
typeset -g _ENC_UI_STATUS_TEXT=""
typeset -g _ENC_UI_INIT=0
typeset -g _ENC_CRACK_REPORT=""

_enc_set_crack_report() {
  typeset -g _ENC_CRACK_REPORT="$1"
}

_enc_print_crack_report() {
  [[ -n "${_ENC_CRACK_REPORT:-}" ]] || return 0
  echo "[i] cracked via: $_ENC_CRACK_REPORT" >&2
}

_enc_ui_active() {
  (( _ENC_UI_INIT ))
}

_enc_ui_format_row() {
  local key="$1" state="${_ENC_UI_STATE[$key]:-pending}" label val
  label="$(_enc_try_label "$key")"
  case "$state" in
    pending) printf '%-14s -\n' "$label" >&2 ;;
    trying) printf '%-14s ...\n' "$label" >&2 ;;
    ng) printf '%-14s NG\n' "$label" >&2 ;;
    ok:*)
      val="${state#ok:}"
      if _enc_flag_like_p "$val" 2>/dev/null; then
        label=">>${label}"
      fi
      printf '%-14s OK %s\n' "$label" "$(_enc_ui_disp_val "$val")" >&2
      ;;
  esac
}

_enc_ui_clear_block() {
  local total=$(( _ENC_UI_LINES + _ENC_UI_STATUS_LINES ))
  if (( total > 0 )); then
    printf '\e[%dA\e[J' "$total" >&2
  fi
}

_enc_ui_paint() {
  _enc_ui_clear_block
  local n=0 key
  for key in "${_ENC_UI_KEYS[@]}"; do
    _enc_ui_format_row "$key"
    (( n++ ))
  done >&2
  _ENC_UI_LINES=$n
  if [[ -n "$_ENC_UI_STATUS_TEXT" ]]; then
    printf '\n> %s\n' "$_ENC_UI_STATUS_TEXT" >&2
    _ENC_UI_STATUS_LINES=2
  else
    _ENC_UI_STATUS_LINES=0
  fi
}

_enc_wl_short() {
  local wl="$1"
  [[ -n "$wl" ]] && print -r -- "${wl:t}" || print -r -- wordlist
}

_enc_ui_status() {
  _ENC_UI_STATUS_TEXT="$*"
  _enc_ui_paint
}

_enc_ui_status_inline() {
  _ENC_UI_STATUS_TEXT="$*"
  _enc_ui_clear_block
  local n=0 key
  for key in "${_ENC_UI_KEYS[@]}"; do
    _enc_ui_format_row "$key"
    (( n++ ))
  done >&2
  _ENC_UI_LINES=$n
  printf '\n> %s' "$_ENC_UI_STATUS_TEXT" >&2
  _ENC_UI_STATUS_LINES=2
}

_enc_ui_status_clear() {
  _ENC_UI_STATUS_TEXT=""
}

_enc_ui_after_prompt() {
  _ENC_UI_STATUS_TEXT=""
  local total=$(( _ENC_UI_LINES + _ENC_UI_STATUS_LINES + 1 )) n=0 key
  if (( total > 0 )); then
    printf '\e[%dA\e[J' "$total" >&2
  fi
  _ENC_UI_STATUS_LINES=0
  for key in "${_ENC_UI_KEYS[@]}"; do
    _enc_ui_format_row "$key"
    (( n++ ))
  done >&2
  _ENC_UI_LINES=$n
}

_enc_ui_status_john() {
  local tier="$1" wl="$2"
  local wl_t="$(_enc_wl_short "$wl")"
  if [[ "$tier" == heavy ]]; then
    _enc_ui_status "john --rules $wl_t"
  else
    _enc_ui_status "john $wl_t"
  fi
}

_enc_ui_finish() {
  _ENC_UI_STATUS_TEXT=""
  _ENC_UI_STATUS_LINES=0
}

_enc_ui_finalize_states() {
  local key state
  for key in "${_ENC_UI_KEYS[@]}"; do
    state="${_ENC_UI_STATE[$key]:-pending}"
    case "$state" in
      trying|pending) _ENC_UI_STATE[$key]=ng ;;
    esac
  done
  _ENC_UI_STATUS_TEXT=""
}

_enc_ui_init() {
  _ENC_UI_KEYS=("$@")
  _ENC_UI_STATE=()
  local k
  for k in "$@"; do
    _ENC_UI_STATE[$k]=pending
  done
  _ENC_UI_LINES=0
  _ENC_UI_STATUS_LINES=0
  _ENC_UI_STATUS_TEXT=""
}

_enc_ui_trying() {
  local key="$1"
  _ENC_UI_STATUS_TEXT=""
  _ENC_UI_STATE[$key]=trying
  _enc_ui_paint
}

_enc_ui_plan() {
  local data="$1" offline="$2" no_crack="$3"
  local -a keys=() kinds=() fmt

  if _enc_bin_p "$data"; then
    _enc_ui_init bin
    return 0
  fi

  kinds=("${(@f)$(_enc_hash_candidates "$data")}")
  if (( ${#kinds[@]} )); then
    keys=("${kinds[@]}")
    _enc_ui_init "${keys[@]}"
    return 0
  fi

  if [[ "$data" =~ '^[0-9]+$' ]]; then
    _enc_ui_init b10
    return 0
  fi

  if _enc_ascii_dec_p "$data"; then
    _enc_ui_init ascii
    return 0
  fi

  if _enc_morse_p "$data"; then
    _enc_ui_init morse
    return 0
  fi

  if [[ "$data" =~ '^[0-9a-fA-F]+$' ]] && (( ${#data} % 2 == 0 )); then
    keys=(hex)
  fi
  keys+=(b10 b64 b32 b58 b62 rot)

  if [[ "$data" == *'$'* && "$no_crack" -eq 0 ]]; then
    fmt="$(_enc_hash_fmt_kind "$data")"
    [[ -n "$fmt" ]] && keys+=("$fmt")
  fi

  _enc_ui_init "${keys[@]}"
}

_enc_ui_setup() {
  _ENC_UI_INIT=0
  [[ -t 2 ]] || return 1
  _ENC_UI_INIT=1
  return 0
}

_enc_ui_teardown() {
  if _enc_ui_active; then
    local key state need_paint=0
    for key in "${_ENC_UI_KEYS[@]}"; do
      state="${_ENC_UI_STATE[$key]:-pending}"
      case "$state" in
        trying|pending) need_paint=1 ;;
      esac
    done
    _enc_ui_finalize_states
    if (( need_paint )); then
      _enc_ui_paint
    fi
    _enc_ui_finish
    _ENC_UI_INIT=0
  fi
}

# stderr: table row update (TTY) or "kind OK/NG" line (non-TTY)
_enc_try_log() {
  local key="$1" val="${2:-}"
  if _enc_ui_active; then
    local new_state
    if [[ -n "$val" && "$val" != skip && "$val" != skip* ]]; then
      new_state="ok:$val"
      [[ "${_ENC_UI_STATE[$key]:-}" == "$new_state" ]] && return 0
      _ENC_UI_STATE[$key]="$new_state"
    else
      [[ "${_ENC_UI_STATE[$key]:-}" == ng ]] && return 0
      [[ "${_ENC_UI_STATE[$key]:-}" == ok:* ]] && return 0
      _ENC_UI_STATE[$key]=ng
    fi
    _ENC_UI_STATUS_TEXT=""
    _enc_ui_paint
    return 0
  fi
  local label="$(_enc_try_label "$key")"
  if [[ -n "$val" && "$val" != skip && "$val" != skip* ]]; then
    if _enc_flag_like_p "$val" 2>/dev/null; then
      label=">>${label}"
    fi
    printf '%-14s OK %s\n' "$label" "$(_enc_ui_disp_val "$val")" >&2
  else
    printf '%-14s NG\n' "$label" >&2
  fi
}

_enc_john_show_pass() {
  local fmt="$1" hash_file="$2" pot_file="$3" show pass
  show="$(john --format="$fmt" --pot="$pot_file" --show "$hash_file" 2>/dev/null | sed '/^$/d')"
  if whence _john_pass_from_show >/dev/null 2>&1; then
    pass="$(_john_pass_from_show "$show")"
  else
    pass="${show#*:}"
  fi
  [[ -n "$pass" ]] || return 1
  printf '%s' "$pass"
}

_enc_john_raw_crack() {
  local hash_val="$1" wordlist="$2" fmt="$3" tier="${4:-full}" kind_label="${5:-md5}"
  local out_dir hash_file pot_file pass session rules report_cmd
  local -a rule_passes=()

  typeset -g _ENC_HASH_CRACK_OUT=""

  if [[ -z "$wordlist" || ! -f "$wordlist" ]] || ! command -v john >/dev/null 2>&1; then
    _enc_try_log "$kind_label"
    return 1
  fi

  _enc_ui_trying "$kind_label"
  _enc_ui_status_john "$tier" "$wordlist"

  case "$tier" in
    quick) rule_passes=("" ) ;;
    heavy) rule_passes=("Single") ;;
    full|*) rule_passes=("" "Single") ;;
  esac

  out_dir="${TMPDIR:-/tmp}/enc-john-$$"
  mkdir -p "$out_dir"
  hash_file="$out_dir/hash.txt"
  pot_file="$out_dir/john.pot"

  print -r -- "$hash_val" >"$hash_file"

  for rules in "${rule_passes[@]}"; do
    session="enc-$$-${EPOCHSECONDS}-${RANDOM}-${kind_label}-${rules:-plain}"
    rm -f "$pot_file"
    if [[ -n "$rules" ]]; then
      john --session="$session" --format="$fmt" "$hash_file" --wordlist="$wordlist" \
        --rules="$rules" --pot="$pot_file" >/dev/null 2>&1 || true
    else
      john --session="$session" --format="$fmt" "$hash_file" --wordlist="$wordlist" \
        --pot="$pot_file" >/dev/null 2>&1 || true
    fi
    if pass="$(_enc_john_show_pass "$fmt" "$hash_file" "$pot_file")"; then
      typeset -g _ENC_HASH_CRACK_OUT="$pass"
      report_cmd="john --format=$fmt --wordlist=${(q)wordlist}"
      [[ -n "$rules" ]] && report_cmd+=" --rules=$rules"
      report_cmd+=" <hash>"
      _enc_set_crack_report "$report_cmd"
      _enc_try_log "$kind_label" "$pass"
      rm -rf "$out_dir"
      return 0
    fi
  done

  _enc_try_log "$kind_label"
  rm -rf "$out_dir"
  return 1
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
  local hash_val="$1" wordlist="${2:-${RECON_PASSLIST:-}}" kind="${3:-}" tier="${4:-full}"
  local show pass log_kind="${kind:-$(_enc_hash_fmt_kind "$hash_val")}"

  typeset -g _ENC_HASH_CRACK_OUT=""

  if [[ -z "$wordlist" || ! -f "$wordlist" ]]; then
    _enc_try_log "${log_kind:-md5}"
    return 1
  fi

  case "$kind" in
    md4)
      _enc_john_raw_crack "$hash_val" "$wordlist" Raw-MD4 "$tier" md4
      return $?
      ;;
    ntlm)
      _enc_john_raw_crack "$hash_val" "$wordlist" NT "$tier" ntlm
      return $?
      ;;
    sha1)
      _enc_john_raw_crack "$hash_val" "$wordlist" Raw-SHA1 "$tier" sha1
      return $?
      ;;
    sha256)
      _enc_john_raw_crack "$hash_val" "$wordlist" Raw-SHA256 "$tier" sha256
      return $?
      ;;
  esac

  [[ "$tier" == heavy ]] || return 1

  whence hash-crack >/dev/null 2>&1 || {
    _enc_try_log "${log_kind:-md5}"
    return 1
  }
  _enc_ui_trying "${log_kind:-md5}"
  _enc_ui_status "hash-crack $(_enc_wl_short "$wordlist")"
  show="$(hash-crack "$hash_val" "$wordlist" 2>/dev/null)" || true
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
  )" || {
    _enc_try_log "${log_kind:-md5}"
    return 1
  }
  [[ -n "$pass" ]] || {
    _enc_try_log "${log_kind:-md5}"
    return 1
  }
  _enc_set_crack_report "hash-crack <hash> ${(q)wordlist}"
  _enc_try_log "${log_kind:-md5}" "$pass"
  typeset -g _ENC_HASH_CRACK_OUT="$pass"
  return 0
}

_enc_hash_crack_tier() {
  local hash_val="$1" wordlist="$2" kind="$3" tier="$4"
  local pass wl="${wordlist:-$RECON_PASSLIST}"

  case "$kind" in
    md4)
      if _enc_hash_crack_pass "$hash_val" "$wl" md4 "$tier"; then
        pass="$_ENC_HASH_CRACK_OUT"
        _ENC_HASH_REVERSE_KIND=md4
        _ENC_HASH_REVERSE_OUT="$pass"
        return 0
      fi
      ;;
    ntlm)
      if _enc_hash_crack_pass "$hash_val" "$wl" ntlm "$tier"; then
        pass="$_ENC_HASH_CRACK_OUT"
        _ENC_HASH_REVERSE_KIND=ntlm
        _ENC_HASH_REVERSE_OUT="$pass"
        return 0
      fi
      ;;
    sha1)
      if _enc_hash_crack_pass "$hash_val" "$wl" sha1 "$tier"; then
        pass="$_ENC_HASH_CRACK_OUT"
        _ENC_HASH_REVERSE_KIND=sha1
        _ENC_HASH_REVERSE_OUT="$pass"
        return 0
      fi
      if [[ "$tier" == heavy ]]; then
        if _enc_hash_crack_pass "$hash_val" "$wl" sha1 heavy; then
          pass="$_ENC_HASH_CRACK_OUT"
          _ENC_HASH_REVERSE_KIND=sha1
          _ENC_HASH_REVERSE_OUT="$pass"
          return 0
        fi
      fi
      ;;
    hash64)
      if _enc_hash_crack_pass "$hash_val" "$wl" sha256 "$tier"; then
        pass="$_ENC_HASH_CRACK_OUT"
        _ENC_HASH_REVERSE_KIND=sha256
        _ENC_HASH_REVERSE_OUT="$pass"
        return 0
      fi
      if [[ "$tier" == heavy ]]; then
        if _enc_hash_crack_pass "$hash_val" "$wl" sha256 heavy; then
          pass="$_ENC_HASH_CRACK_OUT"
          _ENC_HASH_REVERSE_KIND=sha256
          _ENC_HASH_REVERSE_OUT="$pass"
          return 0
        fi
      fi
      ;;
    md5)
      if [[ "$tier" == heavy ]]; then
        if _enc_hash_crack_pass "$hash_val" "$wl" md5 heavy; then
          pass="$_ENC_HASH_CRACK_OUT"
          _ENC_HASH_REVERSE_KIND=md5
          _ENC_HASH_REVERSE_OUT="$pass"
          return 0
        fi
      fi
      ;;
    hash32)
      if [[ "$tier" == heavy ]]; then
        if _enc_hash_crack_pass "$hash_val" "$wl" md4 heavy; then
          pass="$_ENC_HASH_CRACK_OUT"
          _ENC_HASH_REVERSE_KIND=md4
          _ENC_HASH_REVERSE_OUT="$pass"
          return 0
        fi
        if _enc_hash_crack_pass "$hash_val" "$wl" md5 heavy; then
          pass="$_ENC_HASH_CRACK_OUT"
          _ENC_HASH_REVERSE_KIND=md5
          _ENC_HASH_REVERSE_OUT="$pass"
          return 0
        fi
      fi
      ;;
  esac
  return 1
}

_enc_heavy_steps_label() {
  local hash_val="$1" kind="${2:-}" fmt
  if [[ -z "$kind" ]]; then
    if [[ "$hash_val" == *'$'* ]]; then
      _enc_try_label "$(_enc_hash_fmt_kind "$hash_val")"
      return 0
    fi
    kind="$(_enc_hash_kind "$hash_val")"
  fi
  case "$kind" in
    hash32) print -r -- 'MD4, MD5' ;;
    md4) print -r -- MD4 ;;
    md5) print -r -- MD5 ;;
    ntlm) print -r -- NTLM ;;
    sha1) print -r -- SHA-1 ;;
    hash64|sha256) print -r -- SHA-256 ;;
    *)
      fmt="$(_enc_hash_fmt_kind "$hash_val")"
      [[ -n "$fmt" ]] && _enc_try_label "$fmt"
      ;;
  esac
}

_enc_confirm_heavy_hash() {
  local hash_val="$1" wordlist="$2"
  local wl_t="${wordlist:-${RECON_PASSLIST:-}}" steps
  wl_t="${wl_t:t}"

  if [[ ! -t 0 || ! -t 2 ]]; then
    return 1
  fi

  steps="$(_enc_heavy_steps_label "$hash_val")"
  if _enc_ui_active; then
    _enc_ui_status_inline "heavy crack? $steps ($wl_t ~20s) [y/N] "
    read -r "ans" </dev/tty
    print '' >&2
    _enc_ui_after_prompt
  else
    printf '? %s (%s ~20s) [y/N] ' "$steps" "$wl_t" >&2
    read -r "ans? " </dev/tty
    printf '\e[1A\e[2K' >&2
  fi
  [[ "$ans" == [yY] || "$ans" == [yY][eE][sS] ]]
}

_enc_hash_reverse() {
  local hash_val="${1//[$' \t\r\n']/}" wordlist="$2" offline="${3:-0}" no_crack="${4:-0}"
  local forced_kind="${5:-}" phase="${6:-full}"
  local pass kind
  local -a kinds=()

  typeset -g _ENC_HASH_REVERSE_KIND=""
  typeset -g _ENC_HASH_REVERSE_OUT=""

  if [[ -n "$forced_kind" ]]; then
    kinds=("$forced_kind")
  else
    kinds=("${(@f)$(_enc_hash_candidates "$hash_val")}")
  fi
  (( ${#kinds[@]} )) || return 1

  if [[ "$phase" == full || "$phase" == quick ]]; then
    local md5_found=""
    if (( ${kinds[(I)md5]} )); then
      _enc_ui_trying md5
      _enc_ui_status "rainbow table"
      pass="$(_enc_hash_rainbow_lookup "$hash_val")"
      if [[ -z "$pass" && "$offline" -eq 0 ]]; then
        _enc_ui_status "online lookup"
        pass="$(_enc_hash_online_lookup "$hash_val" md5)"
      fi
      if [[ -n "$pass" ]]; then
        _enc_try_log md5 "$pass"
        _ENC_HASH_REVERSE_KIND=md5
        _ENC_HASH_REVERSE_OUT="$pass"
        md5_found="$pass"
      else
        _enc_try_log md5
      fi
    fi

    if [[ "$no_crack" -eq 0 ]]; then
      for kind in "${kinds[@]}"; do
        [[ "$kind" == md5 && -n "$md5_found" ]] && continue
        _enc_hash_crack_tier "$hash_val" "$wordlist" "$kind" quick && return 0
      done
      [[ -n "$md5_found" ]] && return 0
    elif [[ -n "$md5_found" ]]; then
      return 0
    fi
  fi

  if [[ "$phase" == full || "$phase" == heavy ]] && [[ "$no_crack" -eq 0 ]]; then
    for kind in "${kinds[@]}"; do
      _enc_hash_crack_tier "$hash_val" "$wordlist" "$kind" heavy && return 0
    done
  fi

  return 1
}

_enc_hash_encode() {
  local kind="$1" raw="$2"
  case "$kind" in
    md4)
      _enc_md4_hex "$raw"
      ;;
    md5)
      printf '%s' "$raw" | md5sum | awk '{print $1}'
      ;;
    ntlm)
      RAW="$raw" python3 <<'PY'
import hashlib, os
raw = os.environ["RAW"]
print(hashlib.new("md4", raw.encode("utf-16le")).hexdigest())
PY
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

_enc_bin_bits() {
  local data="$1"
  DATA="$data" python3 <<'PY'
import os, re, sys

s = os.environ["DATA"].strip()
if not s:
    sys.exit(1)

if re.fullmatch(r"[01]+", s):
    bits = s
elif re.fullmatch(r"[01 \r\n]+", s):
    groups = [g for g in re.split(r"\s+", s) if g]
    if not groups or not all(re.fullmatch(r"[01]+", g) and len(g) % 8 == 0 for g in groups):
        sys.exit(1)
    bits = "".join(groups)
else:
    sys.exit(1)

if not bits or len(bits) % 8:
    sys.exit(1)
print(bits, end="")
PY
}

_enc_bin_p() {
  local data="$1"
  _enc_bin_bits "$data" >/dev/null 2>&1
}

_bin_try_decode() {
  local data="$1" bits
  bits="$(_enc_bin_bits "$data")" || return 1
  DATA="$bits" python3 <<'PY'
import os, sys

bits = os.environ["DATA"]
if not bits or len(bits) % 8:
    sys.exit(1)
try:
    b = int(bits, 2).to_bytes(len(bits) // 8, "big")
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

_enc_morse_p() {
  local data="$1"
  [[ "$data" == *[.-]* ]] || return 1
  DATA="$data" python3 -c 'import os,re,sys; s=os.environ["DATA"]; sys.exit(0 if s and re.fullmatch(r"[./ \r\n-]+",s) and re.search(r"[.-]",s) else 1)'
}

_enc_morse_try_decode() {
  local data="$1"
  DATA="$data" python3 <<'PY'
import os, re, sys

s = os.environ["DATA"].strip()
if not s or not re.fullmatch(r"[./ \r\n-]+", s) or not re.search(r"[.-]", s):
    sys.exit(1)

morse = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'", "-.-.--": "!",
    "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":",
    "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@", "...---...": "SOS",
}

_WORD_FILES = (
    "/usr/share/seclists/Miscellaneous/lang-english.txt",
    "/usr/share/dict/words",
    "/usr/share/dict/american-english",
    "/usr/share/dict/british-english",
)
_word_dict = None


def _word_dict_load():
    global _word_dict
    if _word_dict is not None:
        return _word_dict
    words = set()
    for path in _WORD_FILES:
        try:
            with open(path) as f:
                for line in f:
                    w = line.strip().lower()
                    if len(w) >= 3 and w.isalpha():
                        words.add(w)
        except OSError:
            continue
        if words:
            break
    _word_dict = words
    return words


def _segment_alpha(text):
    words = _word_dict_load()
    if not words:
        return text
    lower = text.lower()
    n = len(text)
    dp = [None] * (n + 1)
    dp[0] = []
    for i in range(1, n + 1):
        for j in range(max(0, i - 24), i):
            w = lower[j:i]
            if len(w) < 3 or dp[j] is None or w not in words:
                continue
            cand = dp[j] + [text[j:i]]
            if dp[i] is None or len(cand) < len(dp[i]):
                dp[i] = cand
    if dp[n] and len(dp[n]) > 1:
        return " ".join(dp[n])
    return text


MORSE_CODES = sorted(morse.keys(), key=len, reverse=True)
BINARY = {"-----", ".----"}


def tokenize_binary_dp(seg):
    memo = {}

    def go(i):
        if i == len(seg):
            return []
        if i in memo:
            return memo[i]
        for code in (".----", "-----"):
            if seg.startswith(code, i):
                rest = go(i + 5)
                if rest is not None:
                    memo[i] = [code] + rest
                    return memo[i]
        memo[i] = None
        return None

    return go(0)


def split_binary_segment(seg):
    if seg in BINARY:
        return [seg]
    if not re.fullmatch(r"[.-]+", seg):
        return None
    if len(seg) % 5 == 0:
        parts = [seg[i : i + 5] for i in range(0, len(seg), 5)]
        if all(p in BINARY for p in parts):
            return parts
    toks = tokenize_binary_dp(seg)
    if toks is not None:
        return toks
    if re.fullmatch(r"-{6,}", seg) and len(seg) % 5 == 0:
        return ["-----"] * (len(seg) // 5)
    return None


def tokenize_greedy(seg):
    tokens = []
    i = 0
    while i < len(seg):
        matched = False
        for code in MORSE_CODES:
            if seg.startswith(code, i):
                tokens.append(code)
                i += len(code)
                matched = True
                break
        if not matched:
            return None
    return tokens


def expand_tokens(chunk):
    tokens = []
    for seg in re.split(r" +", chunk.strip()):
        if not seg:
            continue
        if seg in morse:
            tokens.append(seg)
        elif re.fullmatch(r"[.-]+", seg):
            toks = split_binary_segment(seg)
            if toks is None:
                toks = tokenize_greedy(seg)
            if toks is None:
                return None
            tokens.extend(toks)
        else:
            return None
    return tokens


explicit_sep = bool(re.search(r"(?:/|[\r\n]+| {3,})", s))
chunks = [w.strip() for w in re.split(r"(?:/|[\r\n]+| {3,})", s) if w.strip()]
if not chunks:
    sys.exit(1)

all_tokens = []
for chunk in chunks:
    toks = expand_tokens(chunk)
    if not toks:
        sys.exit(1)
    all_tokens.extend(toks)

if all(t in BINARY for t in all_tokens):
    bits = "".join(morse[t] for t in all_tokens)
    groups = [bits[i : i + 8] for i in range(0, len(bits) - len(bits) % 8, 8)]
    if not groups:
        sys.exit(1)
    print(" ".join(groups), end="")
    sys.exit(0)

out_words = []
for chunk in chunks:
    toks = expand_tokens(chunk)
    letters = []
    for tok in toks:
        ch = morse.get(tok)
        if not ch:
            sys.exit(1)
        letters.append(ch)
    text = "".join(letters)
    if not explicit_sep and len(text) >= 8 and text.isalpha():
        text = _segment_alpha(text)
    out_words.append(text)

print(" ".join(out_words), end="")
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
  local rc=0
  _ENC_CRACK_REPORT=""
  if _enc_ui_setup; then
    _enc_ui_plan "$1" "${2:-0}" "$3" "${4:-0}"
  fi
  _enc_smart_decode_core "$@" || rc=$?
  _enc_ui_teardown
  _enc_print_crack_report
  return $rc
}

_enc_smart_decode_core() {
  local data="$1" offline="${2:-0}" wordlist="$3" no_crack="${4:-0}" assume_yes="${5:-0}"
  local out kind found=0 tail
  typeset -A seen

  if [[ "$data" != *'$'* && "$data" == *:* ]]; then
    tail="${data##*:}"
    if [[ "$tail" =~ '^[0-9A-Za-z+/=_-]+$' && ${#tail} -ge 4 ]]; then
      data="$tail"
    fi
  fi

  _enc_hit() {
    local tag="$1" val="$2" log_try="${3:-1}"
    [[ -n "$val" && -z "${seen[$val]:-}" ]] || return 1
    case "$tag" in
      b64|b32|b58|b62|b10|hex|bin)
        _enc_printable_p "$val" || return 1
        ;;
    esac
    seen[$val]=1
    (( log_try )) && _enc_try_log "$tag" "$val"
    case "$tag" in
      md4|md5|sha1|sha256|bcrypt|md5crypt|sha512crypt|sha256crypt|argon2)
        # TTY + UI table already shows the password; stdout is for pipes only
        if [[ ! -t 1 ]] || ! _enc_ui_active; then
          print -r -- "$val"
        fi
        ;;
      *)
        [[ ! -t 1 ]] && print -r -- "$val"
        ;;
    esac
    found=1
  }

  if _enc_bin_p "$data"; then
    if out="$(_bin_try_decode "$data")"; then
      _enc_hit bin "$out"
    else
      _enc_try_log bin
    fi
    (( found )) && return 0
    echo "enc: no match" >&2
    return 1
  fi

  kind="$(_enc_hash_kind "$data")"
  if [[ -n "$kind" ]]; then
    if out="$(_enc_hash_pot_lookup "$data")"; then
      _enc_hit "$(_enc_hash_log_kind "$kind")" "$out"
      return 0
    fi
    if _enc_hash_reverse "$data" "$wordlist" "$offline" "$no_crack" "" quick; then
      _enc_hit "${_ENC_HASH_REVERSE_KIND:-$(_enc_hash_log_kind "$kind")}" "$_ENC_HASH_REVERSE_OUT" 0
    fi
    if (( ! found )) && [[ "$no_crack" -eq 0 ]]; then
      if (( assume_yes )) || _enc_confirm_heavy_hash "$data" "$wordlist"; then
        if _enc_hash_reverse "$data" "$wordlist" "$offline" 0 "" heavy; then
          _enc_hit "${_ENC_HASH_REVERSE_KIND:-$(_enc_hash_log_kind "$kind")}" "$_ENC_HASH_REVERSE_OUT" 0
        fi
      fi
    fi
    (( found )) && return 0
    echo "enc: no match" >&2
    return 1
  fi

  if [[ "$data" =~ '^[0-9]+$' ]]; then
    if out="$(_b10_try_decode "$data")"; then
      _enc_hit b10 "$out"
    else
      _enc_try_log b10
    fi
    (( found )) && return 0
    echo "enc: no match" >&2
    return 1
  fi

  if _enc_ascii_dec_p "$data"; then
    if out="$(_enc_ascii_dec_try_decode "$data")"; then
      _enc_hit ascii "$out"
    else
      _enc_try_log ascii
    fi
    (( found )) && return 0
    echo "enc: no match" >&2
    return 1
  fi

  if _enc_morse_p "$data"; then
    if out="$(_enc_morse_try_decode "$data")"; then
      _enc_hit morse "$out"
    else
      _enc_try_log morse
    fi
    (( found )) && return 0
    echo "enc: no match" >&2
    return 1
  fi

  if [[ "$data" =~ '^[0-9a-fA-F]+$' ]] && (( ${#data} % 2 == 0 )); then
    if out="$(_hex_try_decode "$data")"; then
      _enc_hit hex "$out"
    else
      _enc_try_log hex
    fi
  fi

  if out="$(_b10_try_decode "$data")"; then
    _enc_hit b10 "$out"
  else
    _enc_try_log b10
  fi
  if out="$(_b64_try_decode "$data")"; then
    _enc_hit b64 "$out"
  else
    _enc_try_log b64
  fi
  if out="$(_b32_try_decode "$data")"; then
    _enc_hit b32 "$out"
  else
    _enc_try_log b32
  fi
  if out="$(_b58_try_decode "$data")"; then
    _enc_hit b58 "$out"
  else
    _enc_try_log b58
  fi
  if out="$(_b62_try_decode "$data")"; then
    _enc_hit b62 "$out"
  else
    _enc_try_log b62
  fi

  local rot_hits=0
  while IFS= read -r out; do
    [[ -n "$out" ]] || continue
    local tag="${out%% *}" rest="${out#* }"
    _enc_hit "$tag" "$rest"
    rot_hits=1
  done < <(_enc_rot_flag_hits "$data")
  (( rot_hits )) || _enc_try_log rot

  (( found )) && return 0

  if [[ "$no_crack" -eq 0 && "$data" == *'$'* ]]; then
    if (( assume_yes )) || _enc_confirm_heavy_hash "$data" "${wordlist:-$RECON_PASSLIST}"; then
      if _enc_hash_crack_pass "$data" "${wordlist:-$RECON_PASSLIST}" "" heavy; then
        _enc_hit "$(_enc_hash_fmt_kind "$data")" "$_ENC_HASH_CRACK_OUT" 0
        return 0
      fi
    else
      _enc_try_log "$(_enc_hash_fmt_kind "$data")"
    fi
  fi

  echo "enc: no match" >&2
  return 1
}

_enc_try_all_decode() {
  _enc_smart_decode "$@"
}

_enc_hash_decode() {
  local data="$1" offline="$2" wordlist="$3" no_crack="$4" assume_yes="$5" type="$6"
  _ENC_CRACK_REPORT=""
  if [[ -z "$type" ]]; then
    _enc_smart_decode "$data" "$offline" "$wordlist" "$no_crack" "$assume_yes"
    return $?
  fi
  local rc=0
  if _enc_ui_setup; then
    _enc_ui_init "$type"
  fi
  _enc_hash_valid_hex "$data" "$type" || {
    _enc_ui_teardown
    echo "enc: input is not a valid $type hex hash" >&2
    return 1
  }
  if _enc_hash_reverse "$data" "$wordlist" "$offline" "$no_crack" "$type" full; then
    print -r -- "$_ENC_HASH_REVERSE_OUT"
  else
    echo "enc: $type hash unresolved (try: enc -d -y -w other-wordlist)" >&2
    rc=1
  fi
  _enc_ui_teardown
  _enc_print_crack_report
  return $rc
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
  emulate -L zsh
  local type="" mode="" file="" data="" raw="" wordlist="" out="" offline=0 no_crack=0 assume_yes=0
  local -a positional=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: enc -d|-e [input]          smart decode / encode"
        echo "       enc -t b64|b32|b58|b62|b10|bin|md4|md5|ntlm|sha1|sha256 -d|-e [input]"
        echo "       enc -d -f <file>  |  ... | enc -d"
        echo ""
        echo "enc -d (no -t): quick decode first; heavy hash steps ask [y/N]"
        echo "  hash hints: clear formats use built-in rules; ambiguous hashes use name-that-hash when available"
        echo "  quick: rainbow / online md5 / john wordlist (no rules)"
        echo "  heavy: john --rules=Single + hash-crack (~20s on rockyou)"
        echo "  >> prefix = flag-like (THM{ HTB{ flag{ ...)"
        echo ""
        echo "options:"
        echo "  -d        decode"
        echo "  -e        encode"
        echo "  -t TYPE   force one type (b64 b32 b58 b62 b10 bin md4 md5 ntlm sha1 sha256)"
        echo "  -f FILE   read input from file"
        echo "  -w FILE   wordlist for hash-crack (default: \$RECON_PASSLIST)"
        echo "  -y, --yes run heavy hash steps without prompt"
        echo "  --offline skip online md5 lookup"
        echo "  --no-crack skip john / hash-crack entirely"
        echo ""
        echo "examples:"
        echo "  enc -d QXJlYTUx"
        echo "  enc -d a18672860d0510e5ab6699730763b250"
        echo "  enc -d ObsJmP173N2X6dOrAgEAL0Vu"
        echo "  alias: dec (= enc -d)"
        echo "  legacy: b64d b64e b32d b32e b58d b58e b62d b62e b10d b10e"
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
      -y|--yes)
        assume_yes=1
        shift
        ;;
      --)
        shift
        positional+=("$@")
        break
        ;;
      -*)
        # Encoded strings may start with '-' (base64url, etc.); after -d/-e treat as input.
        if [[ -n "$mode" ]]; then
          positional+=("$1")
          shift
        else
          echo "enc: unknown option: $1" >&2
          return 1
        fi
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
      md4|md5|ntlm|sha1|sha256) ;;
      *)
        echo "enc: unknown type: $type (use b64, b32, b58, b62, b10, bin, md4, md5, ntlm, sha1, or sha256)" >&2
        return 1
        ;;
    esac
  fi

  if [[ "$mode" == de ]]; then
    if [[ -z "$type" ]]; then
      data="$(_enc_read 0 "$file" "${positional[@]}")" || {
        echo "enc: no input (arg, -f, or stdin)" >&2
        return 1
      }
      [[ -n "$data" ]] || { echo "enc: empty input" >&2; return 1; }
      _enc_smart_decode "$data" "$offline" "$wordlist" "$no_crack" "$assume_yes"
      return $?
    fi

    data="$(_enc_read 1 "$file" "${positional[@]}")" || {
      echo "enc: no input (arg, -f, or stdin)" >&2
      return 1
    }
    [[ -n "$data" ]] || { echo "enc: empty input" >&2; return 1; }

    case "$type" in
      b64) _b64_decode_bytes "$data" && print ;;
      b32) _b32_decode_bytes "$data" && print ;;
      b58) _b58_decode_bytes "$data" && print ;;
      b62) _b62_decode_bytes "$data" && print ;;
      b10) _b10_decode_bytes "$data" && print ;;
      bin) _bin_decode_bytes "$data" && print ;;
      md4|md5|ntlm|sha1|sha256)
        _enc_hash_decode "$data" "$offline" "$wordlist" "$no_crack" 1 "$type"
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
    md4|md5|ntlm|sha1|sha256)
      _enc_hash_encode "$type" "$raw"
      ;;
  esac
}

_rot_parse_range() {
  local spec="$1" max="$2"
  local start end
  if [[ -z "$spec" ]]; then
    print -r -- 0 "$max"
    return 0
  fi
  if [[ "$spec" == *-* ]]; then
    start="${spec%%-*}"
    end="${spec#*-}"
  else
    start="$spec"
    end="$spec"
  fi
  if [[ ! "$start" =~ '^[0-9]+$' || ! "$end" =~ '^[0-9]+$' ]]; then
    echo "rot: -n needs 0-${max}, N, or START-END" >&2
    return 1
  fi
  if (( start < 0 || end > max || start > end )); then
    echo "rot: shift range must be within 0-${max}" >&2
    return 1
  fi
  print -r -- "$start" "$end"
}

_rot_caesar_shift() {
  local data="$1" start="$2" end="$3"
  START="$start" END="$end" DATA="$data" python3 <<'PY'
import os

s = os.environ["DATA"]
start = int(os.environ["START"])
end = int(os.environ["END"])
single = start == end
for n in range(start, end + 1):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    text = "".join(out)
    if single:
        print(text)
    else:
        print("{:2d} {}".format(n, text))
PY
}

_rot_printable_shift_all() {
  local data="$1" start="$2" end="$3"
  START="$start" END="$end" DATA="$data" python3 <<'PY'
import os

s = os.environ["DATA"]
start = int(os.environ["START"])
end = int(os.environ["END"])
single = start == end
for n in range(start, end + 1):
    out = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 + n) % 94)))
        else:
            out.append(c)
    text = "".join(out)
    if single:
        print(text)
    else:
        print("{:2d} {}".format(n, text))
PY
}

_rot_cipher_mode() {
  local spec="$1"
  local start end
  if [[ -z "$spec" ]]; then
    print -r -- caesar
    return 0
  fi
  if [[ "$spec" == *-* ]]; then
    start="${spec%%-*}"
    end="${spec#*-}"
  else
    start="$spec"
    end="$spec"
  fi
  if [[ ! "$start" =~ '^[0-9]+$' || ! "$end" =~ '^[0-9]+$' ]]; then
    echo "rot: -n needs N or START-END" >&2
    return 1
  fi
  if (( start > 25 || end > 25 )); then
    print -r -- printable
  else
    print -r -- caesar
  fi
}

# rot: Caesar 0-25 (A-Za-z). -n >25 switches to printable ASCII (ROT47 etc.)
rot() {
  local file="" data="" rot_range="" cipher=caesar
  local rot_start=0 rot_end=25 rot_max=25
  local -a positional=() range

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: rot <string>                  # Caesar: shifts 0-25"
        echo "       rot -n 13 <string>            # Caesar: ROT13"
        echo "       rot -n 47 <string>            # ROT47 (printable !..~, shift 47)"
        echo "       rot -n 0-93 <string>          # printable: all shifts"
        echo "       rot -f <file>  |  ... | rot"
        echo ""
        echo "  -n 0-25     Caesar (A-Za-z only)"
        echo "  -n 26-93    printable ASCII !..~ (ROT47 = -n 47)"
        echo "  default     Caesar 0-25"
        echo ""
        echo "alias: rotall (= rot)"
        return 0
        ;;
      -a) shift ;;
      -n)
        rot_range="$2"
        shift 2
        ;;
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

  cipher="$(_rot_cipher_mode "$rot_range")" || return 1
  if [[ "$cipher" == printable ]]; then
    rot_max=93
    rot_start=0
    rot_end=93
  fi

  if [[ -n "$rot_range" ]]; then
    range=($(_rot_parse_range "$rot_range" "$rot_max")) || return 1
    rot_start="${range[1]}"
    rot_end="${range[2]}"
  fi

  data="$(_enc_read 0 "$file" "${positional[@]}")" || {
    echo "rot: no input (arg, -f, or stdin)" >&2
    return 1
  }
  [[ -n "$data" ]] || { echo "rot: empty input" >&2; return 1; }

  if [[ "$cipher" == printable ]]; then
    _rot_printable_shift_all "$data" "$rot_start" "$rot_end"
  else
    _rot_caesar_shift "$data" "$rot_start" "$rot_end"
  fi
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
        echo "  legacy: vigd vige vigall vigkey"
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

  data="$(_enc_read 0 "$file" "${positional[@]}")" || {
    if [[ "$mode" == key && -n "$plain" ]]; then
      echo "vig: -K needs cipher text (arg, -f, or stdin)" >&2
    else
      echo "vig: no input (arg, -f, or stdin)" >&2
    fi
    return 1
  }
  data="$(_enc_chomp_trailing_eol "$data")"
  [[ -n "$data" ]] || { echo "vig: empty input" >&2; return 1; }

  case "$mode" in
    de|en)
      local result
      result="$(python3 -c '
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
' "$mode" "$data" "$key")" || return 1
      _vig_print_result "$mode" "$data" "$result"
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
  if (( $# )); then
    enc -d "$@"
  else
    enc -d
  fi
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
    -f) rot -f "$2" ;;
    "")
      [[ -t 0 ]] && { echo "usage: rotall <string>  (see: rot ...)" >&2; return 1; }
      rot
      ;;
    *) rot "$@" ;;
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
