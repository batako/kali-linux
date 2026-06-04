# ========================
# base64 helpers
# ========================

_b64_squash() {
  tr -d '[:space:]'
}

_b64_decode_bytes() {
  local data="$1"
  if printf '%s' "$data" | base64 -d 2>/dev/null; then
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "$data" | openssl base64 -d -A 2>/dev/null && return 0
  fi
  echo "b64d: invalid base64" >&2
  return 1
}

# Decode base64. Whitespace in input is ignored.
# usage: b64d <string>
#        b64d -f <file>
#        echo QXJlYTUx | b64d
#        x "b64d QXJlYTUx"
b64d() {
  local data=""

  case "${1:-}" in
    -h|--help)
      echo "usage: b64d <string>"
      echo "       b64d -f <file>"
      echo "       ... | b64d"
      return 0
      ;;
    -f)
      [[ -f "${2:-}" ]] || { echo "b64d: file not found: ${2:-}" >&2; return 1; }
      data="$(<"$2" | _b64_squash)" || return 1
      ;;
    "")
      if [[ -t 0 ]]; then
        echo "usage: b64d <string> | b64d -f <file> | ... | b64d"
        return 1
      fi
      data="$(cat | _b64_squash)" || return 1
      ;;
    *)
      data="$(printf '%s' "$*" | _b64_squash)" || return 1
      ;;
  esac

  [[ -n "$data" ]] || { echo "b64d: empty input" >&2; return 1; }
  _b64_decode_bytes "$data" && print
}

# Encode to base64 (single line, no trailing newline).
# usage: b64e <string>
#        b64e -f <file>
#        ... | b64e
b64e() {
  local raw=""

  case "${1:-}" in
    -h|--help)
      echo "usage: b64e <string>"
      echo "       b64e -f <file>"
      echo "       ... | b64e"
      return 0
      ;;
    -f)
      [[ -f "${2:-}" ]] || { echo "b64e: file not found: ${2:-}" >&2; return 1; }
      raw="$(<"$2")"
      ;;
    "")
      if [[ -t 0 ]]; then
        echo "usage: b64e <string> | b64e -f <file> | ... | b64e"
        return 1
      fi
      raw="$(cat)"
      ;;
    *)
      raw="$*"
      ;;
  esac

  printf '%s' "$raw" | base64 | tr -d '\n'
  print
}
