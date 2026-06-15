# ========================
# recon hints
# ========================

_hint-add() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: hint-add [-t tag] text..."
    echo "  alias: ha"
    echo "examples:"
    echo "  hint-add go!go!go!"
    echo "  hint-add -t codeword vigilante"
    echo "  hint-add -t island-page 'The Code Word is: ...'"
    echo "  hint-add -t codeword -   # paste via stdin"
    return 0
  fi

  local tag=""
  local -a text_parts=()

  if [[ -z "${CASE:-}" ]]; then
    echo "[-] case-set <room> first" >&2
    return 1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--tag)
        [[ -n "${2:-}" ]] || { echo "usage: hint-add [-t tag] text..." >&2; echo "  alias: ha" >&2; return 1; }
        tag="$2"; shift 2 ;;
      --)
        shift
        text_parts+=("$@")
        break ;;
      -)
        if [[ $# -eq 1 ]]; then
          local stdin_text
          stdin_text="$(cat)"
          [[ -n "$stdin_text" ]] && text_parts+=("$stdin_text")
          break
        fi
        text_parts+=("$1"); shift ;;
      *)
        text_parts+=("$1"); shift ;;
    esac
  done

  if [[ ${#text_parts[@]} -eq 0 ]]; then
    echo "usage: hint-add [-t tag] text..." >&2
    echo "  alias: ha" >&2
    return 1
  fi

  local -a args=(hint-add)
  [[ -n "$tag" ]] && args+=(-t "$tag")
  args+=(-- "${text_parts[@]}")
  python3 "$RECON_APP" "${args[@]}"
}

hint-add() { _hint-add "$@"; }

hint-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: hint-list"
    echo "  alias: hl"
    return 0
  fi
  if [[ -z "${CASE:-}" ]]; then
    echo "[-] case-set <room> first" >&2
    return 1
  fi
  python3 "$RECON_APP" hint-list
}

hint-rm() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: hint-rm <hint_id>"
    echo "  alias: hr"
    return 0
  fi
  if [[ $# -lt 1 ]]; then
    echo "usage: hint-rm <hint_id>" >&2
    echo "  alias: hr" >&2
    return 1
  fi
  python3 "$RECON_APP" hint-rm "$1"
}

alias ha='noglob _hint-add'
alias hl='hint-list'
alias hr='hint-rm'
