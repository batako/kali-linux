# ========================
# recon hints
# ========================

_hint-add() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: hint-add [-t tag] text..." "使い方: hint-add [-t タグ] text..."
    _toolkit-echo "  alias: ha" "  alias: ha"
    _toolkit-echo "examples:" "例:"
    _toolkit-echo "  hint-add go!go!go!" "  hint-add go!go!go!"
    _toolkit-echo "  hint-add -t codeword vigilante" "  hint-add -t codeword vigilante"
    _toolkit-echo "  hint-add -t island-page 'The Code Word is: ...'" "  hint-add -t island-page 'The Code Word is: ...'"
    _toolkit-echo "  hint-add -t codeword -   # paste via stdin" "  hint-add -t codeword -   # stdin から貼り付け"
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
    _toolkit-echo "usage: hint-list" "使い方: hint-list"
    _toolkit-echo "  alias: hl" "  alias: hl"
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
    _toolkit-echo "usage: hint-rm <hint_id>" "使い方: hint-rm <hint_id>"
    _toolkit-echo "  alias: hr" "  alias: hr"
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
