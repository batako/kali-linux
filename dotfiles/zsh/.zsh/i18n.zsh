# ========================
# toolkit i18n helpers
# ========================

_toolkit-lang() {
  local raw="${TOOLKIT_LANG:-en}"
  raw="${raw:l}"
  if [[ "$raw" == ja || "$raw" == ja_* || "$raw" == ja-* ]]; then
    echo "ja"
    return
  fi
  echo "en"
}

_toolkit-lang-ja() {
  [[ "$(_toolkit-lang)" == "ja" ]]
}

_toolkit-echo() {
  local en="$1"
  local ja="$2"
  if _toolkit-lang-ja; then
    print -r -- "$ja"
  else
    print -r -- "$en"
  fi
}

_toolkit-echo-err() {
  local en="$1"
  local ja="$2"
  if _toolkit-lang-ja; then
    print -r -- "$ja" >&2
  else
    print -r -- "$en" >&2
  fi
}
