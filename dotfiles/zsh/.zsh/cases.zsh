# ========================
# cases (per-room / per-scope workspace)
# ========================
#
# File outputs (listen -l, sshkey-crack, …) need a case directory.
#
# Default (strict): case unset → error. Use: cs <room>
# Optional:         export CASE_LOOSE=1 → fallback to cases/_unscoped/ + warning
#
# recon/ holds recon.db only (no shells/exports/notes).

export CASE_ROOT="/workspace/cases"
export CASE_FALLBACK_NAME="_unscoped"

case-set() {
  if [[ $# -lt 1 ]]; then
    echo "usage: case-set <name>  (sets case and cd to cases/<name>)"
    return 1
  fi

  local name="$1"
  if [[ ! "$name" =~ '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' ]]; then
    echo "[-] invalid name (use letters, numbers, . _ -)"
    return 1
  fi
  if [[ "$name" == "$CASE_FALLBACK_NAME" ]]; then
    echo "[-] reserved name: $CASE_FALLBACK_NAME (used by CASE_LOOSE fallback)"
    return 1
  fi

  export CASE="$name"
  export CASE_HOME="$CASE_ROOT/$name"

  mkdir -p "$CASE_HOME"/{logs,exports}

  echo "[+] case: $name"
  echo "[+] path: $CASE_HOME"
  cd "$CASE_HOME" || return 1

  if (( $+functions[_case-on-enter] )); then
    _case-on-enter
  fi
}

case-show() {
  if [[ -n "${CASE:-}" ]]; then
    echo "case: $CASE"
    echo "path: ${CASE_HOME:-}"
    return 0
  fi
  if [[ "${CASE_LOOSE:-}" == 1 ]]; then
    echo "case: (unset, CASE_LOOSE → $CASE_FALLBACK_NAME)"
    echo "path: $CASE_ROOT/$CASE_FALLBACK_NAME"
    return 0
  fi
  echo "(no case set — use: cs <name>)"
  return 1
}

case-clear() {
  unset CASE CASE_HOME
  echo "[+] case cleared"
}

case-open() {
  local home
  home="$(case-home)" || return 1
  cd "$home" || return 1
  echo "[+] cwd: $home"
}

cs() { case-set "$@" }

# Resolve cases/<name> for file outputs; strict unless CASE_LOOSE=1
case-home() {
  if [[ -n "${CASE:-}" && -n "${CASE_HOME:-}" ]]; then
    mkdir -p "$CASE_HOME"/{logs,exports}
    echo "$CASE_HOME"
    return 0
  fi

  if [[ "${CASE_LOOSE:-}" == 1 ]]; then
    local loose="$CASE_ROOT/$CASE_FALLBACK_NAME"
    mkdir -p "$loose"/{logs,exports}
    echo "[!] case unset → $loose (set CASE_LOOSE=0 or: cs <name>)" >&2
    echo "$loose"
    return 0
  fi

  echo "[-] case not set — file output needs: cs <name>" >&2
  echo "[-] optional: export CASE_LOOSE=1 → $CASE_ROOT/$CASE_FALLBACK_NAME/" >&2
  return 1
}

case-logs-dir() {
  local home
  home="$(case-home)" || return 1
  echo "$home/logs"
}

case-exports-dir() {
  local home
  home="$(case-home)" || return 1
  echo "$home/exports"
}
