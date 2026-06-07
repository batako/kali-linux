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
    if (( $+functions[target-current] )) && target-current >/dev/null 2>&1; then
      echo "target: $IP"
    fi
    if [[ -f "${CASE_HOME}/load_from" ]]; then
      echo "load_from: $(head -1 "${CASE_HOME}/load_from" | tr -d '[:space:]')"
    else
      echo "load_from: (none)"
    fi
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

# Change load_from for current target (recon scope) without changing IP
case-load() {
  if [[ -z "${CASE:-}" ]]; then
    echo "[-] case-load: cs <case> first" >&2
    return 1
  fi
  if [[ $# -lt 1 ]]; then
    echo "usage: case-load <ip|--new|--pick>"
    echo "  change inherit source for el/cl/scout (current IP unchanged)"
    return 1
  fi
  python3 "$RECON_APP" case-load-from "$1"
}

cs() { case-set "$@" }

# Infer CASE / CASE_HOME when cwd is under cases/<name>/ (multi-tab / manual cd)
_case-resolve-from-pwd() {
  local name

  [[ "$PWD" == "$CASE_ROOT"/* ]] || return 1
  name="${PWD#$CASE_ROOT/}"
  name="${name%%/*}"
  [[ -n "$name" ]] || return 1
  [[ "$name" == "$CASE_FALLBACK_NAME" ]] && return 1
  [[ "$name" =~ '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' ]] || return 1

  export CASE="$name"
  export CASE_HOME="$CASE_ROOT/$name"
  return 0
}

# Reload case env + target from $PWD (no cd). For new shells in cases/<name>/
case-sync() {
  if _case-resolve-from-pwd; then
    mkdir -p "$CASE_HOME"/{logs,exports}
    echo "[+] case: $CASE  (from \$PWD)"
    if (( $+functions[_case-on-enter] )); then
      _case-on-enter
    fi
    return 0
  fi
  if [[ -n "${CASE:-}" ]]; then
    echo "[+] case: $CASE  (already set)"
    (( $+functions[_case-on-enter] )) && _case-on-enter
    return 0
  fi
  echo "[-] not under $CASE_ROOT/<name>/ — use: cs <name>" >&2
  return 1
}

_case-chpwd() {
  [[ "$PWD" == "$CASE_ROOT"/* ]] || return 0
  local name="${PWD#$CASE_ROOT/}"
  name="${name%%/*}"
  [[ -n "$name" && "$name" != "$CASE_FALLBACK_NAME" ]] || return 0
  if [[ "${CASE:-}" != "$name" ]]; then
    _case-resolve-from-pwd && (( $+functions[_case-on-enter] )) && _case-on-enter 2>/dev/null
  elif [[ -z "${IP:-}" ]] && (( $+functions[target-load] )); then
    target-load 2>/dev/null
  fi
}

chpwd_functions+=(_case-chpwd)

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

# New shell already cd'd into cases/<name>/ (e.g. after source ~/.zshrc)
if [[ -o interactive && -z "${CASE:-}" ]]; then
  _case-resolve-from-pwd 2>/dev/null && (( $+functions[_case-on-enter] )) && _case-on-enter 2>/dev/null
fi
