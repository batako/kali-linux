# ========================
# cases (per-room / per-scope workspace)
# ========================
#
# File outputs (listen -l, sshkey-crack, …) need a case directory.
#
# Default (strict): case unset → error. Use: case-set <room>
# Optional:         export CASE_LOOSE=1 → fallback to cases/_unscoped/ + warning
#
# Recon CLI DB lives in recon/data/ (not under workspace/cases).

export CASE_ROOT="/workspace/cases"
export CASE_FALLBACK_NAME="_unscoped"

case-set() {
  if [[ $# -lt 1 ]]; then
    _toolkit-echo "usage: case-set <room>" "使い方: case-set <room>"
    _toolkit-echo "  alias: cs" "  alias: cs"
    _toolkit-echo "  cd to cases/<room>/ and set CASE / CASE_HOME" "  cases/<room>/ に移動し、CASE / CASE_HOME を設定"
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
    if [[ -f "${CASE_HOME}/.load_from" ]]; then
      echo "load_from: $(head -1 "${CASE_HOME}/.load_from" | tr -d '[:space:]')"
    else
      echo "load_from: (none)"
    fi
    if [[ -f "${CASE_HOME}/.lineage" ]]; then
      echo "lineage: $(grep -E '^[0-9]+\.' "${CASE_HOME}/.lineage" | paste -sd, -)"
    else
      echo "lineage: (none)"
    fi
    if [[ -f "${CASE_HOME}/hosts" ]]; then
      echo "hosts: $(head -1 "${CASE_HOME}/hosts" | sed 's/[[:space:]]*$//')"
    else
      echo "hosts: (none)"
    fi
    if [[ -f "${CASE_HOME}/exploit" ]]; then
      echo "exploit: $(head -1 "${CASE_HOME}/exploit" | tr -d '[:space:]')"
    else
      echo "exploit: (none)"
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

# Read current target without side effects (safe for prompt rendering).
# Uses cases/<room>/.target only — not session $IP (avoids stale IP after cs).
case-target-current() {
  local f ip
  [[ -n "${CASE_HOME:-}" ]] || return 1
  f="$CASE_HOME/.target"
  [[ -f "$f" ]] || return 1
  ip="$(head -1 "$f" | tr -d '[:space:]')"
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  echo "$ip"
}

# Attacker IPv4 for prompt (tun0 → eth0). No stderr; safe for prompt rendering.
case-lhost-current() {
  local ip
  ip=$(ip -o -4 addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$ip" ]] && { echo "$ip"; return 0 }
  ip=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$ip" ]] && { echo "$ip"; return 0 }
  return 1
}

case-clear() {
  unset CASE CASE_HOME
  echo "[+] case cleared"
}

# Wipe cases/<room>/ files + recon DB rows for the room (target, lineage, logs, …)
case-reset() {
  local yes="" room="" arg
  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      -y|--yes) yes="--yes" ;;
      -h|--help)
        _toolkit-echo "usage: case-reset [-y] [<room>]" "使い方: case-reset [-y] [<room>]"
        _toolkit-echo "  delete all files under cases/<room>/ and recon DB data for the room" "  cases/<room>/ 配下の全ファイルと、そのルームの recon DB データを削除"
        _toolkit-echo "  default room: current CASE (requires case-set or pass <room>)" "  room 省略時は現在の CASE を使用（case-set 済み、または <room> 指定が必要）"
        return 0
        ;;
      *)
        if [[ -n "$room" ]]; then
          echo "[-] unexpected argument: $arg" >&2
          return 1
        fi
        room="$arg"
        ;;
    esac
    shift
  done

  if [[ -z "$room" ]]; then
    if [[ -z "${CASE:-}" ]]; then
      echo "[-] case-reset: case-set <room> first, or: case-reset <room>" >&2
      return 1
    fi
    room="$CASE"
  fi

  if [[ ! "$room" =~ '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' ]]; then
    echo "[-] invalid name (use letters, numbers, . _ -)" >&2
    return 1
  fi
  if [[ "$room" == "$CASE_FALLBACK_NAME" ]]; then
    echo "[-] reserved name: $CASE_FALLBACK_NAME" >&2
    return 1
  fi

  local -a reset_args=(case-reset)
  [[ -n "$yes" ]] && reset_args+=("$yes")
  reset_args+=("$room")
  python3 "$RECON_APP" "${reset_args[@]}" || return $?

  if [[ "${CASE:-}" == "$room" ]]; then
    unset IP
    mkdir -p "$CASE_ROOT/$room"/{logs,exports}
    export CASE_HOME="$CASE_ROOT/$room"
    cd "$CASE_HOME" || return 1
    echo "[+] cwd: $CASE_HOME  (.target/.lineage cleared — target-set <ip>)"
  fi
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
    echo "[-] case-load: case-set <room> first" >&2
    return 1
  fi
  if [[ $# -lt 1 ]]; then
    _toolkit-echo "usage: case-load <ip|--new|--pick>" "使い方: case-load <ip|--new|--pick>"
    _toolkit-echo "  change inherit source for exec-list / creds-list / scout (current IP unchanged)" "  exec-list / creds-list / scout の継承元を変更（現在 IP は変えない）"
    return 1
  fi
  python3 "$RECON_APP" case-load-from "$1"
}

# List IPs in current case (lineage, scope, activity summary)
case-ips() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: case-ips" "使い方: case-ips"
    _toolkit-echo "  list case IPs with lineage / load_from markers (+ in lineage, * latest load_from)" "  ケース内の IP 一覧を表示（lineage / load_from の印付き。+ は lineage、* は最新 load_from）"
    return 0
  fi
  if [[ -z "${CASE:-}" ]]; then
    echo "[-] case-ips: case-set <room> first" >&2
    return 1
  fi
  python3 "$RECON_APP" case-ip-list
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
