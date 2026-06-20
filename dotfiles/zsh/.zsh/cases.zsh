# ========================
# cases (per-room / per-scope workspace)
# ========================
#
# File outputs (listen -l, sshkey-crack, …) need a case directory.
#
# Default (strict): case unset → error. Use: cases set <room>
# Optional:         export CASE_LOOSE=1 → fallback to cases/_unscoped/ + warning
#
# Recon CLI DB lives in recon/data/ (not under workspace/cases).

export CASE_ROOT="/workspace/cases"
export CASE_FALLBACK_NAME="_unscoped"

_cases_cmd_set() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: cases set <room>" "使い方: cases set <room>"
    _toolkit-echo "  short: c set <room>" "  short: c set <room>"
    _toolkit-echo "  create cases/<room>/ if needed, cd into it, and set CASE / CASE_HOME" "  必要なら cases/<room>/ を作成し、そこへ移動して CASE / CASE_HOME を設定"
    return 0
  fi
  if [[ $# -lt 1 ]]; then
    _toolkit-echo "usage: cases set <room>" "使い方: cases set <room>"
    _toolkit-echo "  short: c set <room>" "  short: c set <room>"
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

_cases_cmd_show() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: cases show" "使い方: cases show"
    _toolkit-echo "  short: c show" "  short: c show"
    _toolkit-echo "  show current CASE / CASE_HOME / target / load_from / lineage" "  現在の CASE / CASE_HOME / target / load_from / lineage を表示"
    return 0
  fi
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
    if [[ -f "${CASE_HOME}/.hosts" ]]; then
      echo "hosts: $(head -1 "${CASE_HOME}/.hosts" | sed 's/[[:space:]]*$//')"
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
  echo "(no case set — use: cases set <name>)"
  return 1
}

# Read current target without side effects (safe for prompt rendering).
# Uses cases/<room>/.target only — not session $IP (avoids stale IP after cases sync).
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

_cases_cmd_clear() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: cases clear" "使い方: cases clear"
    _toolkit-echo "  short: c clear" "  short: c clear"
    _toolkit-echo "  unset CASE and CASE_HOME (does not delete files)" "  CASE と CASE_HOME を unset（ファイルは削除しない）"
    return 0
  fi
  unset CASE CASE_HOME
  echo "[+] case cleared"
}

# Wipe cases/<room>/ files + recon DB rows for the room (target, lineage, logs, …)
_cases_cmd_reset() {
  local yes="" room="" arg
  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      -y|--yes) yes="--yes" ;;
      -h|--help)
        _toolkit-echo "usage: cases reset [-y] [<room>]" "使い方: cases reset [-y] [<room>]"
        _toolkit-echo "  short: c reset [-y] [<room>]" "  short: c reset [-y] [<room>]"
        _toolkit-echo "  delete all files under cases/<room>/ and recon DB data for the room" "  cases/<room>/ 配下の全ファイルと、そのルームの recon DB データを削除"
        _toolkit-echo "  default room: current CASE (requires cases set or pass <room>)" "  room 省略時は現在の CASE を使用（cases set 済み、または <room> 指定が必要）"
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
      echo "[-] cases reset: cases set <room> first, or: cases reset <room>" >&2
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

_cases_cmd_open() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: cases open" "使い方: cases open"
    _toolkit-echo "  short: c open" "  short: c open"
    _toolkit-echo "  cd to current CASE_HOME without changing room selection" "  ルーム選択を変えずに現在の CASE_HOME へ移動"
    return 0
  fi
  local home
  home="$(case-home)" || return 1
  cd "$home" || return 1
  echo "[+] cwd: $home"
}

# Change load_from for current target (recon scope) without changing IP
_cases_cmd_load() {
  if [[ -z "${CASE:-}" ]]; then
    echo "[-] cases load: cases set <room> first" >&2
    return 1
  fi
  if [[ $# -lt 1 ]]; then
    _toolkit-echo "usage: cases load <ip|--new|--pick>" "使い方: cases load <ip|--new|--pick>"
    _toolkit-echo "  short: c load <ip|--new|--pick>" "  short: c load <ip|--new|--pick>"
    _toolkit-echo "  change inherit source for exec-list / creds-list / scout (current IP unchanged)" "  exec-list / creds-list / scout の継承元を変更（現在 IP は変えない）"
    return 1
  fi
  python3 "$RECON_APP" case-load-from "$1"
}

# List IPs in current case (lineage, scope, activity summary)
_cases_cmd_ips() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: cases ips" "使い方: cases ips"
    _toolkit-echo "  short: c ips" "  short: c ips"
    _toolkit-echo "  list case IPs with lineage / load_from markers (+ in lineage, * latest load_from)" "  ケース内の IP 一覧を表示（lineage / load_from の印付き。+ は lineage、* は最新 load_from）"
    return 0
  fi
  if [[ -z "${CASE:-}" ]]; then
    echo "[-] cases ips: cases set <room> first" >&2
    return 1
  fi
  python3 "$RECON_APP" case-ip-list
}

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
_cases_cmd_sync() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: cases sync" "使い方: cases sync"
    _toolkit-echo "  short: c sync" "  short: c sync"
    _toolkit-echo "  restore CASE / CASE_HOME and target from \$PWD under cases/<room>/" "  cases/<room>/ 配下の \$PWD から CASE / CASE_HOME と target を復元"
    return 0
  fi
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
  echo "[-] not under $CASE_ROOT/<name>/ — use: cases set <name>" >&2
  return 1
}

cases() {
  local sub="${1:-}"
  if [[ -z "$sub" || "$sub" == -h || "$sub" == --help ]]; then
    _toolkit-echo "usage: cases <subcommand> [args]" "使い方: cases <subcommand> [args]"
    _toolkit-echo "  subcommands: set show clear reset open load ips sync" "  subcommands: set show clear reset open load ips sync"
    _toolkit-echo "    set <room>            select room and cd into cases/<room>/" "    set <room>            ルームを選択し cases/<room>/ に移動"
    _toolkit-echo "    show                  show current CASE / target / lineage" "    show                  現在の CASE / target / lineage を表示"
    _toolkit-echo "    clear                 unset CASE and CASE_HOME" "    clear                 CASE と CASE_HOME を unset"
    _toolkit-echo "    reset [-y] [room]     wipe room files and DB rows" "    reset [-y] [room]     ルーム配下のファイルと DB 行を削除"
    _toolkit-echo "    open                  cd to current CASE_HOME" "    open                  現在の CASE_HOME に移動"
    _toolkit-echo "    load <ip|--new|--pick> change load_from without changing IP" "    load <ip|--new|--pick> IP を変えず load_from を変更"
    _toolkit-echo "    ips                   list room IPs with markers" "    ips                   ルーム内 IP 一覧を印付きで表示"
    _toolkit-echo "    sync                  restore CASE and target from \$PWD" "    sync                  \$PWD から CASE と target を復元"
    _toolkit-echo "  short: c <subcommand> [args]" "  short: c <subcommand> [args]"
    return ${sub:+0}
  fi
  shift
  case "$sub" in
    set) _cases_cmd_set "$@" ;;
    show) _cases_cmd_show "$@" ;;
    clear) _cases_cmd_clear "$@" ;;
    reset) _cases_cmd_reset "$@" ;;
    open) _cases_cmd_open "$@" ;;
    load) _cases_cmd_load "$@" ;;
    ips) _cases_cmd_ips "$@" ;;
    sync) _cases_cmd_sync "$@" ;;
    *)
      echo "[-] unknown cases subcommand: $sub" >&2
      echo "    use: cases --help" >&2
      return 1
      ;;
  esac
}

alias c=cases
cs() { cases set "$@" }

_cases() {
  local -a subcommands
  subcommands=(
    'set:select room and cd into it'
    'show:show current case details'
    'clear:clear CASE and CASE_HOME'
    'reset:wipe room files and DB rows'
    'open:cd to current case home'
    'load:change load_from for current target'
    'ips:list room IPs'
    'sync:restore CASE and target from $PWD'
  )

  if (( CURRENT == 2 )); then
    _describe -t cases-subcommands 'cases subcommands' subcommands
    return
  fi

  case "$words[2]" in
    set|reset)
      _arguments '*:room name:_files -/'
      ;;
    load)
      _arguments '1:mode or ip:(--new --pick)'
      ;;
    *)
      _arguments '*:arg: '
      ;;
  esac
}

if (( $+functions[compdef] )); then
  compdef _cases cases
  compdef _cases c
fi

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
    echo "[!] case unset → $loose (set CASE_LOOSE=0 or: cases set <name>)" >&2
    echo "$loose"
    return 0
  fi

  echo "[-] case not set — file output needs: cases set <name>" >&2
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
