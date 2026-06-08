# ========================
# recon system
# ========================

export RECON_DATA="/opt/recon/data"
export RECON_DB="$RECON_DATA/recon.db"
# db.py reads RECON_DB_PATH (preferred) for DB location
export RECON_DB_PATH="$RECON_DB"
export RECON_APP="/opt/recon/recon.py"

_case-target-file() {
  [[ -n "${CASE_HOME:-}" ]] && echo "$CASE_HOME/target"
}

# Load IP from cases/<room>/target into $IP
target-load() {
  local f ip
  f="$(_case-target-file)" || return 1
  [[ -f "$f" ]] || return 1
  ip="$(head -1 "$f" | tr -d '[:space:]')"
  [[ "$ip" =~ $(_recon-ip-re) ]] || return 1
  export IP="$ip"
  if [[ -n "${CASE:-}" ]]; then
    python3 "$RECON_APP" case-register-ip "$ip" 2>/dev/null
    python3 "$RECON_APP" case-sync-ips 2>/dev/null
  fi
  return 0
}

# Persist $IP for current case
target-save() {
  local ip="${1:-${IP:-}}"
  local f
  [[ "$ip" =~ $(_recon-ip-re) ]] || return 1
  f="$(_case-target-file)" || return 1
  print -r -- "$ip" >"$f"
  if [[ -n "${CASE:-}" ]]; then
    python3 "$RECON_APP" case-register-ip "$ip" 2>/dev/null
    python3 "$RECON_APP" case-sync-ips 2>/dev/null
  fi
  return 0
}

# Resolve target IP: $IP, else cases/<room>/target
target-current() {
  if [[ -n "${IP:-}" ]]; then
    echo "$IP"
    return 0
  fi
  target-load && echo "$IP"
}

_case-on-enter() {
  if (( $+functions[_ftp-shell-reset-case] )); then
    _ftp-shell-reset-case
  fi
  if target-load; then
    echo "[+] target: $IP  ($CASE_HOME/target)"
  fi
  if [[ -f "${CASE_HOME:-}/ftp-shell" ]]; then
    echo "[+] ftp-shell: $CASE_HOME/ftp-shell"
  fi
}

# Session-only IP (no CASE / no load_from)
_target-set-session() {
  local ip="$1"
  export IP="$ip"
  echo "[+] target set: $ip  (session only — case-set <room> to persist)"
}

# Set or reload investigation target ($IP + cases/<room>/target + load_from)
# usage: target-set <ip> [--new|--pick]  |  target-set
target-set() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: target-set <ip> [--new|--pick]  |  target-set"
    echo "  alias: ts (= target-set)"
    echo "  set \$IP (+ save to cases/<room>/target)"
    echo "  IP change: auto-inherit previous target when it has recon data"
    echo "  --new   pivot (no inherit)    --pick   numbered load_from picker"
    echo "  no args: reload from target file"
    return 0
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  if [[ $# -ge 1 ]]; then
    local new_ip="" mode="auto" arg
    for arg in "$@"; do
      case "$arg" in
        --new) mode=new ;;
        --pick) mode=pick ;;
        -h|--help) target-set --help; return 0 ;;
        --*)
          echo "[-] unknown option: $arg" >&2
          echo "    use: target-set <ip> [--new|--pick]" >&2
          return 1
          ;;
        *)
          if [[ -z "$new_ip" ]]; then
            new_ip="$arg"
          else
            echo "[-] unexpected argument: $arg" >&2
            return 1
          fi
          ;;
      esac
    done

    if [[ -z "$new_ip" ]]; then
      echo "usage: target-set <ip> [--new|--pick]" >&2
      return 1
    fi

    if [[ ! "$new_ip" =~ $(_recon-ip-re) ]]; then
      echo "usage: target-set <ipv4> [--new|--pick]" >&2
      return 1
    fi

    if [[ -n "${CASE:-}" ]]; then
      local previous_ip="" set_args=(case-target-set "$new_ip" --mode "$mode")
      local f
      f="$(_case-target-file 2>/dev/null)"
      if [[ -n "$f" && -f "$f" ]]; then
        previous_ip="$(head -1 "$f" | tr -d '[:space:]')"
        [[ "$previous_ip" =~ $(_recon-ip-re) ]] && set_args+=(--previous "$previous_ip")
      fi
      python3 "$RECON_APP" "${set_args[@]}" || return $?
      export IP="$new_ip"
      return 0
    fi

    _target-set-session "$new_ip"
    return 0
  fi

  if target-load; then
    echo "[+] target: $IP  ($CASE_HOME/target)"
    return 0
  fi

  echo "usage: target-set <ip>  |  target-set  (case-set <room> or cwd under cases/<room>/)" >&2
  return 1
}

target-show() {
  local f
  if target-current >/dev/null; then
    echo "$IP"
    f="$(_case-target-file 2>/dev/null)"
    [[ -n "$f" && -f "$f" ]] && echo "[*] file: $f"
    return 0
  fi
  echo "(no target — target-set <ip> or case-set <room> with cases/<room>/target)"
  return 1
}

target-clear() {
  local f
  unset IP
  f="$(_case-target-file 2>/dev/null)"
  [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  echo "[+] target cleared"
}

recon-init() {
  mkdir -p "$RECON_DATA"

  python3 "$RECON_APP" init

  echo "[+] recon initialized"
  echo "[+] db: $RECON_DB"
  echo "[*] file outputs (logs, exports): cs <name> first (or CASE_LOOSE=1)"
}

net-scan() {
  if [[ $# -lt 1 ]]; then
    echo "usage: net-scan <cidr>"
    return 1
  fi

  python3 "$RECON_APP" net-scan "$1"
}

net-view() {
  python3 "$RECON_APP" net-view
}

host-view() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: host-view <ip>"
    return 1
  fi

  python3 "$RECON_APP" host-view "$ip"
}

host-summary() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: host-summary <ip>"
    return 1
  fi

  python3 "$RECON_APP" host-summary "$ip" --json
}

task-view() {
  python3 "$RECON_APP" task-view
}

task-done() {
  if [[ $# -lt 1 ]]; then
    echo "usage: task-done <id>"
    return 1
  fi

  python3 "$RECON_APP" task-done "$1"
}

task-run() {
  if [[ $# -lt 1 ]]; then
    echo "usage: task-run <id>"
    return 1
  fi

  python3 "$RECON_APP" task-run "$1"
}

host-run-next() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: host-run-next <ip>"
    return 1
  fi

  python3 "$RECON_APP" host-run-next "$ip"
}

exec-run() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-run [-s] [ip] <command...>"
    echo "  alias: x (exec-run -s → xs)"
    return 0
  fi

  local ip=""
  local cmd_start=1

  local silence=""

  if [[ "${1:-}" == "-s" ]]; then
    silence="-s"
    shift
  fi

  # If first arg looks like an IP, treat it as ip; otherwise fall back to current target.
  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: exec-run [-s] [ip] <command...>" >&2
    echo "  alias: x (exec-run -s → xs)" >&2
    return 1
  fi

  python3 "$RECON_APP" exec-run $silence "$ip" "$@"
}

# Short aliases for daily use (same as exec-run / exec-run -s)
x() {
  exec-run "$@"
}

xs() {
  exec-run -s "$@"
}

exec-cache() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-cache [-s] [ip] <command...>"
    echo "  alias: xc (exec-cache -s → xcs)"
    return 0
  fi

  local ip=""
  local silence=""

  if [[ "${1:-}" == "-s" ]]; then
    silence="-s"
    shift
  fi

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: exec-cache [-s] [ip] <command...>" >&2
    echo "  alias: xc (exec-cache -s → xcs)" >&2
    return 1
  fi

  python3 "$RECON_APP" exec-cache $silence "$ip" "$@"
}

# cache-or-run: skip if already done for this ip+command
xc() {
  exec-cache "$@"
}

xcs() {
  exec-cache -s "$@"
}

exec-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-list [-l] [--all-case] [ip]"
    echo "  alias: el"
    return 0
  fi
  python3 "$RECON_APP" exec-list "$@"
}

exec-view() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-view <exec_id> [--tail N]"
    echo "  alias: ev"
    return 0
  fi
  if [[ $# -lt 1 ]]; then
    echo "usage: exec-view <exec_id> [--tail N]" >&2
    echo "  alias: ev" >&2
    return 1
  fi
  python3 "$RECON_APP" exec-view "$@"
}

el() {
  exec-list "$@"
}

ev() {
  exec-view "$@"
}

artifact-add() {
  local ip=""
  local kind=""
  local value=""
  local key=""

  # usage: artifact-add [ip] <kind> <value> [key]
  if [[ $# -ge 4 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"; kind="$2"; value="$3"; key="${4:-}"
  else
    ip="${IP:-}"
    kind="$1"; value="$2"; key="${3:-}"
  fi

  if [[ -z "$ip" || -z "$kind" || -z "$value" ]]; then
    echo "usage: artifact-add [ip] <kind> <value> [key]"
    return 1
  fi

  python3 "$RECON_APP" artifact-add "$ip" "$kind" "$value" "$key"
}

_creds-add() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: creds-add [ip] <username> [<password>]"
    echo "  alias: ca"
    echo "  password omitted → prompt (paste ok)"
    echo "examples:"
    echo "  creds-add vigilante              # prompt for password"
    echo "  creds-add vigilante -            # password from stdin / pipe"
    echo "  creds-add vigilante '!#th3h00d'  # inline (quote when pass has # or !)"
    return 0
  fi

  local ip=""
  local user=""
  local pass=""
  local from_args=false

  # usage: creds-add [ip] <username> [<password>]
  #        password omitted → prompt (paste ok; no shell quoting needed)
  if [[ $# -ge 3 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    user="$2"
    shift 2
  elif [[ $# -ge 1 ]]; then
    ip="${IP:-}"
    user="$1"
    shift
  else
    echo "usage: creds-add [ip] <username> [<password>]" >&2
    echo "  alias: ca" >&2
    return 1
  fi

  if [[ $# -eq 1 && "$1" == "-" ]]; then
    pass="$(cat)"
    pass="${pass//$'\n'/}"
  elif [[ $# -ge 1 ]]; then
    pass="$*"
    from_args=true
  elif [[ -t 0 ]]; then
    read -r "pass?password for ${user}@${ip} (paste ok): "
  else
    pass="$(cat)"
    pass="${pass//$'\n'/}"
  fi

  if [[ -z "$ip" ]]; then
    echo "[-] no target ip — target-set <ip> first" >&2
    return 1
  fi
  if [[ -z "$user" || -z "$pass" ]]; then
    echo "[-] empty username or password" >&2
    return 1
  fi
  if $from_args && [[ "$pass" == "!" ]]; then
    echo "[-] password looks truncated — # starts a shell comment without quotes" >&2
    echo "      creds-add ${user}              # prompt instead" >&2
    echo "      creds-add ${user} '!#th3h00d'" >&2
    return 1
  fi

  python3 "$RECON_APP" creds-add "$ip" "$user" "$pass"
}

# noglob は関数内では遅い（呼び出し前に zsh が ? / ??? 等を展開する）→ alias で付与
unfunction ca creds-add creds-rm cr ts 2>/dev/null
setopt aliases
alias creds-add='noglob _creds-add'
alias ca='noglob _creds-add'
alias ts=target-set

creds-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: creds-list [ip]"
    echo "  alias: cl"
    echo "  or: case-set <room> first (load_from + current IP)"
    return 0
  fi
  if [[ -n "${1:-}" ]]; then
    python3 "$RECON_APP" creds-list "$1"
    return $?
  fi
  if [[ -z "${CASE:-}" && -z "${IP:-}" ]]; then
    echo "usage: creds-list [ip]" >&2
    echo "  alias: cl" >&2
    echo "  or: case-set <room> first" >&2
    return 1
  fi
  python3 "$RECON_APP" creds-list
}

# usage: creds-rm [ip] [username]   (no username → all creds for ip)
_creds-rm() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: creds-rm [ip] [username]"
    echo "  alias: cr"
    echo "  no username → delete all creds for ip"
    return 0
  fi

  local ip="" user=""

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    user="${2:-}"
  elif [[ $# -ge 1 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
  elif [[ $# -ge 1 ]]; then
    ip="${IP:-}"
    user="$1"
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" ]]; then
    echo "usage: creds-rm [ip] [username]" >&2
    echo "  alias: cr" >&2
    return 1
  fi

  if [[ -n "$user" ]]; then
    python3 "$RECON_APP" creds-rm "$ip" "$user"
  else
    python3 "$RECON_APP" creds-rm "$ip"
  fi
}

alias creds-rm='noglob _creds-rm'
alias cr='noglob _creds-rm'

cl() {
  creds-list "$@"
}

artifact-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: artifact-list [-l] [ip]"
    echo "  alias: al"
    return 0
  fi
  python3 "$RECON_APP" artifact-list "$@"
}

al() {
  artifact-list "$@"
}

artifact-del() {
  if [[ $# -lt 1 ]]; then
    echo "usage: artifact-del <artifact_id>"
    return 1
  fi
  python3 "$RECON_APP" artifact-del "$1"
}

_exploit-reject() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exploit-reject [--port 80/tcp] [--note text] [ip] <EDB>"
    echo "  alias: erj"
    echo "examples:"
    echo "  exploit-reject 50383              # hide from scout -re"
    echo "  exploit-reject --port 80/tcp 50383"
    return 0
  fi

  local ip="" edb="" port="" note=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port|-P)
        [[ -n "${2:-}" ]] || { echo "usage: exploit-reject [--port 80/tcp] <EDB>" >&2; echo "  alias: erj" >&2; return 1; }
        port="$2"; shift 2 ;;
      --note)
        [[ -n "${2:-}" ]] || { echo "usage: exploit-reject [--note text] <EDB>" >&2; echo "  alias: erj" >&2; return 1; }
        note="$2"; shift 2 ;;
      *)
        if [[ "$1" =~ $(_recon-ip-re) ]]; then
          ip="$1"
        elif [[ -z "$edb" ]]; then
          edb="${1#EDB-}"; edb="${edb#edb-}"
        else
          echo "usage: exploit-reject [--port 80/tcp] [--note text] [ip] <EDB>" >&2
          echo "  alias: erj" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || true
  fi
  if [[ -z "$ip" || -z "$edb" ]]; then
    echo "usage: exploit-reject [--port 80/tcp] [--note text] [ip] <EDB>" >&2
    echo "  alias: erj" >&2
    return 1
  fi

  local -a args=(exploit-reject "$ip" "$edb")
  [[ -n "$port" ]] && args+=(--port "$port")
  [[ -n "$note" ]] && args+=(--note "$note")
  python3 "$RECON_APP" "${args[@]}"
}

_exploit-unreject() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exploit-unreject [--port 80/tcp] [ip] <EDB>"
    echo "  alias: eru"
    return 0
  fi

  local ip="" edb="" port=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port|-P)
        [[ -n "${2:-}" ]] || { echo "usage: exploit-unreject [--port 80/tcp] <EDB>" >&2; echo "  alias: eru" >&2; return 1; }
        port="$2"; shift 2 ;;
      *)
        if [[ "$1" =~ $(_recon-ip-re) ]]; then
          ip="$1"
        elif [[ -z "$edb" ]]; then
          edb="${1#EDB-}"; edb="${edb#edb-}"
        else
          echo "usage: exploit-unreject [--port 80/tcp] [ip] <EDB>" >&2
          echo "  alias: eru" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || true
  fi
  if [[ -z "$ip" || -z "$edb" ]]; then
    echo "usage: exploit-unreject [--port 80/tcp] [ip] <EDB>" >&2
    echo "  alias: eru" >&2
    return 1
  fi

  local -a args=(exploit-unreject "$ip" "$edb")
  [[ -n "$port" ]] && args+=(--port "$port")
  python3 "$RECON_APP" "${args[@]}"
}

exploit-reject() { _exploit-reject "$@"; }
exploit-unreject() { _exploit-unreject "$@"; }
exploit-rejects() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exploit-rejects [ip]"
    echo "  alias: erl"
    return 0
  fi
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "usage: exploit-rejects [ip]" >&2
    echo "  alias: erl" >&2
    return 1
  fi
  python3 "$RECON_APP" exploit-rejects "$ip"
}

alias erj='noglob _exploit-reject'
alias eru='noglob _exploit-unreject'
alias erl='exploit-rejects'

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
