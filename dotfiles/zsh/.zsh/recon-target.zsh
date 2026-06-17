# ========================
# recon target
# ========================

_case-target-file() {
  [[ -n "${CASE_HOME:-}" ]] && echo "$CASE_HOME/.target"
}

# Load IP from cases/<room>/.target into $IP
target-load() {
  local f ip
  f="$(_case-target-file)" || return 1
  [[ -f "$f" ]] || return 1
  ip="$(head -1 "$f" | tr -d '[:space:]')"
  [[ "$ip" =~ $(_recon-ip-re) ]] || return 1
  export IP="$ip"
  if [[ -n "${CASE:-}" ]]; then
    python3 "$RECON_APP" case-register-ip "$ip" >/dev/null
    python3 "$RECON_APP" case-sync-ips >/dev/null
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
    python3 "$RECON_APP" case-register-ip "$ip" >/dev/null
    python3 "$RECON_APP" case-sync-ips >/dev/null
  fi
  return 0
}

# Resolve target IP: $IP, else cases/<room>/.target
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
  unset IP
  if target-load; then
    echo "[+] target: $IP  ($CASE_HOME/.target)"
  fi
  if [[ -f "${CASE_HOME:-}/ftp-shell" ]]; then
    echo "[+] ftp-shell: $CASE_HOME/ftp-shell"
  fi
  if [[ -f "${CASE_HOME:-}/exploit" ]]; then
    echo "[+] exploit: $(head -1 "${CASE_HOME}/exploit" | tr -d '[:space:]')"
  fi
  if (( $+functions[_recon-hosts-apply] )); then
    _recon-hosts-apply
  fi
}

# Session-only IP (no CASE / no load_from)
_target-set-session() {
  local ip="$1"
  export IP="$ip"
  echo "[+] target set: $ip  (session only — case-set <room> to persist)"
}

# Set or reload investigation target ($IP + cases/<room>/.target + load_from)
# usage: target-set <ip> [--new|--pick]  |  target-set
target-set() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: target-set <ip> [--new|--pick]  |  target-set"
    echo "  alias: ts (= target-set)"
    echo "  set \$IP (+ save to cases/<room>/.target)"
    echo "  IP change: auto-inherit previous target when it has recon data"
    echo "  hosts:     previous IP in cases/<room>/hosts → new IP on target-set (not --new)"
    echo "  lineage: prior IPs of same VM accumulate in cases/<room>/.lineage"
    echo "  --new   pivot (clear lineage)    --pick   numbered load_from picker"
    echo "  no args: reload from .target file"
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
      if [[ "$mode" != new && -n "$previous_ip" && "$previous_ip" != "$new_ip" ]]; then
        (( $+functions[_hosts-remap-ip] )) && _hosts-remap-ip "$previous_ip" "$new_ip"
      fi
      return 0
    fi

    _target-set-session "$new_ip"
    return 0
  fi

  if target-load; then
    echo "[+] target: $IP  ($CASE_HOME/.target)"
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
  echo "(no target — target-set <ip> or case-set <room> with cases/<room>/.target)"
  return 1
}

target-clear() {
  local f
  unset IP
  f="$(_case-target-file 2>/dev/null)"
  [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  f="$(_case-target-file-legacy 2>/dev/null)"
  [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  echo "[+] target cleared"
}

alias ts=target-set
