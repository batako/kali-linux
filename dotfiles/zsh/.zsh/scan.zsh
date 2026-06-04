# ========================
# scan — nmap -sC -sV with port_scan_coverage (recon.db)
# ========================

scan() {
  local ip="" profile="" force="" dry="" quiet=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scan [full] [options] [ip]"
        echo "  scan       nmap top 1000 (-sC -sV), skips covered ports"
        echo "  scan full  TCP 1-65535 in 1000-port chunks, runs until complete (one command)"
        echo ""
        echo "options:"
        echo "  -f, --force       rescan (top 1000 or -p- for full)"
        echo "  -n, --dry-run     print nmap command only"
        echo "  -q, --quiet       no port tables at end"
        echo ""
        echo "prep: cs <case>  &&  ti <ip>"
        echo "more: host-view [ip]  (tasks, history, artifacts)"
        return 0
        ;;
      full)
        profile=full
        shift
        ;;
      -f|--force)
        force="--force"
        shift
        ;;
      -n|--dry-run)
        dry="-n"
        shift
        ;;
      -q|--quiet)
        quiet="-q"
        shift
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        if [[ "$1" =~ $(_recon-ip-re) ]]; then
          ip="$1"
        else
          echo "[-] expected ip, got: $1" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || {
      echo "[-] no target (ti <ip> / cs <case>)" >&2
      return 1
    }
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  local -a args=(scan)
  [[ -n "$profile" ]] && args+=(full)
  args+=("$ip")
  [[ -n "$force" ]] && args+=("$force")
  [[ -n "$dry" ]] && args+=(-n)
  [[ -n "$quiet" ]] && args+=(-q)

  python3 "$RECON_APP" "${args[@]}"
}

_scan() {
  _arguments \
    '1: :(full)' \
    '-f[force rescan]' \
    '-n[dry-run]' \
    '-q[no port tables]' \
    '2:ip:($IP)'
}

host-reset() {
  local ip="${1:-${IP:-}}"
  if [[ -z "$ip" ]]; then
    echo "[-] usage: host-reset [ip]  (or ti <ip> first)" >&2
    return 1
  fi
  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null
  python3 "$RECON_APP" host-reset "$ip"
}

compdef _scan scan
