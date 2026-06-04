# ========================
# scan — nmap basic with port_scan_coverage (recon.db)
# ========================

scan() {
  local ip="" force="" dry="" quiet=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scan [options] [ip]"
        echo "  nmap -sC -sV (default top 1000 tcp)"
        echo "  ends with OPEN + CLOSED (service on closed) from recon.db"
        echo ""
        echo "options:"
        echo "  -f, --force       rescan all ports"
        echo "  -n, --dry-run     print nmap command only"
        echo "  -q, --quiet       no port tables at end"
        echo ""
        echo "prep: cs <case>  &&  ti <ip>"
        echo "more: host-view [ip]  (tasks, history, artifacts)"
        return 0
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

  local -a args=(scan "$ip")
  [[ -n "$force" ]] && args+=("$force")
  [[ -n "$dry" ]] && args+=(-n)
  [[ -n "$quiet" ]] && args+=(-q)

  python3 "$RECON_APP" "${args[@]}"
}

_scan() {
  _arguments \
    '-f[force rescan]' \
    '-n[dry-run]' \
    '-q[no port tables]' \
    '1:ip:($IP)'
}

compdef _scan scan
