# ========================
# scan — nmap -sC -sV with port_scan_coverage (recon.db)
# ========================

scan() {
  local ip="" profile="" force="" dry="" quiet="" jobs=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scan [full] [options] [ip]"
        echo "  scan       nmap top 1000 (-sC -sV), skips covered ports"
        echo "  scan full  TCP 1-65535 until complete (one command)"
        echo ""
        echo "options:"
        echo "  -f, --force       rescan (top 1000 or -p- for full)"
        echo "  -n, --dry-run     print nmap command only"
        echo "  -q, --quiet       no port tables at end"
        echo "  -j, --jobs N      scan full only: parallel workers (1-${SCAN_FULL_JOBS_MAX:-8}, default 1)"
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
      -j|--jobs)
        jobs="$2"
        shift 2
        ;;
      -j[1-9]|-j[1-9][0-9])
        jobs="${1#-j}"
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
  [[ -n "$jobs" ]] && args+=(-j "$jobs")

  python3 "$RECON_APP" "${args[@]}"
}

_scan() {
  _arguments \
    '1: :(full)' \
    '-f[force rescan]' \
    '-n[dry-run]' \
    '-q[no port tables]' \
    '-j[parallel workers (scan full)]::jobs:' \
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
