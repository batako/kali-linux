# ========================
# scan — nmap -sC -sV with port_scan_coverage (recon.db)
# ========================

scan() {
  local ip="" profile="" report="" force="" dry="" quiet="" jobs=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scan [options] [ip]"
        echo "  scan              nmap top 1000 (-sC -sV), skips covered ports"
        echo "  scan -f           same with --full (TCP 1-65535 until complete)"
        echo "  scan --report     coverage + OPEN + gaps (no nmap)"
        echo ""
        echo "options:"
        echo "  -h, --help        this help"
        echo "  -f, --full        TCP 1-65535 until complete (one command)"
        echo "  -r, --report      scan status report (no nmap)"
        echo "  --force           rescan (top 1000 or -p- with --full)"
        echo "  -n, --dry-run     print nmap command only"
        echo "  -q, --quiet       no port tables at end"
        echo "  -j, --jobs N      --full only: parallel workers (1-${SCAN_FULL_JOBS_MAX:-8}, default 1)"
        echo ""
        echo "prep: cs <case>  &&  ti <ip>"
        echo "more: host-view [ip]  (tasks, history, artifacts)"
        return 0
        ;;
      -f|--full)
        profile=full
        shift
        ;;
      -r|--report)
        report=1
        shift
        ;;
      --force)
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
      -j[0-9]|-j[0-9][0-9])
        jobs="${1#-j}"
        shift
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      full|report)
        echo "[-] use scan -f or scan --$1 (positional '$1' removed)" >&2
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

  if [[ -n "$report" && -n "$profile" ]]; then
    echo "[-] use either --full/-f or --report/-r, not both" >&2
    return 1
  fi
  if [[ -n "$report" && ( -n "$force" || -n "$dry" || -n "$quiet" || -n "$jobs" ) ]]; then
    echo "[-] --report does not take --force, -n, -q, or -j" >&2
    return 1
  fi

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || {
      echo "[-] no target (ti <ip> / cs <case>)" >&2
      return 1
    }
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  local -a args=(scan)
  if [[ -n "$report" ]]; then
    args+=(--report "$ip")
  else
    [[ -n "$profile" ]] && args+=(--full)
    args+=("$ip")
    [[ -n "$force" ]] && args+=("$force")
    [[ -n "$dry" ]] && args+=(-n)
    [[ -n "$quiet" ]] && args+=(-q)
    [[ -n "$jobs" ]] && args+=(-j "$jobs")
  fi

  python3 "$RECON_APP" "${args[@]}"
}

_scan() {
  _arguments \
    '-h[usage]' '--help[usage]' \
    '-f[full TCP 1-65535]' \
    '--full[full TCP 1-65535]' \
    '-r[report only]' \
    '--report[report only]' \
    '--force[rescan]' \
    '-n[dry-run]' \
    '-q[no port tables]' \
    '-j[parallel workers (--full)]::jobs:' \
    '*:ip:($IP)'
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
