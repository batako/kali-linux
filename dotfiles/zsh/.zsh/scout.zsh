# ========================
# scout — scan (top 1000) + probes on open 22/80
# ========================

scout() {
  local ip="" force="" dry="" quiet=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scout [options] [ip]"
        echo "  phase 1: scan (nmap top 1000 -sC -sV)"
        echo "  phase 2: open 22/80 → probe by nmap service (ssh/http/ftp)"
        echo ""
        echo "options:"
        echo "  -h, --help        this help"
        echo "  --force           force port rescan (scan --force)"
        echo "  -n, --dry-run     show planned scan + probe commands"
        echo "  -q, --quiet       no port tables after scan"
        echo ""
        echo "prep: cs <case>  &&  ti <ip>"
        echo "view: ev <exec_id>   el [ip]"
        return 0
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

  local -a args=(scout "$ip")
  [[ -n "$force" ]] && args+=("$force")
  [[ -n "$dry" ]] && args+=(-n)
  [[ -n "$quiet" ]] && args+=(-q)

  python3 "$RECON_APP" "${args[@]}"
}

_scout() {
  _arguments \
    '-h[usage]' '--help[usage]' \
    '--force[force port rescan]' \
    '-n[dry-run]' \
    '-q[no port tables after scan]' \
    '*:ip:($IP)'
}

compdef _scout scout
