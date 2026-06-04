# ========================
# scout — scan + probes + background gobuster dirs
# ========================

_scout-is-path() {
  [[ "$1" == /* || "$1" == http://* || "$1" == https://* ]]
}

scout() {
  # legacy: scout status → -s; scout status --watch → -ws
  if [[ "${1:-}" == "status" ]]; then
    shift
    if [[ "${1:-}" == "--watch" || "${1:-}" == "-W" || "${1:-}" == "--wait-dirs" || "${1:-}" == "-ws" || "${1:-}" == "-wd" ]]; then
      shift
      set -- -ws "$@"
    else
      set -- -s "$@"
    fi
  fi

  local ip="" force="" dry="" quiet="" dirs_only="" scout_status="" wait_dirs="" wait_iv="" wordlist="" threads="" ext="" report=""
  local -a extra_urls=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scout [options] [ip|path|url...]"
        echo ""
        echo "dirs job status (pair):"
        echo "  -s, --status [ip]         show once"
        echo "  -ws, --wait-dirs [sec]    refresh until all jobs finish (default 2s)"
        echo ""
        echo "other options:"
        echo "  -r, --report              ports + probes + PATHS from DB"
        echo "  -d, --dirs [path]         gobuster dir only"
        echo "  --force                   force rescan / re-dispatch dirs"
        echo "  -n, --dry-run             show planned commands"
        echo "  -q, --quiet               no port tables after scan"
        echo "  -w, --wordlist            wordlist (default: \$GB_WORDLIST)"
        echo "  -t, --threads             gobuster threads"
        echo "  -x, --ext                 file extensions"
        echo ""
        echo "examples:"
        echo "  scout -d /admin"
        echo "  scout -ws                 wait for dirs"
        echo "  scout -s                  status snapshot"
        echo "  scout -r"
        return 0
        ;;
      -r|--report)
        report="-r"
        shift
        ;;
      -s|--status)
        if [[ -n "$wait_dirs" ]]; then
          echo "[-] use -s or -ws, not both" >&2
          return 1
        fi
        scout_status="-s"
        shift
        ;;
      -ws|--wait-dirs)
        if [[ -n "$scout_status" ]]; then
          echo "[-] use -s or -ws, not both" >&2
          return 1
        fi
        wait_dirs="--wait-dirs"
        shift
        if [[ -n "${1:-}" && "$1" != -* && "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
          wait_iv="$1"
          shift
        fi
        ;;
      -wd)
        echo "[!] -wd is deprecated — use -ws (pair of -s)" >&2
        if [[ -n "$scout_status" ]]; then
          echo "[-] use -s or -ws, not both" >&2
          return 1
        fi
        wait_dirs="--wait-dirs"
        shift
        if [[ -n "${1:-}" && "$1" != -* && "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
          wait_iv="$1"
          shift
        fi
        ;;
      --watch|-W)
        echo "[-] use -ws, not --watch" >&2
        return 1
        ;;
      -d|--dirs)
        dirs_only="--dirs"
        shift
        if [[ -n "${1:-}" ]] && _scout-is-path "$1"; then
          extra_urls+=("$1")
          shift
        elif [[ -n "${1:-}" && "$1" != -* && ! "$1" =~ $(_recon-ip-re) ]]; then
          extra_urls+=("$1")
          shift
        fi
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
      -w|--wordlist)
        wordlist="-w"
        shift
        wordlist+=" $1"
        shift
        ;;
      -t)
        threads="-t"
        shift
        threads+=" $1"
        shift
        ;;
      -x|--ext)
        ext="-x"
        shift
        ext+=" $1"
        shift
        ;;
      http://*|https://*)
        extra_urls+=("$1")
        shift
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      *)
        if [[ "$1" =~ $(_recon-ip-re) ]]; then
          ip="$1"
        elif [[ -n "$dirs_only" ]] && _scout-is-path "$1"; then
          extra_urls+=("$1")
        elif [[ -n "$dirs_only" && "$1" != -* ]]; then
          extra_urls+=("$1")
        else
          echo "[-] expected ip or use -d with path, got: $1" >&2
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

  local -a args=(scout)
  [[ -n "$report" ]] && args+=("$report")
  [[ -n "$scout_status" ]] && args+=("$scout_status")
  [[ -n "$wait_dirs" ]] && args+=("$wait_dirs")
  [[ -n "$wait_iv" ]] && args+=("$wait_iv")
  [[ -n "$dirs_only" ]] && args+=("$dirs_only")
  [[ -n "$force" ]] && args+=("$force")
  [[ -n "$dry" ]] && args+=(-n)
  [[ -n "$quiet" ]] && args+=(-q)
  [[ -n "$wordlist" ]] && args+=(${=wordlist})
  [[ -n "$threads" ]] && args+=(${=threads})
  [[ -n "$ext" ]] && args+=(${=ext})
  args+=("$ip")
  args+=("${extra_urls[@]}")

  python3 "$RECON_APP" "${args[@]}"
}

_scout() {
  _arguments \
    '-h[usage]' '--help[usage]' \
    '-r[report from DB]' '--report[report from DB]' \
    '-s[dirs status once]' '--status[dirs status once]' \
    '-ws[wait for dirs jobs]:sec:' '--wait-dirs[wait for dirs jobs]:sec:' \
    '-d[dirs only]:path:_path_files' '--dirs[dirs only]:path:_path_files' \
    '--force[force rescan / re-dispatch dirs]' \
    '-n[dry-run]' \
    '-q[no port tables after scan]' \
    '-w[wordlist]:wordlist:_files' \
    '-t[threads]:threads:' \
    '-x[extensions]:ext:' \
    '*:ip:($IP)'
}

compdef _scout scout
