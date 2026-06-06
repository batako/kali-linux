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

  local ip="" force="" dry="" quiet="" dirs_only="" scout_status="" wait_dirs="" wait_iv=""
  local wordlist="" threads="" ext=""
  local report="" report_ports="" report_exploits="" search_exploits=""
  local -a extra_urls=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scout [options] [ip|path|url...]  (alias: s)"
        echo ""
        echo "  scout / s / scout -d  dispatch dirs then auto-watch (-ws) until jobs finish"
        echo ""
        echo "dirs job status (pair):"
        echo "  -s, --status [ip]              show once"
        echo "  -ws, --wait-dirs [sec]         refresh until all jobs finish (default 2s)"
        echo ""
        echo "report (DB only, no rescan):"
        echo "  -r, --report [ip]              full report"
        echo "  -rp, --report-ports [ip]       OPEN + CLOSED"
        echo "  -re, --report-exploits [ip]   EXPLOITS"
        echo ""
        echo "search (always refreshes exploit cache; e.g. after searchsploit -u):"
        echo "  -se, --search-exploits [ip]    searchsploit → cache (also in scout)"
        echo "  scout -r -se [ip]              refresh exploits then full report"
        echo ""
        echo "other:"
        echo "  -d, --dirs [path]              gobuster dir only"
        echo "  --force                        rescan ports / re-dispatch dirs (not -se)"
        echo "  -n, --dry-run                  show planned commands"
        echo "  -q, --quiet                    no port tables after scan"
        echo "  -w, --wordlist [id]            id/path, or bare -w to pick from list"
        echo "  -t, --threads                  gobuster threads"
        echo "  -x, --ext                      extension fuzz (-w omitted → default list)"
        echo ""
        echo "wordlist:"
        echo "  (omit -w)                      catalog default (common unless env set)"
        echo "  -w                             pick from dirs / dirs-ext (-x decides)"
        echo "  -w browse                      browse all catalog categories"
        echo ""
        echo "examples:"
        echo "  s -d /admin -x ticket          # default wordlist"
        echo "  s -d /admin -x ticket -w       # pick"
        echo "  s -d /admin -x ticket -w dirbuster-small"
        echo "  s -re"
        echo "  s -rp"
        echo "  s -se"
        echo "  s -d /admin"
        return 0
        ;;
      -rp|--report-ports)
        report_ports="-rp"
        shift
        ;;
      -re|--report-exploits)
        report_exploits="-re"
        shift
        ;;
      -se|--search-exploits)
        search_exploits="-se"
        shift
        ;;
      -r|--report)
        report="-r"
        shift
        ;;
      -p|--ports)
        echo "[!] -p is deprecated — use -rp" >&2
        report_ports="-rp"
        shift
        ;;
      -e|--exploit)
        echo "[!] -e is deprecated — use -se" >&2
        search_exploits="-se"
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
        if [[ -n "${1:-}" && "${1:-}" != -* ]]; then
          wordlist+=" $1"
          shift
        fi
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

  if [[ -n "$report_ports" && ( -n "$report" || -n "$report_exploits" ) ]]; then
    echo "[-] use one report flag: -r, -rp, or -re" >&2
    return 1
  fi
  if [[ -n "$report_exploits" && -n "$report" ]]; then
    echo "[-] use -r or -re, not both" >&2
    return 1
  fi
  if [[ -n "$search_exploits" && ( -n "$report_ports" || -n "$report_exploits" ) ]]; then
    echo "[-] -se combines with -r only (or use alone)" >&2
    return 1
  fi

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || {
      echo "[-] no target (ti <ip> / cs <case>)" >&2
      return 1
    }
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  local -a args=(scout)
  if [[ -n "$report_ports" ]]; then
    args+=(-rp)
  elif [[ -n "$report_exploits" ]]; then
    args+=(-re)
  elif [[ -n "$search_exploits" && -z "$report" ]]; then
    args+=(-se)
  elif [[ -n "$report" ]]; then
    args+=(-r)
    [[ -n "$search_exploits" ]] && args+=(-se)
  fi
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
    '-r[full report from DB]' '--report[full report from DB]' \
    '-rp[OPEN+CLOSED from DB]' '--report-ports[OPEN+CLOSED from DB]' \
    '-re[EXPLOITS from DB]' '--report-exploits[EXPLOITS from DB]' \
    '-se[searchsploit and cache]' '--search-exploits[searchsploit and cache]' \
    '-s[dirs status once]' '--status[dirs status once]' \
    '-ws[wait for dirs jobs]:sec:' '--wait-dirs[wait for dirs jobs]:sec:' \
    '-d[dirs only]:path:_path_files' '--dirs[dirs only]:path:_path_files' \
    '--force[rescan ports / re-dispatch dirs]' \
    '-n[dry-run]' \
    '-q[no port tables after scan]' \
    '-w[wordlist]:wordlist:_files' \
    '-t[threads]:threads:' \
    '-x[extensions]:ext:' \
    '*:ip:($IP)'
}

compdef _scout scout

# alias: s (scout hub)
alias s='noglob scout'
compdef _scout s
