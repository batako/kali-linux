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

  local ip="" force="" dry="" quiet="" dirs_only="" dirs_multi="" dirs_preset="" scout_status="" wait_dirs="" wait_iv=""
  local wordlist="" threads="" ext=""
  local report="" report_ports="" report_exploits="" report_paths="" search_exploits=""
  local -a extra_urls=()
  local -a wordlist_ids=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scout [options] [ip|path|url...]  (alias: s)"
        echo ""
        echo "  scout / s / scout -d  dispatch dirs then auto-watch (-ws) until jobs finish"
        echo "  scout -ds           parallel dirs (preset tiers; default standard)"
        echo ""
        echo "dirs job status (pair):"
        echo "  -s, --status [ip]              show once"
        echo "  -ws, --wait-dirs [sec]         refresh until all jobs finish (default 2s)"
        echo ""
        echo "report (DB only, no rescan):"
        echo "  -r, --report [ip]              full report"
        echo "  -rp, --report-ports [ip]       OPEN + CLOSED"
        echo "  -re, --report-exploits [ip]   EXPLOITS"
        echo "  -rt, --report-paths [ip]      PATHS (dirs tree)"
        echo ""
        echo "search (always refreshes exploit cache; e.g. after searchsploit -u):"
        echo "  -se, --search-exploits [ip]    searchsploit → cache (also in scout)"
        echo "  scout -r -se [ip]              refresh exploits then full report"
        echo ""
        echo "exploit reject (manual — only after confirming N/A; untried picks stay):"
        echo "  erj <EDB> [--port 80/tcp]       hide from scout -re"
        echo "  eru <EDB> [--port 80/tcp]       undo"
        echo "  erl [ip]                        list rejected"
        echo ""
        echo "other:"
        echo "  -d, --dirs [path]              gobuster dir only (single wordlist)"
        echo "  -ds, --dirs-multi [path]       parallel dirs (see presets below)"
        echo "  --force                        rescan ports / re-dispatch dirs (not -se)"
        echo ""
        echo "dirs job cache (-d / -ds):"
        echo "  skip when same ip + url + wordlist is running or done"
        echo "  -x (extensions) is NOT part of the cache key — use --force to rerun with different -x"
        echo "  -n, --dry-run                  show planned commands"
        echo "  -q, --quiet                    no port tables after scan"
        echo "  -w, --wordlist [id]            id/path; bare -w on -d opens picker (-h: tier table below)"
        echo "  -t, --threads                  gobuster threads (-ds default: 15)"
        echo "  -x, --ext                      extension fuzz (-d only; default list: common)"
        echo ""
        echo "scout -ds -p (wordlist tiers: light → standard → wide → deep)"
        echo "  -p is NOT ports (ports report → -rp)."
        echo ""
        echo "  dirs (no -x):"
        echo "    light     common, quickhits"
        echo "    standard  + raft-small-directories          (default -ds)"
        echo "    wide      + raft-small-files"
        echo "    deep      + dirbuster-small, raft-small-words"
        echo ""
        echo "  dirs-ext (-x EXT):"
        echo "    light     common"
        echo "    standard  + dirbuster-small                 (default -ds -x)"
        echo "    wide      + dirbuster-medium"
        echo "    deep      + raft-small-files"
        echo ""
        echo "  -p next     next tier adds only (skip done jobs on same URL)"
        echo "  aliases: fast→light, ctf→standard"
        echo ""
        echo "  common wordlist ids (-w):"
        echo "    common, quickhits, raft-small-directories, raft-small-files,"
        echo "    raft-small-words, dirbuster-small, dirbuster-medium"
        echo ""
        echo "examples:"
        echo "  s -ds /admin                  # standard tier on /admin/"
        echo "  s -ds /assets                 # enumerate under /assets/"
        echo "  s -ds -p next /assets         # tier up when hits empty"
        echo "  s -ds -p wide /uploads        # cumulative through wide"
        echo "  s -ds -x php /backup          # ext fuzz, standard tier"
        echo "  s -ds -x bak -p next /api     # next ext tier"
        echo "  s -d /config -w dirbuster-small"
        echo "  s -rp                         # port list (not -p)"
        echo "  s -rt                         # dirs PATHS tree only"
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
      -rt|--report-paths)
        report_paths="-rt"
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
      --ports)
        echo "[!] --ports is deprecated — use -rp" >&2
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
      -ds|--dirs-multi)
        dirs_multi="--dirs-multi"
        shift
        if [[ -n "${1:-}" ]] && _scout-is-path "$1"; then
          extra_urls+=("$1")
          shift
        elif [[ -n "${1:-}" && "$1" != -* && ! "$1" =~ $(_recon-ip-re) ]]; then
          extra_urls+=("$1")
          shift
        fi
        ;;
      -p|--preset)
        shift
        if [[ "${1:-}" =~ ^(light|standard|wide|deep|next|ctf|fast)$ ]]; then
          dirs_preset="-p $1"
          shift
        elif [[ -n "$dirs_multi" ]]; then
          echo "[-] unknown preset: ${1:-} (light|standard|wide|deep|next)" >&2
          return 1
        else
          echo "[!] -p is deprecated for ports — use -rp (or -ds -p ctf|fast|deep)" >&2
          report_ports="-rp"
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
        shift
        if [[ -n "${1:-}" && "${1:-}" != -* ]]; then
          if [[ -n "$dirs_multi" ]]; then
            wordlist_ids+=(-w "$1")
          else
            wordlist="-w $1"
          fi
          shift
        elif [[ -n "$dirs_multi" ]]; then
          echo "[-] scout -ds needs -p preset or repeated -w <catalog-id>" >&2
          return 1
        else
          wordlist="-w"
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
        elif [[ -n "$dirs_only$dirs_multi" ]] && _scout-is-path "$1"; then
          extra_urls+=("$1")
        elif [[ -n "$dirs_only$dirs_multi" && "$1" != -* ]]; then
          extra_urls+=("$1")
        else
          echo "[-] expected ip or use -d/-ds with path, got: $1" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -n "$report_ports" && ( -n "$report" || -n "$report_exploits" || -n "$report_paths" ) ]]; then
    echo "[-] use one report flag: -r, -rp, -re, or -rt" >&2
    return 1
  fi
  if [[ -n "$report_exploits" && ( -n "$report" || -n "$report_paths" ) ]]; then
    echo "[-] use one report flag: -r, -re, or -rt" >&2
    return 1
  fi
  if [[ -n "$report_paths" && -n "$report" ]]; then
    echo "[-] use -r or -rt, not both" >&2
    return 1
  fi
  if [[ -n "$search_exploits" && ( -n "$report_ports" || -n "$report_exploits" || -n "$report_paths" ) ]]; then
    echo "[-] -se combines with -r only (or use alone)" >&2
    return 1
  fi

  if [[ -n "$dirs_only" && -n "$dirs_multi" ]]; then
    echo "[-] use -d or -ds, not both" >&2
    return 1
  fi

  if [[ -n "$dirs_preset" && -z "$dirs_multi" ]]; then
    echo "[-] -p/--preset requires scout -ds" >&2
    return 1
  fi

  if [[ ${#wordlist_ids[@]} -gt 0 && -z "$dirs_multi" ]]; then
    echo "[-] repeat -w requires scout -ds" >&2
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
  elif [[ -n "$report_paths" ]]; then
    args+=(-rt)
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
  [[ -n "$dirs_multi" ]] && args+=("$dirs_multi")
  [[ -n "$dirs_preset" ]] && args+=(${=dirs_preset})
  [[ -n "$force" ]] && args+=("$force")
  [[ -n "$dry" ]] && args+=(-n)
  [[ -n "$quiet" ]] && args+=(-q)
  args+=("${extra_urls[@]}")
  [[ -n "$threads" ]] && args+=(${=threads})
  [[ -n "$ext" ]] && args+=(${=ext})
  args+=("$ip")
  # -w after ip so bare `-w` is not parsed as `-w <ip>` in recon.py
  if (( ${#wordlist_ids[@]} )); then
    args+=("${wordlist_ids[@]}")
  elif [[ -n "$wordlist" ]]; then
    args+=(${=wordlist})
  fi

  python3 "$RECON_APP" "${args[@]}"
}

_scout() {
  _arguments \
    '-h[usage]' '--help[usage]' \
    '-r[full report from DB]' '--report[full report from DB]' \
    '-rp[OPEN+CLOSED from DB]' '--report-ports[OPEN+CLOSED from DB]' \
    '-re[EXPLOITS from DB]' '--report-exploits[EXPLOITS from DB]' \
    '-rt[PATHS tree from DB]' '--report-paths[PATHS tree from DB]' \
    '-se[searchsploit and cache]' '--search-exploits[searchsploit and cache]' \
    '-s[dirs status once]' '--status[dirs status once]' \
    '-ws[wait for dirs jobs]:sec:' '--wait-dirs[wait for dirs jobs]:sec:' \
    '-d[dirs only]:path:_path_files' '--dirs[dirs only]:path:_path_files' \
    '-ds[parallel dirs]:path:_path_files' '--dirs-multi[parallel dirs]:path:_path_files' \
    '-p[preset light|standard|wide|deep|next with -ds]:preset:(light standard wide deep next)' \
    '--preset[preset with -ds]:preset:(light standard wide deep next)' \
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
