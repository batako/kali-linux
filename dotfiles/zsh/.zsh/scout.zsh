# ========================
# scout — scan + probes + background gobuster dirs
# ========================

_scout-is-path() {
  [[ "$1" == /* || "$1" == http://* || "$1" == https://* ]]
}

_scout-is-vhost() {
  [[ "$1" != /* && "$1" != http://* && "$1" != https://* && "$1" != :* && "$1" != .* ]] \
    && [[ "$1" == *.* ]] \
    && [[ "$1" =~ '^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$' ]]
}

_scout-set-vhost() {
  if [[ -n "$host_header" ]]; then
    echo "[-] use one vhost hostname (-H or positional FQDN)" >&2
    return 1
  fi
  host_header="-H $1"
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

  local ip="" force="" dry="" quiet="" full_ports="" scan_jobs="" dirs_only="" dirs_multi="" dirs_preset="" scout_status="" wait_dirs="" wait_iv=""
  local plan_only="" no_plan=""
  local vhosts_only="" vhosts_target=""
  local wordlist="" threads="" ext="" host_header="" dirs_ext_fuzz=""
  local report="" report_ports="" report_exploits="" report_exploit_pack="" report_paths="" report_tree_fetch="" search_exploits=""
  local -a extra_urls=()
  local -a wordlist_ids=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scout [options] [ip|path|url...]"
        echo "  alias: s"
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
        echo "  -ep, --exploit-pack [ip]       AI submission → cases/<room>/plans/*.md"
        echo "  -rt, --report-paths [ip]      PATHS (dirs tree)"
        echo "  -rtf, --report-tree-fetch [ip]  PATHS → sitemap + local mirror (-n dry-run)"
        echo ""
        echo "search (always refreshes exploit cache; e.g. after searchsploit -u):"
        echo "  -se, --search-exploits [ip]    searchsploit → cache (also in scout)"
        echo "  scout -r -se [ip]              refresh exploits then full report"
        echo ""
        echo "exploit reject (manual — only after confirming N/A; untried picks stay):"
        echo "  exploit-reject <EDB> [--port 80/tcp]    hide from scout -re  (alias: erj)"
        echo "  exploit-unreject <EDB> [--port 80/tcp]  undo  (alias: eru)"
        echo "  exploit-rejects [ip]                    list rejected  (alias: erl)"
        echo ""
        echo "ports (scan only — like -d for gobuster):"
        echo "  -fp, --full-ports              TCP 1-65535 then searchsploit (-se)"
        echo "  -j, --jobs N                   with -fp: parallel full scan (e.g. -fp -j 4)"
        echo ""
        echo "vhost discovery (THM / IP):"
        echo "  -v, --vhosts [domain|ip]       Host: FUZZ.domain (ffuf) or gobuster vhost on IP"
        echo "  s -v example.com                 # vhost discovery (hosts apex first)"
        echo "  s -d -H www.example.com          # dir on discovered vhost"
        echo ""
        echo "other:"
        echo "  -d, --dirs [path]              gobuster dir (single wl)"
        echo "  -dx, --dirs-ext-fuzz [path]    ffuf extension fuzz (requires -dx; .FUZZ / stem.* with -dx)"
        echo "  -ds, --dirs-multi [path]       parallel dirs (see presets below)"
        echo "  --force                        rescan ports / re-dispatch dirs (not -se)"
        echo "  --plan                         auth-quick enqueue only (phase 2.5; no hydra)"
        echo "  --no-plan                      skip auth enqueue during full scout"
        echo ""
        echo "attack queue (see also: strike):"
        echo "  s --plan [ip]                  enqueue auth tasks from DB ports"
        echo "  strike [ip]                    run pending auth tasks"
        echo "  strike -l                      list tasks"
        echo ""
        echo "dirs job cache (-d / -ds):"
        echo "  skip when same ip + url + wordlist + Host is running or done"
        echo "  -x (extensions) is NOT part of the cache key — use --force to rerun with different -x"
        echo "  -n, --dry-run                  show planned commands"
        echo "  -q, --quiet                    no port tables after scan"
        echo "  -w, --wordlist [id]            id/path; bare -w on -d opens picker (-h: tier table below)"
        echo "  -t, --threads                  gobuster threads (-ds default: 15)"
        echo "  -x, --ext                      extension fuzz (-d only; default list: common)"
        echo "  -H, --host <name>              vhost Host header (-d/-ds only; IP URL + Host: name)"
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
        echo "  s -dx /scripts/script.txt       # ffuf ext fuzz (script.FUZZ)"
        echo "  s -dx /scripts/script.FUZZ      # stem with dots — explicit marker"
        echo "  s -d /scripts/script.FUZZ/      # literal dir named script.FUZZ"
        echo "  s -dx /scripts/script.*         # stem.* syntax (requires -dx)"
        echo "  s -d /config -w dirbuster-small"
        echo "  s -v example.com                    # vhost discovery (hosts apex first)"
        echo "  s -d -H www.example.com             # dir on discovered vhost"
        echo "  s -d -H app.example.com               # gobuster with Host: app.example.com"
        echo "  s -ds :65524/hidden/           # http://\$IP:65524/hidden/"
        echo "  s -ds :443/hoge                # https://\$IP/hoge/"
        echo "  s -ds :80/fuga                 # http://\$IP/fuga/"
        echo "  s -rp                         # port list (not -p)"
        echo "  s -rt                         # dirs PATHS tree only"
        echo "  s -rtf                        # PATHS sitemap + download (200/301 + crawl)"
        echo "  s -rtf -n                     # planned URLs only"
        echo "  s -fp                         # full port scan (65535) + exploit search"
        echo "  s -fp -j 4                    # same, 4 parallel nmap workers"
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
      -ep|--exploit-pack)
        report_exploit_pack="-ep"
        shift
        ;;
      -rt|--report-paths)
        report_paths="-rt"
        shift
        ;;
      -rtf|--report-tree-fetch)
        report_tree_fetch="-rtf"
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
      -v|--vhosts)
        vhosts_only=1
        shift
        if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
          _scout-vhosts-help
          return 0
        fi
        if [[ -n "${1:-}" && "$1" != -* ]]; then
          vhosts_target="$1"
          shift
        fi
        ;;
      -d|--dirs)
        dirs_only="--dirs"
        shift
        if [[ -n "${1:-}" ]] && _scout-is-path "$1"; then
          extra_urls+=("$1")
          shift
        elif [[ -n "${1:-}" && "$1" != -* && ! "$1" =~ $(_recon-ip-re) ]]; then
          if _scout-is-vhost "$1"; then
            _scout-set-vhost "$1" || return $?
          else
            extra_urls+=("$1")
          fi
          shift
        fi
        ;;
      -dx|--dirs-ext-fuzz)
        dirs_ext_fuzz="--dirs-ext-fuzz"
        dirs_only="--dirs"
        shift
        if [[ -n "${1:-}" ]] && _scout-is-path "$1"; then
          extra_urls+=("$1")
          shift
        elif [[ -n "${1:-}" && "$1" != -* && ! "$1" =~ $(_recon-ip-re) ]]; then
          if _scout-is-vhost "$1"; then
            _scout-set-vhost "$1" || return $?
          else
            extra_urls+=("$1")
          fi
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
          if _scout-is-vhost "$1"; then
            _scout-set-vhost "$1" || return $?
          else
            extra_urls+=("$1")
          fi
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
      --plan)
        plan_only="--plan"
        shift
        ;;
      --no-plan)
        no_plan="--no-plan"
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
      -fp|--full-ports)
        full_ports="--full-ports"
        shift
        ;;
      -j|--jobs)
        scan_jobs="-j $2"
        shift 2
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
      -H|--host)
        host_header="-H $2"
        shift 2
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
          if _scout-is-vhost "$1"; then
            _scout-set-vhost "$1" || return $?
          else
            extra_urls+=("$1")
          fi
        else
          echo "[-] expected ip or use -d/-ds with path, got: $1" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -n "$report_ports" && ( -n "$report" || -n "$report_exploits" || -n "$report_exploit_pack" || -n "$report_paths" || -n "$report_tree_fetch" ) ]]; then
    echo "[-] use one report flag: -r, -rp, -re, -ep, -rt, or -rtf" >&2
    return 1
  fi
  if [[ -n "$report_exploits" && ( -n "$report" || -n "$report_exploit_pack" || -n "$report_paths" || -n "$report_tree_fetch" ) ]]; then
    echo "[-] use one report flag: -r, -re, -ep, -rt, or -rtf" >&2
    return 1
  fi
  if [[ -n "$report_exploit_pack" && ( -n "$report" || -n "$report_paths" || -n "$report_tree_fetch" ) ]]; then
    echo "[-] use one report flag: -r, -ep, -rt, or -rtf" >&2
    return 1
  fi
  if [[ -n "$report_paths" && ( -n "$report" || -n "$report_tree_fetch" ) ]]; then
    echo "[-] use one report flag: -r, -rt, or -rtf" >&2
    return 1
  fi
  if [[ -n "$report_tree_fetch" && -n "$report" ]]; then
    echo "[-] use -r or -rtf, not both" >&2
    return 1
  fi
  if [[ -n "$search_exploits" && ( -n "$report_ports" || -n "$report_exploits" || -n "$report_exploit_pack" || -n "$report_paths" || -n "$report_tree_fetch" ) ]]; then
    echo "[-] -se combines with -r only (or use alone)" >&2
    return 1
  fi

  if [[ -n "$vhosts_only" ]]; then
    if [[ -n "$dirs_only$dirs_multi$report$report_ports$report_exploits$report_exploit_pack$report_paths$report_tree_fetch$search_exploits$scout_status$wait_dirs$full_ports$force$dry$quiet$threads$ext$host_header" ]] \
      || (( ${#wordlist_ids[@]} )) || [[ -n "$wordlist$dirs_preset$scan_jobs" ]]; then
      echo "[-] scout -v is standalone — do not combine with other flags" >&2
      return 1
    fi
    if [[ $# -gt 0 ]]; then
      echo "[-] scout -v: unexpected arguments: $*" >&2
      return 1
    fi
  fi

  if [[ -n "$vhosts_only" ]]; then
    (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null
    _scout-vhosts ${vhosts_target:+"$vhosts_target"}
    return $?
  fi

  if [[ -n "$dirs_ext_fuzz" && -n "$dirs_multi" ]]; then
    echo "[-] use -dx with -d only, not -ds" >&2
    return 1
  fi

  if [[ -n "$dirs_ext_fuzz" && -n "$ext" ]]; then
    echo "[-] -dx (ffuf ext fuzz) does not combine with gobuster -x" >&2
    return 1
  fi

  if [[ -n "$dirs_ext_fuzz" && ${#extra_urls[@]} -eq 0 ]]; then
    echo "[-] -dx requires a file stem path (e.g. /scripts/script or /scripts/script.txt)" >&2
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

  if [[ -n "$host_header" && -z "$dirs_only$dirs_multi" ]]; then
    echo "[-] -H/--host requires scout -d or -ds" >&2
    return 1
  fi

  if [[ ${#wordlist_ids[@]} -gt 0 && -z "$dirs_multi" ]]; then
    echo "[-] repeat -w requires scout -ds" >&2
    return 1
  fi

  if [[ -n "$scan_jobs" && -z "$full_ports" ]]; then
    echo "[-] scout -j requires -fp (--full-ports)" >&2
    return 1
  fi

  if [[ -n "$plan_only" && ( -n "$dirs_only$dirs_multi$report$report_ports$report_exploits$report_exploit_pack$report_paths$report_tree_fetch$search_exploits$scout_status$wait_dirs$full_ports$vhosts_only" ) ]]; then
    echo "[-] --plan does not combine with -d, -ds, -s, -ws, -se, -fp, -v, or report flags" >&2
    return 1
  fi

  if [[ -n "$full_ports" && ( -n "$dirs_only" || -n "$dirs_multi" || -n "$scout_status" || -n "$wait_dirs" || -n "$search_exploits" || -n "$report" || -n "$report_ports" || -n "$report_exploits" || -n "$report_exploit_pack" || -n "$report_paths" || -n "$report_tree_fetch" ) ]]; then
    echo "[-] -fp is port scan only — do not combine with report/status/dirs flags" >&2
    return 1
  fi

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || {
      echo "[-] no target (target-set <ip> / case-set <room>)" >&2
      return 1
    }
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  local -a args=(scout)
  if [[ -n "$report_ports" ]]; then
    args+=(-rp)
  elif [[ -n "$report_exploits" ]]; then
    args+=(-re)
  elif [[ -n "$report_exploit_pack" ]]; then
    args+=(-ep)
  elif [[ -n "$report_paths" ]]; then
    args+=(-rt)
  elif [[ -n "$report_tree_fetch" ]]; then
    args+=(-rtf)
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
  [[ -n "$dirs_ext_fuzz" ]] && args+=("$dirs_ext_fuzz")
  [[ -n "$dirs_multi" ]] && args+=("$dirs_multi")
  [[ -n "$host_header" ]] && args+=(${=host_header})
  [[ -n "$dirs_preset" ]] && args+=(${=dirs_preset})
  [[ -n "$force" ]] && args+=("$force")
  [[ -n "$plan_only" ]] && args+=("$plan_only")
  [[ -n "$no_plan" ]] && args+=("$no_plan")
  [[ -n "$dry" ]] && args+=(-n)
  [[ -n "$quiet" ]] && args+=(-q)
  [[ -n "$full_ports" ]] && args+=("$full_ports")
  [[ -n "$scan_jobs" ]] && args+=(${=scan_jobs})
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
    '-ep[AI exploit submission pack]' '--exploit-pack[AI exploit submission pack]' \
    '-rt[PATHS tree from DB]' '--report-paths[PATHS tree from DB]' \
    '-rtf[PATHS sitemap + mirror]' '--report-tree-fetch[PATHS sitemap + mirror]' \
    '-se[searchsploit and cache]' '--search-exploits[searchsploit and cache]' \
    '-s[dirs status once]' '--status[dirs status once]' \
    '-ws[wait for dirs jobs]:sec:' '--wait-dirs[wait for dirs jobs]:sec:' \
    '-v[vhost discovery (ffuf / gobuster)]' '--vhosts[vhost discovery (ffuf / gobuster)]' \
    '-d[dirs only]:path:_path_files' '--dirs[dirs only]:path:_path_files' \
    '-ds[parallel dirs]:path:_path_files' '--dirs-multi[parallel dirs]:path:_path_files' \
    '-p[preset light|standard|wide|deep|next with -ds]:preset:(light standard wide deep next)' \
    '--preset[preset with -ds]:preset:(light standard wide deep next)' \
    '--force[rescan ports / re-dispatch dirs]' \
    '-fp[full TCP 1-65535 scan + exploit search]' '--full-ports[full TCP 1-65535 scan + exploit search]' \
    '-j[parallel full scan workers with -fp]:jobs:' '--jobs[parallel full scan workers with -fp]:jobs:' \
    '-n[dry-run]' \
    '-q[no port tables after scan]' \
    '-w[wordlist]:wordlist:_files' \
    '-t[threads]:threads:' \
    '-x[extensions]:ext:' \
    '-H[vhost Host header with -d/-ds]:host:' '--host[vhost Host header with -d/-ds]:host:' \
    '*:ip:($IP)'
}

compdef _scout scout

# alias: s (scout hub)
alias s='noglob scout'
compdef _scout s
