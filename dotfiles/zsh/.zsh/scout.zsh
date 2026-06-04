# ========================
# scout — scan + probes + background gobuster dirs
# ========================

scout() {
  if [[ "${1:-}" == "status" ]]; then
    shift
    local ip=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -h|--help)
          echo "usage: scout status [ip]"
          echo "  show scout_jobs (dirs): running/done, logs, hit summary"
          return 0
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
    python3 "$RECON_APP" scout status "$ip"
    return $?
  fi

  local ip="" force="" dry="" quiet="" dirs_only="" wordlist="" threads="" ext=""
  local -a extra_urls=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: scout [options] [ip|url...]"
        echo "  phase 1: scan (nmap top 1000 -sC -sV)"
        echo "  phase 2: open 22/80 → probe by nmap service (ssh/http/ftp)"
        echo "  phase 3: Web open ports → gobuster dir (background, cases/.../logs/)"
        echo ""
        echo "options:"
        echo "  -h, --help        this help"
        echo "  --dirs            phase 3 only (gobuster dir)"
        echo "  --force           force rescan / re-dispatch running dirs jobs"
        echo "  -n, --dry-run     show planned commands"
        echo "  -q, --quiet       no port tables after scan"
        echo "  -w, --wordlist    wordlist path (default: \$GB_WORDLIST)"
        echo "  -t, --threads     gobuster threads (default: \$GB_THREADS)"
        echo "  -x, --ext         file extensions for gobuster"
        echo ""
        echo "subcommand:"
        echo "  scout status [ip]   dirs job status + hit summary"
        echo ""
        echo "prep: cs <case>  &&  ti <ip>"
        echo "view: ev <exec_id>   el [ip]   scout status"
        return 0
        ;;
      --dirs)
        dirs_only="--dirs"
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
        else
          echo "[-] expected ip or url, got: $1" >&2
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
    '--dirs[phase 3 only]' \
    '--force[force rescan / re-dispatch dirs]' \
    '-n[dry-run]' \
    '-q[no port tables after scan]' \
    '-w[wordlist]:wordlist:_files' \
    '-t[threads]:threads:' \
    '-x[extensions]:ext:' \
    '1: :(( status scout ))' \
    '*:ip:($IP)'
}

compdef _scout scout
