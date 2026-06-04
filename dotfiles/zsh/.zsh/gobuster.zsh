# ========================
# gobuster helpers
# ========================

GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
GB_THREADS=40
GB_DIRS_THREADS=15
GB_WEB_ROOT="/usr/share/seclists/Discovery/Web-Content"

gb-normalize-url() {
  local url="$1"

  # http/https補完
  if [[ "$url" != http*://* ]]; then
    url="http://$url"
  fi

  echo "$url"
}

gb-resolve-target() {
  local target="${1:-}"

  if [[ -z "$target" ]]; then
    target="${IP:-}"
    [[ -z "$target" ]] && target="$(target-current 2>/dev/null)"
  fi

  if [[ -z "$target" ]]; then
    echo "usage: target-set <ip>  or pass url/ip as argument" >&2
    return 1
  fi

  echo "$target"
}

gb-set-web() {
  echo "Select Gobuster wordlist:"
  echo "1) raft-small"
  echo "2) raft-medium"
  echo "3) raft-large"
  echo "4) dirbuster-medium"
  echo "5) combined (heavy)"
  read -r choice

  case "$choice" in
    1)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
      ;;
    2)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
      ;;
    3)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
      ;;
    4)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
      ;;
    5)
      export GB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/combined_directories.txt"
      ;;
    *)
      echo "invalid"
      return 1
      ;;
  esac

  echo "[+] GB_WORDLIST set to:"
  echo "$GB_WORDLIST"
}

gb-set-dns() {
  echo "Select DNS wordlist:"
  echo "1) fast (5000)"
  echo "2) normal (20000)"
  echo "3) heavy (100k bitquark)"
  echo "4) full (combined)"
  echo "5) aggressive (jhaddix)"

  read -r c

  case "$c" in
    1)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
      ;;
    2)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
      ;;
    3)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
      ;;
    4)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/combined_subdomains.txt"
      ;;
    5)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
      ;;
    *)
      echo "invalid"
      return 1
      ;;
  esac

  echo "[+] GB_DNS_WORDLIST set:"
  echo "$GB_DNS_WORDLIST"
}

gb-set-threads() {
  echo "Select threads:"
  echo "1) safe   (10)"
  echo "2) normal (30)"
  echo "3) fast   (60)"
  echo "4) max    (100)"
  read -r c

  case "$c" in
    1) export GB_THREADS=10 ;;
    2) export GB_THREADS=30 ;;
    3) export GB_THREADS=60 ;;
    4) export GB_THREADS=100 ;;
    *) echo "invalid"; return 1 ;;
  esac

  echo "[+] GB_THREADS = $GB_THREADS"
}

_gb-url-host-slug() {
  local url="${1#http://}"
  url="${url#https://}"
  url="${url%%/*}"
  url="${url//:/_}"
  echo "${url:-target}"
}

_gb-list-slug() {
  local base="${1:t}"
  base="${base%.txt}"
  echo "${base//[^a-zA-Z0-9._-]/_}"
}

_gb-dirs-preset-lists() {
  local preset="$1"
  local r="$GB_WEB_ROOT"

  # One path per line so (${(@f)$(...)}) splits correctly in gb-dirs
  case "$preset" in
    ctf)
      print -r -- "$r/common.txt"
      print -r -- "$r/raft-small-directories.txt"
      print -r -- "$r/quickhits.txt"
      ;;
    fast)
      print -r -- "$r/common.txt"
      print -r -- "$r/quickhits.txt"
      ;;
    deep)
      print -r -- "$r/common.txt"
      print -r -- "$r/raft-small-directories.txt"
      print -r -- "$r/quickhits.txt"
      print -r -- "$r/raft-small-files.txt"
      ;;
    *)
      echo "[-] unknown preset: $preset (ctf|fast|deep)" >&2
      return 1
      ;;
  esac
}

_gb-dir-log-path() {
  local url="$1"
  local wordlist="$2"
  local logs host slug ts

  logs="$(case-logs-dir)" || return 1
  host="$(_gb-url-host-slug "$url")"
  slug="$(_gb-list-slug "$wordlist")"
  ts="$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$logs"
  echo "$logs/gobuster_${host}_${slug}_${ts}.log"
}

# Wait for background gobuster jobs; print each slug as it finishes (any order)
_gb-dirs-wait-jobs() {
  local -a pids=("${(@)1}")
  local -a slugs=("${(@)2}")
  local -a logfiles=("${(@)3}")
  local ok=0 fail=0 running=${#pids[@]}
  local -A finished=()
  local i pid rc last_heartbeat=0 now

  while (( running > 0 )); do
    for i in {1..${#pids[@]}}; do
      [[ -n "${finished[$i]:-}" ]] && continue
      pid="${pids[$i]}"
      if kill -0 "$pid" 2>/dev/null; then
        continue
      fi
      if wait "$pid"; then
        rc=0
      else
        rc=$?
      fi
      finished[$i]=1
      (( running-- ))
      if (( rc == 0 )); then
        (( ok++ ))
        echo "[+] done: ${slugs[$i]} (exit 0)"
      else
        (( fail++ ))
        echo "[-] failed: ${slugs[$i]} (exit $rc) — ${logfiles[$i]}" >&2
      fi
    done

    if (( running > 0 )); then
      now=$(date +%s)
      if (( now - last_heartbeat >= 15 )); then
        echo "[*] still running: $running job(s) (logs only; try: tail -f ${logfiles[1]:h}/gobuster_*)"
        last_heartbeat=$now
      fi
      sleep 2
    fi
  done

  return $(( fail > 0 ))
}

gb-dir() {
  local url=""
  local extensions=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -x|--ext)
        extensions="$2"
        shift 2
        ;;
      *)
        url="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$url" ]]; then
    url="$(gb-resolve-target)" || return 1
  fi

  url="$(gb-normalize-url "$url")"

  echo "========================"
  echo "[DIR] $url"
  echo "[*] WORDLIST: $GB_WORDLIST"
  echo "[*] THREADS: $GB_THREADS"
  echo "[*] EXTENSIONS: ${extensions:-none}"
  echo "========================"

  local args=(
    -u "$url"
    -w "$GB_WORDLIST"
    -t "$GB_THREADS"
    -q
  )

  if [[ -n "$extensions" ]]; then
    args+=(--extensions "$extensions")
  fi

  gobuster dir "${args[@]}"
}

gb-dirs() {
  local preset="ctf"
  local list_mode="ctf"
  local dry_run=false
  local threads="$GB_DIRS_THREADS"
  local url=""
  local extensions=""
  local -a wordlists=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p|--preset)
        preset="$2"
        list_mode="$2"
        shift 2
        ;;
      -w|--wordlist)
        wordlists+=("$2")
        list_mode="custom"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -x|--ext)
        extensions="$2"
        shift 2
        ;;
      -n|--dry-run)
        dry_run=true
        shift
        ;;
      -h|--help)
        echo "usage: gb-dirs [-p ctf|fast|deep] [-w wordlist]... [-t N] [-x ext] [-n] [url]"
        echo "  parallel gobuster dir (non-overlapping seclists presets)"
        echo "  logs: cases/<name>/logs/gobuster_<host>_<list>_<ts>.log"
        echo "  presets:"
        echo "    ctf  — common + raft-small-directories + quickhits (default)"
        echo "    fast — common + quickhits"
        echo "    deep — ctf + raft-small-files (4 jobs; use lower -t)"
        return 0
        ;;
      *)
        url="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$url" ]]; then
    url="$(gb-resolve-target)" || return 1
  fi
  url="$(gb-normalize-url "$url")"

  if (( ${#wordlists[@]} == 0 )); then
    wordlists=("${(@f)$(_gb-dirs-preset-lists "$preset")}") || return 1
  fi

  if [[ "$preset" == deep && $dry_run == false ]]; then
    echo "[!] deep preset runs ${#wordlists[@]} jobs — consider: gb-dirs -t 10" >&2
  fi

  local wl logfile slug
  local -a pids=() logfiles=() slugs=() gbargs=()

  echo "========================"
  echo "[DIRS] $url"
  echo "[*] MODE: $list_mode (${#wordlists[@]} wordlists)"
  echo "[*] THREADS (per job): $threads"
  echo "[*] EXTENSIONS: ${extensions:-none}"
  $dry_run && echo "[*] DRY-RUN"
  echo "========================"

  for wl in "${wordlists[@]}"; do
    if [[ ! -f "$wl" ]]; then
      echo "[-] wordlist not found: $wl" >&2
      return 1
    fi

    if $dry_run; then
      logfile="$(mktemp "${TMPDIR:-/tmp}/gb-dirs.XXXXXX.log")"
    else
      logfile="$(_gb-dir-log-path "$url" "$wl")" || return 1
    fi

    slug="$(_gb-list-slug "$wl")"
    slugs+=("$slug")
    logfiles+=("$logfile")

    echo "[+] ${slug}: $wl"
    $dry_run || echo "    log: $logfile"

    gbargs=(
      dir
      -u "$url"
      -w "$wl"
      -t "$threads"
      -q
    )
    [[ -n "$extensions" ]] && gbargs+=(--extensions "$extensions")

    if $dry_run; then
      echo "gobuster ${gbargs[@]} >\"$logfile\" 2>&1 &"
    else
      # Background in this shell (not $( )) so wait can reap children
      gobuster "${gbargs[@]}" >"$logfile" 2>&1 &
      pids+=($!)
    fi
  done

  $dry_run && return 0

  echo ""
  echo "[*] ${#pids[@]} job(s) started — gobuster output goes to logs (not this terminal)"
  echo "[*] live view: tail -f ${logfiles[1]:h}/gobuster_*"
  echo ""

  _gb-dirs-wait-jobs "${pids[@]}" "${slugs[@]}" "${logfiles[@]}"
  local wait_rc=$?

  echo ""
  echo "-----"
  if (( wait_rc == 0 )); then
    echo "[*] all ${#pids[@]} job(s) finished OK"
  else
    echo "[*] one or more jobs failed (see above)"
  fi
  echo "[*] logs:"
  for logfile in "${logfiles[@]}"; do
    echo "    $logfile"
  done
  if [[ -n "${logfiles[1]:h}" ]]; then
    echo "[*] hits: rg -i 'Status: 200' ${logfiles[1]:h}/gobuster_*"
  fi

  return $wait_rc
}

gb-dns() {
  local domain=""

  if [[ $# -ge 1 ]]; then
    domain="$1"
  else
    domain="${IP:-}"
  fi

  if [[ -z "$domain" ]]; then
    echo "usage: gb-dns [domain]  (or: target-set <ip>)"
    return 1
  fi

  echo "========================"
  echo "[DNS] $domain"
  echo "[*] WORDLIST: $GB_DNS_WORDLIST"
  echo "========================"

  gobuster dns \
    --domain "$domain" \
    -w "$GB_DNS_WORDLIST" \
    -t "$GB_THREADS" \
    -q
}

gb-vhost() {
  local ip=""

  if [[ $# -ge 1 ]]; then
    ip="$1"
  else
    ip="$(gb-resolve-target)" || return 1
  fi

  echo "=============================="
  echo "[VHOST]"
  echo "[*] TARGET IP: $ip"
  echo "[*] WORDLIST: $GB_WORDLIST"
  echo "[*] THREADS: $GB_THREADS"
  echo "=============================="

  echo "[HTTP] http://$ip"
  echo "------------------------------"

  gobuster vhost \
    -u "http://$ip" \
    -w "$GB_WORDLIST" \
    -t "$GB_THREADS" \
    -q

  echo "------------------------------"
  echo "[HTTPS] https://$ip"
  echo "------------------------------"

  gobuster vhost \
    -u "https://$ip" \
    -k \
    -w "$GB_WORDLIST" \
    -t "$GB_THREADS" \
    -q
}
