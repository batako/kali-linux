# ========================
# gobuster helpers
# ========================

# vhost discovery: scout -v (s -v); dir scans use scout -d / scout -ds
GB_VHOST_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
GB_THREADS=15

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

gb-set-dns() {
  echo "Select DNS wordlist:"
  echo "1) fast (5000)"
  echo "2) normal (20000)"
  echo "3) heavy (100k bitquark)"
  echo "4) full (combined)"
  echo "5) aggressive (jhaddix)"
  echo "6) 110k"

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
    6)
      export GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
      ;;
    *)
      echo "invalid"
      return 1
      ;;
  esac

  echo "[+] GB_DNS_WORDLIST set:"
  echo "$GB_DNS_WORDLIST"
}

gb-dirs() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "deprecated: use scout -ds"
    echo "  alias: s"
    echo ""
    echo "usage: scout -ds [-p light|standard|wide|deep|next] [-w id]... [-t N] [-x ext] [-n] [path|url]"
    echo "  tiers (light → standard → wide → deep):"
    echo "    standard — default -ds (3 jobs on dirs)"
    echo "    next     — next tier adds only"
    echo ""
    echo "examples:"
    echo "  scout -ds /admin"
    echo "  scout -ds -p next /assets"
    echo "  scout -ds -p wide -n"
    return 0
  fi
  echo "[!] gb-dirs is deprecated — use: scout -ds" >&2
  scout -ds "$@"
}

_gb-is-ip() {
  [[ "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]
}

_gb-vhost-run() {
  local scheme="$1" url="$2" wordlist="$3" append_domain="$4"
  local -a args=(
    gobuster vhost
    -u "${scheme}://${url}"
    -w "$wordlist"
    -t "$GB_THREADS"
    -q
  )

  [[ "$scheme" == https ]] && args+=(-k)
  [[ -n "$append_domain" ]] && args+=(--append-domain)
  if [[ -n "${GB_VHOST_EXCLUDE_LENGTH:-}" ]]; then
    args+=(--exclude-length "$GB_VHOST_EXCLUDE_LENGTH")
  fi

  "${args[@]}"
}

# THM domain mode: ffuf Host FUZZ.domain (gobuster vhost は応答差分検出が不安定)
_gb-vhost-print-summary() {
  local json="$1" domain="$2"
  [[ -f "$json" ]] || {
    echo "[i] no results file"
    return 0
  }
  python3 -c "
import json, sys
path, domain = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    print('[i] could not read results')
    sys.exit(0)
rows = data.get('results') or []
if not rows:
    print('[-] no vhosts found')
    sys.exit(0)
for r in rows:
    fuzz = (r.get('input') or {}).get('FUZZ', '?')
    host = f'{fuzz}.{domain}' if fuzz != '?' else domain
    print(f\"[+] {host}\tstatus={r.get('status', '?')}\tsize={r.get('length', '?')}\")
" "$json" "$domain"
}

_gb-vhost-hostnames-from-json() {
  local json="$1" domain="$2"
  [[ -f "$json" ]] || return 0
  python3 -c "
import json, sys
path, domain = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    sys.exit(0)
seen = set()
for r in data.get('results') or []:
    fuzz = (r.get('input') or {}).get('FUZZ')
    if not fuzz:
        continue
    host = f'{fuzz}.{domain}'
    if host not in seen:
        seen.add(host)
        print(host)
" "$json" "$domain"
}

_gb-vhost-ffuf-filter() {
  local domain="$1" total="${2:-0}"
  python3 -u -c "
import re, sys

domain = sys.argv[1]
total_hint = int(sys.argv[2] or 0)
progress_re = re.compile(r'Progress:\s*\[(\d+)/(\d+)\]')
errors_re = re.compile(r'Errors:\s*(\d+)')
hit_re = re.compile(r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)')
ansi_re = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')

state = {'cur': 0, 'tot': total_hint, 'errors': 0}
seen_hosts = set()
header_done = False
progress_active = False
last_drawn = -1

def progress_line():
    cur, tot = state['cur'], state['tot']
    if not tot:
        return None
    pct = cur * 100 // tot
    err = state['errors']
    suffix = f'  errors={err}' if err else ''
    return f'[*] {cur}/{tot} ({pct}%){suffix}'

def ensure_header():
    global header_done
    if header_done:
        return
    sys.stderr.write('===== results =====\n')
    sys.stderr.flush()
    header_done = True

def clear_progress():
    global progress_active
    if progress_active:
        sys.stderr.write('\r\033[2K')
        sys.stderr.flush()
        progress_active = False

def show_progress(force=False):
    global progress_active, last_drawn
    pl = progress_line()
    if not pl:
        return
    if not force and state['cur'] == last_drawn:
        return
    last_drawn = state['cur']
    ensure_header()
    sys.stderr.write('\r\033[2K' + pl)
    sys.stderr.flush()
    progress_active = True

def add_hit(host, status, size):
    global progress_active, last_drawn
    ensure_header()
    clear_progress()
    sys.stderr.write(f'[+] {host}\tstatus={status}\tsize={size}\n')
    sys.stderr.flush()
    last_drawn = -1
    show_progress(force=True)

def finish():
    ensure_header()
    clear_progress()
    if not seen_hosts:
        sys.stderr.write('[-] no vhosts found\n')
    else:
        sys.stderr.write('\n')
    sys.stderr.flush()

def apply_progress(text):
    ms = list(progress_re.finditer(text))
    if not ms:
        return
    m = ms[-1]
    state['cur'] = int(m.group(1))
    state['tot'] = int(m.group(2))
    em = errors_re.search(m.group(0))
    if em:
        state['errors'] = int(em.group(1))
    show_progress()

def apply_hits(text):
    for line in text.splitlines():
        line = ansi_re.sub('', line).strip()
        if not line:
            continue
        m = hit_re.search(line)
        if not m:
            continue
        fuzz, status, size = m.groups()
        host = f'{fuzz}.{domain}'
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        add_hit(host, status, size)

def scan_buf(buf):
    clean = ansi_re.sub('', buf)
    if 'Progress:' in clean:
        apply_progress(clean)
    apply_hits(clean)

show_progress(force=True)

buf = ''
while True:
    chunk = sys.stdin.buffer.read(256)
    if not chunk:
        break
    buf += chunk.decode('utf-8', errors='replace')
    scan_buf(buf)
    if len(buf) > 8192:
        buf = buf[-4096:]

if buf.strip():
    scan_buf(buf)

finish()
" "$domain" "$total"
}

_gb-vhost-register-hosts() {
  local json="$1" domain="$2"
  local f ip name
  local -a names new_names

  [[ -f "$json" ]] || return 1
  (( $+functions[_hosts-register-line] )) || return 1

  while IFS= read -r name; do
    [[ -n "$name" ]] && names+=("$name")
  done < <(_gb-vhost-hostnames-from-json "$json" "$domain")
  (( ${#names[@]} )) || return 1

  f="$(_hosts-case-file 2>/dev/null)" || {
    echo "[i] case not set — skipping auto-register"
    return 1
  }
  ip="$(_hosts-default-ip 2>/dev/null)" || {
    echo "[i] no target IP — skipping auto-register"
    return 1
  }

  for name in "${names[@]}"; do
    if [[ -f "$f" ]] && grep -qw -- "$name" "$f" 2>/dev/null; then
      continue
    fi
    new_names+=("$name")
  done

  if (( ! ${#new_names[@]} )); then
    echo "[=] all vhosts already in cases/${CASE:-?}/hosts"
    return 0
  fi

  echo "[*] registering ${#new_names[@]} vhost(s) → cases/${CASE:-?}/hosts"
  if (( ${#new_names[@]} == 1 )); then
    _hosts-register-line append "${new_names[1]}"
  else
    _hosts-register-line append "${new_names[1]}" "${new_names[@]:2}"
  fi
}

_gb-vhost-domain-ffuf() {
  local domain="$1" wordlist="$2"
  local fs="${GB_VHOST_EXCLUDE_LENGTH:-0}"
  local ts base logs_dir rc wl_total
  local -a args

  ts="$(date +%Y%m%d-%H%M%S)"
  if logs_dir="$(case-logs-dir 2>/dev/null)"; then
    base="${logs_dir}/vhost_${domain//\./_}_${ts}"
  else
    base="${TMPDIR:-/tmp}/vhost_${domain//\./_}_${ts}"
    echo "[i] case not set — log under $base.*" >&2
  fi

  args=(
    ffuf
    -w "$wordlist"
    -H "Host: FUZZ.${domain}"
    -u "http://${domain}/"
    -t "$GB_THREADS"
    -o "${base}.json"
    -of json
  )
  if [[ -n "$fs" ]]; then
    args+=(-fs "$fs")
  fi

  wl_total="$(wc -l <"$wordlist" | tr -d '[:space:]')"

  echo "[*] log:  ${base}.log"
  echo "[*] json: ${base}.json"
  echo "[*] scan: ${wl_total:-?} names × Host: FUZZ.${domain}"
  echo ""

  local cmd
  local -a run_cmd
  if command -v stdbuf >/dev/null 2>&1; then
    run_cmd=(stdbuf -o0 -e0 "${args[@]}")
  else
    run_cmd=("${args[@]}")
  fi
  cmd="${(j: :)${(@q)run_cmd}}"

  if command -v script >/dev/null 2>&1; then
    # -f: flush PTY capture each write (progress uses \r, not \n)
    script -q -e -f -c "$cmd" /dev/null 2>&1 | _gb-vhost-ffuf-filter "$domain" "$wl_total"
  else
    "${run_cmd[@]}" 2>&1 | _gb-vhost-ffuf-filter "$domain" "$wl_total"
  fi
  rc=${pipestatus[1]:-$?}

  {
    echo "===== results ====="
    _gb-vhost-print-summary "${base}.json" "$domain"
  } >"${base}.log"

  if _gb-vhost-hostnames-from-json "${base}.json" "$domain" | grep -q .; then
    echo "===== hosts ====="
    _gb-vhost-register-hosts "${base}.json" "$domain"
  fi

  return $rc
}

gb-dns() {
  local domain=""

  if [[ "${1:-}" == "-h" || "${1:-}" == --help ]]; then
    echo "usage: gb-dns [domain]"
    echo "  real DNS brute-force (gobuster dns)"
    echo "  THM *.thm with only /etc/hosts → use: scout -v lookup.thm"
    return 0
  fi

  if [[ $# -ge 1 ]]; then
    domain="$1"
  else
    domain="${IP:-}"
  fi

  if [[ -z "$domain" ]]; then
    echo "usage: gb-dns [domain]" >&2
    return 1
  fi

  if [[ "$domain" == *.thm ]]; then
    echo "[i] gb-dns: *.thm は THM の DNS に引かないことが多いです" >&2
    echo "    Host ヘッダ列挙なら: scout -v ${domain}" >&2
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

_scout-vhosts-help() {
  echo "usage: scout -v [domain|ip]   (alias: s -v)"
  echo "  s -v lookup.thm   # THM: ffuf -H 'Host: FUZZ.lookup.thm' -u http://lookup.thm"
  echo "  s -v              # IP 直叩き gobuster (raft-small-words)"
  echo ""
  echo "  prereq (THM): hosts lookup.thm  (apex のみ。サブドメインは終了後に自動登録)"
  echo "  wordlist: GB_DNS_WORDLIST (gb-set-dns で変更可)"
  echo "  filter:   GB_VHOST_EXCLUDE_LENGTH (domain 既定 0 = ffuf -fs 0)"
  echo "  hosts:    ヒットを cases/<room>/hosts に自動追記"
  echo ""
  echo "  見つけた vhost で dir: s -d -H www.lookup.thm"
}

_scout-vhosts() {
  local target="" wordlist=""

  if [[ "${1:-}" == "-h" || "${1:-}" == --help ]]; then
    _scout-vhosts-help
    return 0
  fi

  if [[ $# -ge 1 ]]; then
    target="$1"
  else
    target="$(gb-resolve-target)" || return 1
  fi

  if _gb-is-ip "$target"; then
    wordlist="$GB_VHOST_WORDLIST"
    echo "=============================="
    echo "[VHOST] IP mode"
    echo "[*] TARGET: $target"
    echo "[*] WORDLIST: $wordlist"
    echo "[*] THREADS: $GB_THREADS"
    echo "=============================="

    echo "[HTTP] http://$target"
    echo "------------------------------"
    _gb-vhost-run http "$target" "$wordlist" ""
    echo "------------------------------"
    echo "[HTTPS] https://$target"
    echo "------------------------------"
    _gb-vhost-run https "$target" "$wordlist" ""
    return 0
  fi

  wordlist="$GB_DNS_WORDLIST"
  if ! getent hosts "$target" &>/dev/null; then
    echo "[-] scout -v: $target does not resolve — run: hosts $target" >&2
    return 1
  fi

  if ! command -v ffuf >/dev/null 2>&1; then
    echo "[-] scout -v: ffuf not found (domain mode requires ffuf)" >&2
    return 1
  fi

  echo "=============================="
  echo "[VHOST] domain mode (ffuf Host: FUZZ.$target)"
  echo "[*] URL: http://$target/"
  echo "[*] WORDLIST: $wordlist"
  echo "[*] THREADS: $GB_THREADS"
  echo "[*] FILTER SIZE (-fs): ${GB_VHOST_EXCLUDE_LENGTH:-0}"
  echo "=============================="

  _gb-vhost-domain-ffuf "$target" "$wordlist"
}

gb-vhost() {
  if [[ "${1:-}" == "-h" || "${1:-}" == --help ]]; then
    echo "[!] gb-vhost is deprecated — use: scout -v (alias: s -v)" >&2
    _scout-vhosts-help
    return 0
  fi
  echo "[!] gb-vhost is deprecated — use: scout -v (alias: s -v)" >&2
  _scout-vhosts "$@"
}
