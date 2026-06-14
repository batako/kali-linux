# ========================
# gobuster helpers
# ========================

# vhost discovery: scout -v (s -v); dir scans use scout -d / scout -ds
GB_VHOST_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
GB_DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
GB_VHOST_MATCH_CODES="${GB_VHOST_MATCH_CODES:-200-299,301,302,307,401,403,405,421,422,500}"
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
  local json="$1" domain="$2" scheme="${3:-}"
  [[ -f "$json" ]] || {
    echo "[i] no results file"
    return 0
  }
  python3 -c "
import json, sys
path, domain, scheme = sys.argv[1], sys.argv[2], sys.argv[3]
tag = f' ({scheme})' if scheme else ''
try:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    print('[i] could not read results')
    sys.exit(0)
rows = data.get('results') or []
if not rows:
    print('[-] no vhosts found' + tag)
    sys.exit(0)
for r in rows:
    fuzz = (r.get('input') or {}).get('FUZZ', '?')
    host = f'{fuzz}.{domain}' if fuzz != '?' else domain
    print(f\"[+] {host}\tstatus={r.get('status', '?')}\tsize={r.get('length', '?')}{tag}\")
" "$json" "$domain" "$scheme"
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

_gb-vhost-hostnames-from-jsons() {
  local domain="$1"
  shift
  local json
  [[ $# -gt 0 ]] || return 0
  for json in "$@"; do
    _gb-vhost-hostnames-from-json "$json" "$domain"
  done | sort -u
}

_gb-vhost-print-merged-summary() {
  local domain="$1"
  shift
  local -a specs=("$@")
  [[ ${#specs[@]} -gt 0 ]] || {
    echo "[-] no vhosts found"
    return 0
  }
  python3 -c "
import json, sys

domain = sys.argv[1]
specs = sys.argv[2:]
merged = {}
for spec in specs:
    scheme, path = spec.split(':', 1)
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        continue
    for r in data.get('results') or []:
        fuzz = (r.get('input') or {}).get('FUZZ')
        if not fuzz:
            continue
        host = f'{fuzz}.{domain}'
        row = {
            'host': host,
            'status': r.get('status', '?'),
            'size': r.get('length', '?'),
            'scheme': scheme,
        }
        prev = merged.get(host)
        if prev is None or (scheme == 'https' and prev['scheme'] != 'https'):
            merged[host] = row
if not merged:
    print('[-] no vhosts found')
    sys.exit(0)
for host in sorted(merged):
    row = merged[host]
    print(f\"[+] {row['host']}\tstatus={row['status']}\tsize={row['size']} ({row['scheme']})\")
" "$domain" "${specs[@]}"
}

_gb-vhost-plan-schemes() {
  local override="${1:-}" ip
  local -a py_args=(vhost-schemes) schemes=()

  if (( $+functions[target-load] )); then
    target-load 2>/dev/null
  fi
  ip="${IP:-}"

  [[ -n "$override" ]] && py_args+=("--$override")
  [[ -n "$ip" ]] && py_args+=("$ip")

  if [[ -n "${RECON_APP:-}" && -f "$RECON_APP" ]]; then
    while IFS= read -r line; do
      [[ "$line" == http || "$line" == https ]] && schemes+=("$line")
    done < <(python3 "$RECON_APP" "${py_args[@]}" 2>/dev/null)
  fi

  if (( ! ${#schemes[@]} )); then
    case "$override" in
      http)  schemes=(http) ;;
      https) schemes=(https) ;;
      *)     schemes=(https http) ;;
    esac
  fi

  local s
  for s in "${schemes[@]}"; do
    echo "$s"
  done
}

_gb-vhost-scheme-plan-label() {
  local override="${1:-}" ip="${IP:-}"
  local -a schemes
  schemes=("${(@f)$(_gb-vhost-plan-schemes "$override")}")
  if [[ "$override" == both ]]; then
    echo "both (https → http)"
    return 0
  fi
  if [[ -n "$override" ]]; then
    echo "$override"
    return 0
  fi
  if (( ${#schemes[@]} == 2 )); then
    echo "auto: https → http (80+443 or unknown)"
  elif [[ "${schemes[1]}" == https ]]; then
    echo "auto: https only (443 open)"
  else
    echo "auto: http only (80 open)"
  fi
}

_gb-vhost-ffuf-filter() {
  local domain="$1" total="${2:-0}" scheme="${3:-}"
  python3 -u -c "
import re, sys

domain = sys.argv[1]
total_hint = int(sys.argv[2] or 0)
scheme = sys.argv[3]
scheme_tag = f' ({scheme})' if scheme else ''
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
    sys.stderr.write(f'[+] {host}\tstatus={status}\tsize={size}{scheme_tag}\n')
    sys.stderr.flush()
    last_drawn = -1
    show_progress(force=True)

def finish():
    ensure_header()
    clear_progress()
    if not seen_hosts:
        sys.stderr.write('[-] no vhosts found' + scheme_tag + '\n')
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
" "$domain" "$total" "$scheme"
}

_gb-vhost-register-hosts() {
  local domain="$1"
  shift
  local -a json_files=("$@")
  local f ip name json
  local -a names new_names

  (( ${#json_files[@]} )) || return 1
  (( $+functions[_hosts-register-line] )) || return 1

  while IFS= read -r name; do
    [[ -n "$name" ]] && names+=("$name")
  done < <(_gb-vhost-hostnames-from-jsons "$domain" "${json_files[@]}")
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

_gb-vhost-fetch-profile() {
  local domain="$1" scheme="$2"
  [[ -n "${RECON_APP:-}" && -f "$RECON_APP" ]] || return 1
  python3 "$RECON_APP" vhost-wildcard-profile --"$scheme" "$domain" 2>/dev/null
}

_gb-vhost-resolve-filter() {
  local domain="$1" scheme="$2"
  local profile filter_mode sizes suspicion label

  if [[ -n "${GB_VHOST_EXCLUDE_LENGTH:-}" ]]; then
    print -r -- "fs|${GB_VHOST_EXCLUDE_LENGTH}|manual|${GB_VHOST_EXCLUDE_LENGTH} (GB_VHOST_EXCLUDE_LENGTH)"
    return 0
  fi

  profile="$(_gb-vhost-fetch-profile "$domain" "$scheme")"
  [[ -n "$profile" ]] || return 1

  filter_mode="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("filter_mode","ac"))' <<< "$profile")"
  suspicion="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("suspicion","none"))' <<< "$profile")"
  sizes="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(str(x) for x in (d.get("exclude_sizes") or [])))' <<< "$profile")"

  if [[ "$filter_mode" == fs && -n "$sizes" ]]; then
    label="${suspicion} wildcard suspicion → -fs ${sizes//,/ }"
  elif [[ "$suspicion" == weak ]]; then
    label="weak wildcard suspicion → ffuf -ac (status/size match; hash/headers differ)"
  else
    label="${suspicion} → ffuf -ac (response diff)"
  fi
  print -r -- "${filter_mode}|${sizes}|${suspicion}|${label}"
}

_gb-vhost-http-assessment-note() {
  local domain="$1"
  local assessment advisory msg

  [[ -n "${RECON_APP:-}" && -f "$RECON_APP" ]] || return 0
  assessment="$(python3 "$RECON_APP" vhost-http-assessment "$domain" 2>/dev/null)"
  [[ -n "$assessment" ]] || return 0

  advisory="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("advisory") or "")' <<< "$assessment")"
  msg="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("message") or "")' <<< "$assessment")"
  [[ "$advisory" == strong_redirect_suspicion ]] || return 0

  echo "[i] http: ${msg}"
  if [[ -n "${GB_VHOST_SKIP_HTTP_REDIRECT:-}" ]]; then
    echo "[i] http: GB_VHOST_SKIP_HTTP_REDIRECT set — skipping HTTP ffuf (HTTPS pass is authoritative)"
    return 1
  fi
  return 0
}

_gb-vhost-domain-ffuf() {
  local domain="$1" wordlist="$2" scheme="$3" ts="$4"
  local filter_line filter_mode sizes suspicion fs_label size
  local base logs_dir rc wl_total
  local -a args parts

  filter_line="$(_gb-vhost-resolve-filter "$domain" "$scheme")"
  if [[ -n "$filter_line" ]]; then
    parts=("${(@s:|:)filter_line}")
    filter_mode="${parts[1]}"
    sizes="${parts[2]}"
    suspicion="${parts[3]}"
    fs_label="${parts[4]}"
  else
    filter_mode="ac"
    fs_label="probe failed → ffuf -ac (may get catch-all noise)"
  fi

  if logs_dir="$(case-logs-dir 2>/dev/null)"; then
    base="${logs_dir}/vhost_${domain//\./_}_${scheme}_${ts}"
  else
    base="${TMPDIR:-/tmp}/vhost_${domain//\./_}_${scheme}_${ts}"
    echo "[i] case not set — log under $base.*" >&2
  fi

  args=(
    ffuf
    -w "$wordlist"
    -H "Host: FUZZ.${domain}"
    -u "${scheme}://${domain}/"
    -t "$GB_THREADS"
    -o "${base}.json"
    -of json
  )
  [[ "$scheme" == https ]] && args+=(-k)

  if [[ "$filter_mode" == fs && -n "$sizes" ]]; then
    for size in ${(s:,:)sizes}; do
      [[ "$size" == <-> ]] && args+=(-fs "$size")
    done
  else
    args+=(-ac)
  fi

  if [[ -z "${GB_VHOST_NO_MC:-}" ]]; then
    args+=(-mc "$GB_VHOST_MATCH_CODES")
  fi

  wl_total="$(wc -l <"$wordlist" | tr -d '[:space:]')"

  echo "[*] log:  ${base}.log"
  echo "[*] json: ${base}.json"
  echo "[*] filter: ${fs_label}"
  echo "[*] match:  ${GB_VHOST_NO_MC:+off (GB_VHOST_NO_MC)}${GB_VHOST_NO_MC:-ffuf -mc ${GB_VHOST_MATCH_CODES} (auxiliary)}"
  echo "[*] scan: ${wl_total:-?} names × Host: FUZZ.${domain} (${scheme})"
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
    script -q -e -f -c "$cmd" /dev/null 2>&1 | _gb-vhost-ffuf-filter "$domain" "$wl_total" "$scheme"
  else
    "${run_cmd[@]}" 2>&1 | _gb-vhost-ffuf-filter "$domain" "$wl_total" "$scheme"
  fi
  rc=${pipestatus[1]:-$?}

  {
    echo "===== results ====="
    _gb-vhost-print-summary "${base}.json" "$domain" "$scheme"
  } >"${base}.log"

  print -r -- "${base}.json"
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
  echo "usage: scout -v [--http|--https|--both] [domain|ip]   (alias: s -v)"
  echo "  s -v lookup.thm           # THM: ffuf Host: FUZZ.lookup.thm (https → http)"
  echo "  s -v --https lookup.thm   # HTTPS only (ffuf -k)"
  echo "  s -v --both lookup.thm    # force both schemes (ignore nmap)"
  echo "  s -v                      # IP 直叩き gobuster (raft-small-words)"
  echo ""
  echo "  prereq (THM): hosts lookup.thm  (apex のみ。サブドメインは終了後に自動登録)"
  echo "  schemes:  default auto from nmap (443→https, 80→http, both→https then http)"
  echo "  wordlist: GB_DNS_WORDLIST (gb-set-dns で変更可)"
  echo "  filter:   3× probe (status/size/redirect/hash/headers) → -fs or -ac (GB_VHOST_EXCLUDE_LENGTH overrides)"
  echo "  match:    ffuf -mc auxiliary (default: ${GB_VHOST_MATCH_CODES}; GB_VHOST_NO_MC=1 to omit)"
  echo "  http:     always runs ffuf; redirect-only port 80 → advisory (GB_VHOST_SKIP_HTTP_REDIRECT=1 to skip)"
  echo "  logs:     cases/<room>/logs/vhost_<domain>_<scheme>_<ts>.json"
  echo "  hosts:    ヒットを cases/<room>/hosts に自動追記（http/https マージ）"
  echo ""
  echo "  見つけた vhost で dir: s -d -H www.lookup.thm"
}

_scout-vhosts() {
  local target="" wordlist="" scheme_override=""
  local -a schemes json_files merge_specs
  local scheme ts rc=0 json_path

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _scout-vhosts-help
        return 0
        ;;
      --http)
        scheme_override=http
        shift
        ;;
      --https)
        scheme_override=https
        shift
        ;;
      --both)
        scheme_override=both
        shift
        ;;
      -*)
        echo "[-] scout -v: unknown option: $1" >&2
        return 1
        ;;
      *)
        if [[ -n "$target" ]]; then
          echo "[-] scout -v: unexpected argument: $1" >&2
          return 1
        fi
        target="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$target" ]]; then
    target="$(gb-resolve-target)" || return 1
  fi

  if _gb-is-ip "$target"; then
    wordlist="$GB_VHOST_WORDLIST"
    schemes=("${(@f)$(_gb-vhost-plan-schemes "$scheme_override")}")
    echo "=============================="
    echo "[VHOST] IP mode"
    echo "[*] TARGET: $target"
    echo "[*] SCHEMES: $(_gb-vhost-scheme-plan-label "$scheme_override")"
    echo "[*] WORDLIST: $wordlist"
    echo "[*] THREADS: $GB_THREADS"
    echo "=============================="

    for scheme in "${schemes[@]}"; do
      echo "[${(U)scheme}] ${scheme}://${target}"
      echo "------------------------------"
      _gb-vhost-run "$scheme" "$target" "$wordlist" ""
      echo "------------------------------"
    done
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

  schemes=("${(@f)$(_gb-vhost-plan-schemes "$scheme_override")}")
  ts="$(date +%Y%m%d-%H%M%S)"

  echo "=============================="
  echo "[VHOST] domain mode (ffuf Host: FUZZ.$target)"
  echo "[*] SCHEMES: $(_gb-vhost-scheme-plan-label "$scheme_override")"
  echo "[*] WORDLIST: $wordlist"
  echo "[*] THREADS: $GB_THREADS"
  echo "[*] FILTER: 3× probe → -fs (strong) or -ac (weak/none); GB_VHOST_EXCLUDE_LENGTH overrides"
  echo "=============================="

  merge_specs=()
  json_files=()
  for scheme in "${schemes[@]}"; do
    [[ "$scheme" == http || "$scheme" == https ]] || continue
    if [[ "$scheme" == http ]]; then
      echo "[HTTP] http://${target}/"
      echo "------------------------------"
      if ! _gb-vhost-http-assessment-note "$target"; then
        echo "------------------------------"
        continue
      fi
    else
      echo "[${(U)scheme}] ${scheme}://${target}/"
      echo "------------------------------"
    fi
    json_path="$(_gb-vhost-domain-ffuf "$target" "$wordlist" "$scheme" "$ts")" || rc=$?
    if [[ -n "$json_path" && -f "$json_path" ]]; then
      json_files+=("$json_path")
      merge_specs+=("${scheme}:${json_path}")
    fi
    echo "------------------------------"
  done

  echo "===== results (merged) ====="
  if (( ${#merge_specs[@]} )); then
    _gb-vhost-print-merged-summary "$target" "${merge_specs[@]}"
  else
    echo "[-] no vhosts found"
  fi

  if (( ${#json_files[@]} )) && _gb-vhost-hostnames-from-jsons "$target" "${json_files[@]}" | grep -q .; then
    echo "===== hosts ====="
    _gb-vhost-register-hosts "$target" "${json_files[@]}"
  fi

  return $rc
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
