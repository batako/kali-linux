# ========================
# /etc/hosts per case (THM vhosts)
# ========================
#
# cases/<room>/hosts  →  managed block in /etc/hosts on case-set / hosts --apply

RECON_HOSTS_BEGIN='# BEGIN recon-hosts'
RECON_HOSTS_END='# END recon-hosts'

_hosts-case-file() {
  [[ -n "${CASE_HOME:-}" ]] && echo "$CASE_HOME/hosts"
}

_hosts-valid-line() {
  local line="$1"
  line="${line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] && return 1
  local ip="${line%% *}"
  [[ "$ip" =~ $(_recon-ip-re) ]] || return 1
  [[ "$line" == *" "* ]] || return 1
  return 0
}

_hosts-filter-case-file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    _hosts-valid-line "$line" && print -r -- "${line%%#*}" | sed 's/[[:space:]]*$//'
  done <"$f"
}

_hosts-remove-managed-block() {
  local file="$1"
  [[ -f "$file" ]] || { echo "$file"; return 0; }
  awk -v begin="$RECON_HOSTS_BEGIN" -v end="$RECON_HOSTS_END" '
    $0 == begin { skip=1; next }
    $0 == end { skip=0; next }
  skip==0 { print }
  ' "$file"
}

_recon-hosts-apply() {
  local case_file etc tmp label
  case_file="$(_hosts-case-file)" || return 0
  etc="/etc/hosts"
  tmp="$(mktemp "${TMPDIR:-/tmp}/recon-hosts.XXXXXX")"
  trap 'rm -f "$tmp"' RETURN

  _hosts-remove-managed-block "$etc" >"$tmp"

  if [[ -f "$case_file" ]] && [[ -s "$case_file" ]]; then
    label="${CASE:-case}"
    print -r -- "$RECON_HOSTS_BEGIN $label" >>"$tmp"
    _hosts-filter-case-file "$case_file" >>"$tmp"
    print -r -- "$RECON_HOSTS_END" >>"$tmp"
  fi

  if ! sudo cp "$tmp" "$etc" 2>/dev/null; then
    echo "[-] failed to update $etc (sudo?)" >&2
    return 1
  fi

  if [[ -f "$case_file" ]] && [[ -s "$case_file" ]]; then
    echo "[+] hosts: applied $case_file"
    _hosts-filter-case-file "$case_file" | sed 's/^/    /'
  else
    echo "[+] hosts: cleared recon block"
  fi
}

_recon-hosts-off() {
  local etc tmp
  etc="/etc/hosts"
  tmp="$(mktemp "${TMPDIR:-/tmp}/recon-hosts.XXXXXX")"
  trap 'rm -f "$tmp"' RETURN
  _hosts-remove-managed-block "$etc" >"$tmp"
  sudo cp "$tmp" "$etc" 2>/dev/null || {
    echo "[-] failed to update $etc" >&2
    return 1
  }
  echo "[+] hosts: recon block removed from $etc"
}

_hosts-usage() {
  echo "usage: hosts [-h] [<ip> <hostname> [aliases...]]"
  echo "       hosts -a|--add <ip> <hostname> [aliases...]"
  echo "       hosts --apply | --off | -e|--edit"
  echo
  echo "  (no args)              show case file + /etc/hosts recon block"
  echo "  <ip> <host> [names]    write cases/<room>/hosts (replace) and apply"
  echo "  -a, --add              append a line, then apply"
  echo "  --apply                apply cases/<room>/hosts to /etc/hosts"
  echo "  --off                  remove recon block from /etc/hosts only"
  echo "  -e, --edit             edit cases/<room>/hosts, then apply"
  echo
  echo "  case-set switches rooms → hosts auto-applies when cases/<room>/hosts exists"
  echo
  echo "examples:"
  echo "  hosts 10.10.238.190 mafialive.thm"
  echo "  hosts -a 10.10.238.190 www.mafialive.thm"
  echo "  hosts --off"
}

_hosts-show() {
  local f etc
  f="$(_hosts-case-file 2>/dev/null)"
  echo "case file: ${f:-"(no case)"}"
  if [[ -n "$f" && -f "$f" ]]; then
    sed 's/^/  /' "$f"
  else
    echo "  (none)"
  fi
  echo ""
  echo "/etc/hosts (recon block):"
  etc="/etc/hosts"
  if [[ -f "$etc" ]] && grep -qF "$RECON_HOSTS_BEGIN" "$etc" 2>/dev/null; then
    awk -v begin="$RECON_HOSTS_BEGIN" -v end="$RECON_HOSTS_END" '
      $0 ~ begin { show=1; next }
      $0 ~ end { show=0; next }
      show==1 { print "  " $0 }
    ' "$etc"
  else
    echo "  (none)"
  fi
}

_hosts-write-line() {
  local append="$1"
  shift
  local ip host
  local -a rest
  [[ $# -ge 2 ]] || {
    _hosts-usage >&2
    return 1
  }
  ip="$1"
  host="$2"
  shift 2
  rest=("$@")
  [[ "$ip" =~ $(_recon-ip-re) ]] || {
    echo "[-] invalid ip: $ip" >&2
    return 1
  }
  local f
  f="$(_hosts-case-file)" || {
    echo "[-] case not set — case-set <room> first" >&2
    return 1
  }
  if [[ "$append" == 1 ]]; then
    print -r -- "$ip $host ${rest[*]}" >>"$f"
  else
    print -r -- "$ip $host ${rest[*]}" >"$f"
  fi
  _recon-hosts-apply
}

_hosts-edit() {
  local ed="${EDITOR:-vi}"
  local path
  path="$(_hosts-case-file)" || {
    echo "[-] case not set — case-set <room> first" >&2
    return 1
  }
  touch "$path"
  "$ed" "$path"
  _recon-hosts-apply
}

hosts() {
  local action="" append=0

  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _hosts-usage
    return 0
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -a|--add)
        action=write
        append=1
        shift
        ;;
      --apply)
        action=apply
        shift
        ;;
      --off)
        action=off
        shift
        ;;
      -e|--edit)
        action=edit
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "[-] unknown option: $1  (try: hosts -h)" >&2
        return 1
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ -z "$action" ]]; then
    if [[ $# -eq 0 ]]; then
      action=show
    else
      action=write
    fi
  fi

  case "$action" in
    show)
      [[ $# -eq 0 ]] || {
        echo "[-] unexpected arguments: $*" >&2
        echo "    use: hosts <ip> <hostname>  or  hosts -h" >&2
        return 1
      }
      _hosts-show
      ;;
    write)
      _hosts-write-line "$append" "$@"
      ;;
    apply)
      [[ $# -eq 0 ]] || {
        echo "[-] hosts --apply takes no arguments" >&2
        return 1
      }
      [[ -n "${CASE_HOME:-}" ]] || {
        echo "[-] case not set — case-set <room> first" >&2
        return 1
      }
      _recon-hosts-apply
      ;;
    off)
      [[ $# -eq 0 ]] || {
        echo "[-] hosts --off takes no arguments" >&2
        return 1
      }
      _recon-hosts-off
      ;;
    edit)
      [[ $# -eq 0 ]] || {
        echo "[-] hosts --edit takes no arguments" >&2
        return 1
      }
      _hosts-edit
      ;;
    *)
      _hosts-usage >&2
      return 1
      ;;
  esac
}
