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

_hosts-trim-line() {
  local line="$1"
  line="${line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  print -r -- "$line"
}

_hosts-filter-case-file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    _hosts-valid-line "$line" && _hosts-trim-line "$line"
  done <"$f"
}

_hosts-remove-managed-block() {
  local file="$1"
  [[ -f "$file" ]] || { echo "$file"; return 0; }
  # Prefix match: BEGIN may include case label; END may be missing (legacy stacks).
  "$(_recon-bin awk)" -v begin="$RECON_HOSTS_BEGIN" -v end="$RECON_HOSTS_END" '
    $0 ~ "^" begin { skip=1; next }
    $0 ~ "^" end { skip=0; next }
    skip==0 { print }
  ' "$file"
}

_hosts-print-sudo-plan() {
  local kind="$1" case_file="${2:-}"
  echo "[*] hosts: updating /etc/hosts — sudo password may be required"
  case "$kind" in
    apply)
      if [[ -f "$case_file" ]] && [[ -s "$case_file" ]]; then
        echo "    action: apply recon block (${CASE:-case})"
        echo "    source: $case_file"
        _hosts-filter-case-file "$case_file" | while IFS= read -r line; do
          echo "      $line"
        done
      else
        echo "    action: clear recon block (no entries in case hosts)"
      fi
      ;;
    off)
      echo "    action: remove recon block from /etc/hosts"
      ;;
  esac
}

_recon-hosts-apply() {
  local case_file etc tmp label
  case_file="$(_hosts-case-file)" || return 0
  etc="/etc/hosts"
  tmp="$("$(_recon-bin mktemp)" "${TMPDIR:-/tmp}/recon-hosts.XXXXXX")"

  _hosts-remove-managed-block "$etc" >"$tmp"

  if [[ -f "$case_file" ]] && [[ -s "$case_file" ]]; then
    label="${CASE:-case}"
    print -r -- "$RECON_HOSTS_BEGIN $label" >>"$tmp"
    _hosts-filter-case-file "$case_file" >>"$tmp"
    print -r -- "$RECON_HOSTS_END" >>"$tmp"
  fi

  if "$(_recon-bin cmp)" -s "$tmp" "$etc" 2>/dev/null; then
    "$(_recon-bin rm)" -f "$tmp"
    return 0
  fi

  _hosts-print-sudo-plan apply "$case_file"
  if ! "$(_recon-bin sudo)" "$(_recon-bin cp)" "$tmp" "$etc" 2>/dev/null; then
    "$(_recon-bin rm)" -f "$tmp"
    echo "[-] failed to update $etc (sudo?)" >&2
    return 1
  fi
  "$(_recon-bin rm)" -f "$tmp"

  if [[ -f "$case_file" ]] && [[ -s "$case_file" ]]; then
    echo "[+] hosts: applied $case_file"
    _hosts-filter-case-file "$case_file" | while IFS= read -r line; do
      echo "    $line"
    done
  else
    echo "[+] hosts: cleared recon block"
  fi
}

_recon-hosts-off() {
  local etc tmp
  etc="/etc/hosts"
  tmp="$("$(_recon-bin mktemp)" "${TMPDIR:-/tmp}/recon-hosts.XXXXXX")"
  _hosts-remove-managed-block "$etc" >"$tmp"
  if "$(_recon-bin cmp)" -s "$tmp" "$etc" 2>/dev/null; then
    "$(_recon-bin rm)" -f "$tmp"
    return 0
  fi
  _hosts-print-sudo-plan off
  if ! "$(_recon-bin sudo)" "$(_recon-bin cp)" "$tmp" "$etc" 2>/dev/null; then
    "$(_recon-bin rm)" -f "$tmp"
    echo "[-] failed to update $etc" >&2
    return 1
  fi
  "$(_recon-bin rm)" -f "$tmp"
  echo "[+] hosts: recon block removed from $etc"
}

_hosts-default-ip() {
  if [[ -n "${IP:-}" && "$IP" =~ $(_recon-ip-re) ]]; then
    echo "$IP"
    return 0
  fi
  if (( $+functions[target-load] )); then
    target-load 2>/dev/null
    if [[ -n "${IP:-}" && "$IP" =~ $(_recon-ip-re) ]]; then
      echo "$IP"
      return 0
    fi
  fi
  return 1
}

_hosts-remap-ip() {
  local from_ip="$1" to_ip="$2"
  local f line ip rest trimmed
  local -a out=()
  local changed=false count=0

  [[ "$from_ip" =~ $(_recon-ip-re) && "$to_ip" =~ $(_recon-ip-re) ]] || return 0
  [[ "$from_ip" == "$to_ip" ]] && return 0

  f="$(_hosts-case-file)" || return 0
  [[ -f "$f" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    if _hosts-valid-line "$line"; then
      trimmed="$(_hosts-trim-line "$line")"
      ip="${trimmed%% *}"
      if [[ "$ip" == "$from_ip" ]]; then
        rest="${trimmed#* }"
        line="$to_ip $rest"
        changed=true
        (( count++ ))
      else
        line="$trimmed"
      fi
    fi
    out+=("$line")
  done <"$f"

  if ! $changed; then
    return 0
  fi

  {
    for line in "${out[@]}"; do
      print -r -- "$line"
    done
  } >"$f"

  if (( count == 1 )); then
    echo "[~] hosts: ${from_ip} → ${to_ip} (1 entry)"
  else
    echo "[~] hosts: ${from_ip} → ${to_ip} (${count} entries)"
  fi
  _recon-hosts-apply
}

_hosts-usage() {
  if _toolkit-lang-ja; then
    cat <<'EOF'
使い方: hosts [-h] [<hostname> [aliases...]]
       hosts [<ip>] <hostname> [aliases...]
       hosts -r|--replace [<ip>] <hostname> [aliases...]
       hosts --apply | --off | -e|--edit

  （引数なし）             case ファイルと /etc/hosts の recon ブロックを表示
  <host> [names]         cases/<room>/hosts に upsert（同名は置換）
  <ip> <host> [names]    明示 IP で追記
  -r, --replace          case の hosts ファイルを 1 行で置換して適用
  --apply                cases/<room>/hosts を /etc/hosts に反映
  --off                  /etc/hosts の recon ブロックだけ削除
  -e, --edit             cases/<room>/hosts を編集してから適用

  case-set で部屋を切り替えると、cases/<room>/hosts があれば自動適用
  target-set <new-ip> では、前の target IP の行を新 IP へ書き換える

例:
  hosts smag.thm                    # \$IP を使用
  hosts 10.10.238.190 mafialive.thm
  hosts mafialive.thm www.mafialive.thm
  hosts --off
EOF
  else
    cat <<'EOF'
usage: hosts [-h] [<hostname> [aliases...]]
       hosts [<ip>] <hostname> [aliases...]
       hosts -r|--replace [<ip>] <hostname> [aliases...]
       hosts --apply | --off | -e|--edit

  (no args)              show case file + /etc/hosts recon block
  <host> [names]         upsert cases/<room>/hosts (same name replaces line)
  <ip> <host> [names]    append with explicit IP
  -r, --replace          replace case hosts file with one line, then apply
  --apply                apply cases/<room>/hosts to /etc/hosts
  --off                  remove recon block from /etc/hosts only
  -e, --edit             edit cases/<room>/hosts, then apply

  case-set switches rooms → hosts auto-applies when cases/<room>/hosts exists
  target-set <new-ip>      rewrites lines with the previous target IP to the new IP

examples:
  hosts smag.thm                    # uses $IP
  hosts 10.10.238.190 mafialive.thm
  hosts mafialive.thm www.mafialive.thm
  hosts --off
EOF
  fi
}

_hosts-show() {
  local f etc line
  f="$(_hosts-case-file 2>/dev/null)"
  echo "case file: ${f:-"(no case)"}"
  if [[ -n "$f" && -f "$f" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      echo "  $line"
    done <"$f"
  else
    echo "  (none)"
  fi
  echo ""
  echo "/etc/hosts (recon block):"
  etc="/etc/hosts"
  if [[ -f "$etc" ]] && "$(_recon-bin grep)" -qF "$RECON_HOSTS_BEGIN" "$etc" 2>/dev/null; then
    "$(_recon-bin awk)" -v begin="$RECON_HOSTS_BEGIN" -v end="$RECON_HOSTS_END" '
      $0 ~ begin { show=1; next }
      $0 ~ end { show=0; next }
      show==1 { print "  " $0 }
    ' "$etc"
  else
    echo "  (none)"
  fi
}

_hosts-line-has-name() {
  local line="$1" name="$2"
  local -a fields
  line="${line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  fields=(${=line})
  (( ${#fields[@]} >= 2 )) || return 1
  fields=("${fields[@]:1}")
  local f
  for f in "${fields[@]}"; do
    [[ "$f" == "$name" ]] && return 0
  done
  return 1
}

_hosts-resolve-register-args() {
  local ip host
  local -a rest
  [[ $# -ge 1 ]] || return 1
  if [[ "$1" =~ $(_recon-ip-re) ]]; then
    [[ $# -ge 2 ]] || return 1
    ip="$1"
    host="$2"
    shift 2
    rest=("$@")
  else
    ip="$(_hosts-default-ip)" || return 2
    host="$1"
    shift
    rest=("$@")
  fi
  REPLY=("$ip" "$host" "${rest[@]}")
  return 0
}

_hosts-register-line() {
  local mode="$1"
  shift
  local ip host line
  local -a rest
  local f

  _hosts-resolve-register-args "$@"
  local rc=$?
  if (( rc != 0 )); then
    if (( rc == 2 )); then
      echo "[-] no target IP — target-set <ip> or case-set <room> first" >&2
    else
      _hosts-usage >&2
    fi
    return 1
  fi
  ip="$REPLY[1]"
  host="$REPLY[2]"
  if (( ${#REPLY[@]} > 2 )); then
    rest=("${(@)REPLY[3,-1]}")
  else
    rest=()
  fi
  [[ "$ip" =~ $(_recon-ip-re) ]] || {
    echo "[-] invalid ip: $ip" >&2
    return 1
  }

  f="$(_hosts-case-file)" || {
    echo "[-] case not set — case-set <room> first" >&2
    return 1
  }

  if (( ${#rest[@]} )); then
    line="$ip $host ${rest[*]}"
  else
    line="$ip $host"
  fi

  if [[ "$mode" == replace ]]; then
    print -r -- "$line" >"$f"
  else
    "$(_recon-bin touch)" "$f"
    if "$(_recon-bin grep)" -qFx "$line" "$f" 2>/dev/null; then
      echo "[=] hosts: already registered — $line"
      _recon-hosts-apply
      return 0
    fi

    local -a names=("$host" "${rest[@]}") out=()
    local existing replaced=false l skip name

    while IFS= read -r l || [[ -n "$l" ]]; do
      skip=false
      if _hosts-valid-line "$l"; then
        for name in "${names[@]}"; do
          if _hosts-line-has-name "$l" "$name"; then
            skip=true
            replaced=true
            break
          fi
        done
      fi
      if $skip; then
        continue
      fi
      out+=("$l")
    done <"$f"

    out+=("$line")

    {
      for l in "${out[@]}"; do
        print -r -- "$l"
      done
    } >"$f"

    if $replaced; then
      echo "[~] hosts: updated — $line"
    fi
  fi
  _recon-hosts-apply
}

_hosts-editor() {
  local ed="${EDITOR:-vi}"
  if [[ "$ed" == */* ]]; then
    print -r -- "$ed"
  else
    _recon-bin "$ed"
  fi
}

_hosts-edit() {
  local ed path
  ed="$(_hosts-editor)"
  path="$(_hosts-case-file)" || {
    echo "[-] case not set — case-set <room> first" >&2
    return 1
  }
  "$(_recon-bin touch)" "$path"
  "$ed" "$path"
  _recon-hosts-apply
}

hosts() {
  local action="" mode="append"

  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _hosts-usage
    return 0
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -a|--add)
        action=write
        mode=append
        shift
        ;;
      -r|--replace)
        action=write
        mode=replace
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
        echo "    use: hosts <hostname>  or  hosts -h" >&2
        return 1
      }
      _hosts-show
      ;;
    write)
      _hosts-register-line "$mode" "$@"
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
