# ========================
# recon creds
# ========================

_creds-add() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: creds-add [-c comment] [ip] <username> [<password>]" "使い方: creds-add [-c コメント] [ip] <ユーザー名> [<パスワード>]"
    _toolkit-echo "  alias: ca" "  alias: ca"
    _toolkit-echo "  password omitted → prompt (paste ok)" "  パスワード省略時はプロンプト入力（貼り付け可）"
    _toolkit-echo "  -c comment   usage hint shown in creds-list (e.g. SSH, HTTP Basic, postgres)" "  -c コメント  creds-list に用途ヒントを表示（例: SSH, HTTP Basic, postgres）"
    _toolkit-echo "  -c may appear before or after username/password" "  -c はユーザー名/パスワードの前後どちらでも指定可"
    _toolkit-echo "examples:" "例:"
    _toolkit-echo "  creds-add vigilante              # prompt for password" "  creds-add vigilante              # パスワードを対話入力"
    _toolkit-echo "  creds-add vigilante -            # password from stdin / pipe" "  creds-add vigilante -            # stdin / pipe からパスワード入力"
    _toolkit-echo "  creds-add vigilante '!#th3h00d'  # inline (quote when pass has # or !)" "  creds-add vigilante '!#th3h00d'  # 直接指定（# や ! を含むならクォート）"
    _toolkit-echo "  creds-add -c 'HTTP Basic' barry secret" "  creds-add -c 'HTTP Basic' barry secret"
    _toolkit-echo "  creds-add alison 'p4ss' -c postgres" "  creds-add alison 'p4ss' -c postgres"
    return 0
  fi

  local ip=""
  local user=""
  local pass=""
  local comment=""
  local from_args=false
  local -a args=("$@")
  local -a pos=()
  local i arg

  for (( i=1; i<=${#args[@]}; i++ )); do
    arg="${args[i]}"
    case "$arg" in
      -c|--comment)
        (( i++ ))
        if (( i > ${#args[@]} )); then
          echo "[-] creds-add: -c requires a value" >&2
          return 1
        fi
        comment="${args[i]}"
        ;;
      -h|--help)
        _creds-add -h
        return 0
        ;;
      -*)
        echo "[-] creds-add: unknown option: $arg" >&2
        return 1
        ;;
      *)
        pos+=("$arg")
        ;;
    esac
  done

  if [[ ${#pos[@]} -ge 3 && "${pos[1]}" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="${pos[1]}"
    user="${pos[2]}"
    pos=(${pos[3,-1]})
  elif (( ${#pos[@]} >= 1 )); then
    ip="${IP:-}"
    user="${pos[1]}"
    pos=(${pos[2,-1]})
  else
    echo "usage: creds-add [ip] <username> [<password>]" >&2
    echo "  alias: ca" >&2
    return 1
  fi

  if [[ ${#pos[@]} -eq 1 && "${pos[1]}" == - ]]; then
    pass="$(cat)"
    pass="${pass//$'\n'/}"
  elif (( ${#pos[@]} >= 1 )); then
    pass="${(j: :)pos}"
    from_args=true
  elif [[ -t 0 ]]; then
    read -r "pass?password for ${user}@${ip} (paste ok): "
  else
    pass="$(cat)"
    pass="${pass//$'\n'/}"
  fi

  if [[ -z "$ip" ]]; then
    echo "[-] no target ip — target-set <ip> first" >&2
    return 1
  fi
  if [[ -z "$user" || -z "$pass" ]]; then
    echo "[-] empty username or password" >&2
    return 1
  fi
  if $from_args && [[ "$pass" == "!" ]]; then
    echo "[-] password looks truncated — # starts a shell comment without quotes" >&2
    echo "      creds-add ${user}              # prompt instead" >&2
    echo "      creds-add ${user} '!#th3h00d'" >&2
    return 1
  fi

  if [[ -n "$comment" ]]; then
    python3 "$RECON_APP" creds-add "$ip" "$user" "$pass" --comment "$comment"
  else
    python3 "$RECON_APP" creds-add "$ip" "$user" "$pass"
  fi
}

unfunction ca creds-add creds-rm cr ts 2>/dev/null
setopt aliases
alias creds-add='noglob _creds-add'
alias ca='noglob _creds-add'

creds-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: creds-list [ip]" "使い方: creds-list [ip]"
    _toolkit-echo "  alias: cl" "  alias: cl"
    _toolkit-echo "  columns: user<TAB>pass<TAB>comment  (case scope: ip<TAB>user<TAB>pass<TAB>comment)" "  列: user<TAB>pass<TAB>comment  （case 範囲では ip<TAB>user<TAB>pass<TAB>comment）"
    _toolkit-echo "  or: case-set <room> first (load_from + current IP)" "  または先に case-set <room>（load_from + 現在 IP 範囲）"
    return 0
  fi
  if [[ -n "${1:-}" ]]; then
    python3 "$RECON_APP" creds-list "$1"
    return $?
  fi
  if [[ -z "${CASE:-}" && -z "${IP:-}" ]]; then
    echo "usage: creds-list [ip]" >&2
    echo "  alias: cl" >&2
    echo "  or: case-set <room> first" >&2
    return 1
  fi
  python3 "$RECON_APP" creds-list
}

_creds-rm() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: creds-rm [ip] [username]" "使い方: creds-rm [ip] [username]"
    _toolkit-echo "  alias: cr" "  alias: cr"
    _toolkit-echo "  no username → delete all creds for ip" "  username 省略時はその IP の認証情報を全削除"
    return 0
  fi

  local ip="" user=""

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    user="${2:-}"
  elif [[ $# -ge 1 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
  elif [[ $# -ge 1 ]]; then
    ip="${IP:-}"
    user="$1"
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" ]]; then
    echo "usage: creds-rm [ip] [username]" >&2
    echo "  alias: cr" >&2
    return 1
  fi

  if [[ -n "$user" ]]; then
    python3 "$RECON_APP" creds-rm "$ip" "$user"
  else
    python3 "$RECON_APP" creds-rm "$ip"
  fi
}

alias creds-rm='noglob _creds-rm'
alias cr='noglob _creds-rm'
cl() { creds-list "$@"; }
