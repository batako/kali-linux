# ========================
# Hash list (hlist / hxa / hxr)
# ========================

hash-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: hash-list [--json] [ip]" "使い方: hash-list [--json] [ip]"
    _toolkit-echo "  alias: hlist" "  alias: hlist"
    _toolkit-echo "  columns: user<TAB>stored<TAB>state" "  列: user<TAB>stored<TAB>state"
    return 0
  fi
  if [[ -n "${1:-}" ]]; then
    python3 "$RECON_APP" hash-list "$@"
    return $?
  fi
  if [[ -z "${IP:-}" ]]; then
    echo "usage: hash-list [--json] [ip]" >&2
    echo "  alias: hlist" >&2
    return 1
  fi
  python3 "$RECON_APP" hash-list
}

_hash-add() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: hash-add [ip] <user hash-line>" "使い方: hash-add [ip] <user hash-line>"
    _toolkit-echo "  alias: hxa" "  alias: hxa"
    _toolkit-echo "  e.g. hxa postgres md532e12f215ba27cb750c9e093ce4b5127" "  例: hxa postgres md532e12f215ba27cb750c9e093ce4b5127"
    return 0
  fi

  local ip=""
  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: hash-add [ip] <user hash-line>" >&2
    echo "  alias: hxa" >&2
    return 1
  fi

  python3 "$RECON_APP" hash-add "$ip" "$@"
}

_hash-rm() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    _toolkit-echo "usage: hash-rm [ip] [username]" "使い方: hash-rm [ip] [username]"
    _toolkit-echo "  alias: hxr" "  alias: hxr"
    _toolkit-echo "  no username → delete all hashes for ip" "  username 省略時はその IP のハッシュを全削除"
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
    echo "usage: hash-rm [ip] [username]" >&2
    echo "  alias: hxr" >&2
    return 1
  fi

  if [[ -n "$user" ]]; then
    python3 "$RECON_APP" hash-rm "$ip" "$user"
  else
    python3 "$RECON_APP" hash-rm "$ip"
  fi
}

unfunction hash-add hash-rm 2>/dev/null
setopt aliases
alias hash-add='noglob _hash-add'
alias hxa='noglob _hash-add'
alias hash-rm='noglob _hash-rm'
alias hxr='noglob _hash-rm'
alias hlist=hash-list
