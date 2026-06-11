# ========================
# Hash list (hlist / hxa / hxr)
# ========================

hash-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: hash-list [--json] [ip]"
    echo "  alias: hlist"
    echo "  columns: user<TAB>stored<TAB>state"
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
    echo "usage: hash-add [ip] <user hash-line>"
    echo "  alias: hxa"
    echo "  e.g. hxa postgres md532e12f215ba27cb750c9e093ce4b5127"
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
    echo "usage: hash-rm [ip] [username]"
    echo "  alias: hxr"
    echo "  no username → delete all hashes for ip"
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
