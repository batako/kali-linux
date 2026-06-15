# ========================
# recon exec
# ========================

exec-run() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-run [-s] [ip] <command...>"
    echo "  alias: x (exec-run -s → xs)"
    return 0
  fi

  local ip=""
  local silence=""

  if [[ "${1:-}" == "-s" ]]; then
    silence="-s"
    shift
  fi

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: exec-run [-s] [ip] <command...>" >&2
    echo "  alias: x (exec-run -s → xs)" >&2
    return 1
  fi

  python3 "$RECON_APP" exec-run $silence "$ip" "$@"
}

x() { exec-run "$@"; }
xs() { exec-run -s "$@"; }

exec-cache() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-cache [-s] [ip] <command...>"
    echo "  alias: xc (exec-cache -s → xcs)"
    return 0
  fi

  local ip=""
  local silence=""

  if [[ "${1:-}" == "-s" ]]; then
    silence="-s"
    shift
  fi

  if [[ $# -ge 2 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"
    shift
  else
    ip="${IP:-}"
  fi

  if [[ -z "$ip" || $# -lt 1 ]]; then
    echo "usage: exec-cache [-s] [ip] <command...>" >&2
    echo "  alias: xc (exec-cache -s → xcs)" >&2
    return 1
  fi

  python3 "$RECON_APP" exec-cache $silence "$ip" "$@"
}

xc() { exec-cache "$@"; }
xcs() { exec-cache -s "$@"; }

exec-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-list [-l] [--all-case] [ip]"
    echo "  alias: el"
    return 0
  fi
  python3 "$RECON_APP" exec-list "$@"
}

exec-view() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: exec-view <exec_id> [--tail N]"
    echo "  alias: ev"
    return 0
  fi
  if [[ $# -lt 1 ]]; then
    echo "usage: exec-view <exec_id> [--tail N]" >&2
    echo "  alias: ev" >&2
    return 1
  fi
  python3 "$RECON_APP" exec-view "$@"
}

el() { exec-list "$@"; }
ev() { exec-view "$@"; }
