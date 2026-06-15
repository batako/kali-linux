# ========================
# recon artifacts
# ========================

artifact-add() {
  local ip=""
  local kind=""
  local value=""
  local key=""

  if [[ $# -ge 4 && "$1" =~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
    ip="$1"; kind="$2"; value="$3"; key="${4:-}"
  else
    ip="${IP:-}"
    kind="$1"; value="$2"; key="${3:-}"
  fi

  if [[ -z "$ip" || -z "$kind" || -z "$value" ]]; then
    echo "usage: artifact-add [ip] <kind> <value> [key]"
    return 1
  fi

  python3 "$RECON_APP" artifact-add "$ip" "$kind" "$value" "$key"
}

artifact-list() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: artifact-list [-l] [ip]"
    echo "  alias: al"
    return 0
  fi
  python3 "$RECON_APP" artifact-list "$@"
}

al() { artifact-list "$@"; }

artifact-del() {
  if [[ $# -lt 1 ]]; then
    echo "usage: artifact-del <artifact_id>"
    return 1
  fi
  python3 "$RECON_APP" artifact-del "$1"
}
