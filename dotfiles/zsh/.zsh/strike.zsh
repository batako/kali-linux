# ========================
# strike — run pending auth tasks (attack force)
# ========================

_strike-usage() {
  echo "usage: strike [options] [ip]"
  echo "  run pending auth-quick tasks (scout phase 2.5 enqueues; strike executes)"
  echo ""
  echo "options:"
  echo "  -l, --list       list tasks for target"
  echo "  --all-case       with -l: all tasks in current case"
  echo "  -n, --dry-run    show commands without running"
  echo "  --force          re-run completed auth tasks"
  echo "  --type PREFIX    task_type prefix (default: auth-)"
  echo ""
  echo "examples:"
  echo "  strike              # run pending tasks for \$IP"
  echo "  strike -l           # list tasks"
  echo "  strike -l --all-case"
  echo "  strike --force      # redo auth-quick checks"
  echo "  s --plan            # enqueue only (no hydra)"
  echo ""
  echo "  on hit: creds → cl (creds-import-hydra)"
}

strike() {
  local dry="" force="" list="" all_case="" type_prefix="" ip=""
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--dry-run)
        dry="-n"
        shift
        ;;
      -l|--list)
        list="-l"
        shift
        ;;
      --all-case)
        all_case="--all-case"
        shift
        ;;
      --force)
        force="--force"
        shift
        ;;
      --type)
        [[ $# -ge 2 ]] || { _strike-usage >&2; return 1; }
        type_prefix="--type $2"
        shift 2
        ;;
      -h|--help)
        _strike-usage
        return 0
        ;;
      -*)
        _strike-usage >&2
        return 1
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  if (( ${#args[@]} )); then
    ip="${args[1]:-${args[0]}}"
  fi
  if [[ -z "$ip" && -z "$all_case" ]]; then
    ip="$(target-current 2>/dev/null)" || true
  fi
  if [[ -z "$list" && -z "$ip" ]]; then
    _strike-usage >&2
    return 1
  fi

  python3 "$RECON_APP" strike $list $all_case $dry $force $type_prefix ${ip:+"$ip"}
}
