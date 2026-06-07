# ========================
# target attach (ta / ti)
# ========================
# oh-my-zsh tmux plugin defines ta() as "tmux attach -t". Load this file
# last (99-*) and replace it.

unfunction ta 2>/dev/null

# Set or reload $IP; infers case from $PWD when under cases/<name>/
# usage: ta <ip> [--new|--pick]  |  ta  |  ti … (alias)
_target-attach() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: ta <ip> [--new|--pick]  |  ta   (same: ti)"
    echo "  set \$IP (+ save to cases/<case>/target)"
    echo "  IP change: prompt to inherit from previous target (default Y)"
    echo "  --new   pivot / no inherit    --pick   choose load source"
    echo "  no args: reload from target file"
    echo "  overrides oh-my-zsh tmux plugin ta (tmux attach)"
    return 0
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  if [[ $# -ge 1 ]]; then
    local new_ip="" mode="inherit" args=() assume_yes=0
    local arg
    for arg in "$@"; do
      case "$arg" in
        --new) mode=new ;;
        --pick) mode=pick ;;
        -y|--yes) assume_yes=1 ;;
        -h|--help)
          _target-attach --help
          return 0
          ;;
        --*)
          echo "[-] unknown option: $arg" >&2
          echo "    use: ta <ip> [--new|--pick]" >&2
          return 1
          ;;
        *)
          if [[ -z "$new_ip" ]]; then
            new_ip="$arg"
          else
            echo "[-] unexpected argument: $arg" >&2
            return 1
          fi
          ;;
      esac
    done

    if [[ -z "$new_ip" ]]; then
      echo "usage: ta <ip> [--new|--pick]" >&2
      return 1
    fi

    if [[ ! "$new_ip" =~ $(_recon-ip-re) ]]; then
      echo "usage: ta <ipv4> [--new|--pick]" >&2
      return 1
    fi

    if [[ -n "${CASE:-}" ]]; then
      local previous_ip="" ta_args=(case-target-set "$new_ip" --mode "$mode")
      local f
      f="$(_case-target-file 2>/dev/null)"
      if [[ -n "$f" && -f "$f" ]]; then
        previous_ip="$(head -1 "$f" | tr -d '[:space:]')"
        [[ "$previous_ip" =~ $(_recon-ip-re) ]] && ta_args+=(--previous "$previous_ip")
      fi
      (( assume_yes )) && ta_args+=(-y)
      python3 "$RECON_APP" "${ta_args[@]}" || return $?
      export IP="$new_ip"
      return 0
    fi

    target-set "$new_ip"
    return $?
  fi

  if target-load; then
    echo "[+] target: $IP  ($CASE_HOME/target)"
    return 0
  fi

  echo "usage: ta <ip>  |  ta  (cs <case> or cwd under cases/<case>/)" >&2
  return 1
}

ta() { _target-attach "$@" }
ti() { _target-attach "$@" }
