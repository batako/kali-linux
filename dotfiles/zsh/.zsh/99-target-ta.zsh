# ========================
# target attach (ta / ti)
# ========================
# oh-my-zsh tmux plugin defines ta() as "tmux attach -t". Load this file
# last (99-*) and replace it.

unfunction ta 2>/dev/null

# Set or reload $IP; infers case from $PWD when under cases/<name>/
# usage: ta <ip>  |  ta  |  ti … (alias)
_target-attach() {
  if [[ $# -ge 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    echo "usage: ta <ip>  |  ta   (same: ti)"
    echo "  set \$IP (+ save to cases/<case>/target)"
    echo "  no args: reload from target file"
    echo "  overrides oh-my-zsh tmux plugin ta (tmux attach)"
    return 0
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  if [[ $# -ge 1 ]]; then
    target-set "$1"
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
