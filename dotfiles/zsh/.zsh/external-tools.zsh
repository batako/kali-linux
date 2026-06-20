# ========================
# external tools
# ========================

export ENHANCD_DIR=$HOME/.enhancd
[[ -f $ENHANCD_DIR/init.sh ]] && source $ENHANCD_DIR/init.sh

sqlmap() {
  local arg next_is_output_dir="" output_dir_set=""
  local -a args=()

  for arg in "$@"; do
    if [[ -n "$next_is_output_dir" ]]; then
      output_dir_set=1
      next_is_output_dir=""
    elif [[ "$arg" == --output-dir ]]; then
      output_dir_set=1
      next_is_output_dir=1
    elif [[ "$arg" == --output-dir=* ]]; then
      output_dir_set=1
    fi
    args+=("$arg")
  done

  if [[ -z "$output_dir_set" ]]; then
    (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null
    if [[ -n "${CASE_HOME:-}" && "$PWD" == "$CASE_HOME"(|/*) ]]; then
      local out_dir="$CASE_HOME/exports/sqlmap"
      mkdir -p "$out_dir" || return 1
      args=(--output-dir "$out_dir" "${args[@]}")
    fi
  fi

  command sqlmap "${args[@]}"
}
