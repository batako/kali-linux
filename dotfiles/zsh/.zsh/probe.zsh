# ========================
# probe helpers
# ========================

typeset -g PROBE_SCRIPT_DIR="${${(%):-%N}:A:h}"

reqfuzz() {
  python3 "$PROBE_SCRIPT_DIR/reqfuzz.py" "$@"
}

svcguess() {
  python3 "$PROBE_SCRIPT_DIR/svcguess.py" "$@"
}
