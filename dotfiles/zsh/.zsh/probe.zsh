# ========================
# probe helpers
# ========================

typeset -g PROBE_SCRIPT_DIR="${${(%):-%N}:A:h}"

unalias probe 2>/dev/null || true

probe() {
  python3 "$PROBE_SCRIPT_DIR/probe.py" "$@"
}

reqfuzz() {
  python3 "$PROBE_SCRIPT_DIR/reqfuzz.py" "$@"
}

svcguess() {
  python3 "$PROBE_SCRIPT_DIR/svcguess.py" "$@"
}

_probe() {
  _arguments -C \
    '-h[usage]' '--help[usage]' \
    '--payloads[custom payload list]:file:_files' \
    '--raw[show full response body]' \
    '--save[save response bodies to files]' \
    '--json[emit JSON output]' \
    '-o[output directory for saved responses]:dir:_files -/' \
    '--timeout[HTTP timeout in seconds]:seconds:' \
    '-k[skip TLS certificate verification]' '--insecure[skip TLS certificate verification]' \
    '1:url template with FUZZ:'
}

if (( $+functions[compdef] )); then
  compdef _probe probe
fi

alias probe='noglob probe'
