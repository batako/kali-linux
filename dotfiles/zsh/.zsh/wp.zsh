# ========================
# wp — WordPress assessment CLI
# ========================

WP_APP="${WP_APP:-/opt/recon/wp.py}"

wp() {
  python3 "$WP_APP" "$@"
}

_wp() {
  _arguments -C \
    '-h[usage]' '--help[usage]' \
    '1:command:(assess)' \
    '2:assess subcommand:->assess'

  case $state in
    assess)
      _arguments \
        '-h[usage]' '--help[usage]' \
        '--fast[lightweight checks only]' \
        '--full[expanded exposure checks]' \
        '--use-api[use WPSCAN_API_TOKEN with WPScan]' \
        '--out[write report.md to DIR]:directory:_files -/' \
        '*:target url:_urls'
      ;;
  esac
}

compdef _wp wp
