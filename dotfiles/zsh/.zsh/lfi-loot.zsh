# ========================
# lfi-loot — offline LFI response parser
# ========================

LFI_LOOT_APP="${LFI_LOOT_APP:-${RECON_APP:h}/lfi_loot.py}"

lfi-loot() {
  # Bare URLs with '?' need quotes in zsh, or use: lfi-loot -u 'http://...?pl=...'
  noglob python3 "$LFI_LOOT_APP" "$@"
}

_lfi_loot() {
  _arguments -C \
    '-h[usage]' '--help[usage]' \
    '-k[skip TLS certificate verification]' '--insecure[skip TLS certificate verification]' \
    '-u[fetch URL]:url:' '--url[fetch URL]:url:' \
    '--timeout[HTTP timeout in seconds]:seconds:' \
    '--fuzz-payload[extra FUZZ path]:path:' \
    '--no-b64-fallback[disable auto base64 retry on empty PHP include]' \
    '--name[override logical filename]:logical=target:' \
    '*:input path or URL:_files -/'
}

if (( $+functions[compdef] )); then
  compdef _lfi_loot lfi-loot
fi
