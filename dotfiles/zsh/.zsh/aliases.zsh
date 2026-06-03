# ========================
# system / network
# ========================
alias ports='ss -tulnp'
alias http='python3 -m http.server 8000'

# ========================
# recon / scanning
# =========================

scan() {
  local target="${1:-${IP:-}}"
  if [[ -z "$target" ]]; then
    echo "usage: scan [ip]  (or: target-set <ip> first)"
    return 1
  fi

  local out_dir="${RECON_HOME:-/workspace/recon}/scans"
  mkdir -p "$out_dir"
  nmap -sC -sV -oN "${out_dir}/nmap-${target}.txt" "$target"
}
alias ss='searchsploit'
alias msf='msfconsole'

# ========================
# dns
# ========================
alias diga='dig @1.1.1.1 +short A'
alias digmx='dig @1.1.1.1 +short MX'
alias digtxt='dig @1.1.1.1 +short TXT'
alias digns='dig @1.1.1.1 +short NS'

# ========================
# tmux / workspace
# ========================
alias t='tmux new -A -s ctf'
