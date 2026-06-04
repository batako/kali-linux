# ========================
# system / network
# ========================
alias ports='ss -tulnp'
alias http='python3 -m http.server 8000'

# ========================
# recon / scanning
# =========================

scan() {
  local target="${1:-$(target-current 2>/dev/null)}"
  if [[ -z "$target" ]]; then
    echo "usage: scan [ip]  (or: cs <case> / ts <ip>)"
    return 1
  fi

  # stdout only; persist with: x scan
  nmap -sC -sV "$target"
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
