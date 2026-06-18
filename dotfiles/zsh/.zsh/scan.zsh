# ========================
# scan — nmap -sC -sV with port_scan_coverage (recon.db)
# ========================

scan() {
  local ip="" profile="" report="" force="" dry="" quiet="" jobs=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        if _toolkit-lang-ja; then
          cat <<EOF
使い方: scan [options] [ip]
  scan              nmap top 1000 (-sC -sV)、coverage 済みポートをスキップ
  scan -f           --full と同じ（TCP 1-65535 を完了まで）
  scan -r           DB から OPEN + CLOSED を表示（nmap なし）

オプション:
  -h, --help        このヘルプ
  -f, --full        TCP 1-65535 を完了まで実行（1 コマンド）
  -r, --report      DB のポート表のみ表示（nmap なし）
  --force           再スキャン（top 1000、または --full 時は -p-）
  -n, --dry-run     nmap コマンドだけ表示
  -q, --quiet       最後のポート表を省略
  -j, --jobs N      --full 時のみ: 並列ワーカー数 (1-${SCAN_FULL_JOBS_MAX:-8}, 既定 1)

事前準備: case-set <room>  &&  target-set <ip>
関連: scout -r  （偵察サマリ）  |  case-reset  （ルーム消去）
EOF
        else
          cat <<EOF
usage: scan [options] [ip]
  scan              nmap top 1000 (-sC -sV), skips covered ports
  scan -f           same with --full (TCP 1-65535 until complete)
  scan -r           OPEN + CLOSED from DB (no nmap)

options:
  -h, --help        this help
  -f, --full        TCP 1-65535 until complete (one command)
  -r, --report      port tables from DB (no nmap)
  --force           rescan (top 1000 or -p- with --full)
  -n, --dry-run     print nmap command only
  -q, --quiet       no port tables at end
  -j, --jobs N      --full only: parallel workers (1-${SCAN_FULL_JOBS_MAX:-8}, default 1)

prep: case-set <room>  &&  target-set <ip>
more: scout -r  (recon summary)  |  case-reset  (wipe room)
EOF
        fi
        return 0
        ;;
      -f|--full)
        profile=full
        shift
        ;;
      -r|--report)
        report=1
        shift
        ;;
      --force)
        force="--force"
        shift
        ;;
      -n|--dry-run)
        dry="-n"
        shift
        ;;
      -q|--quiet)
        quiet="-q"
        shift
        ;;
      -j|--jobs)
        jobs="$2"
        shift 2
        ;;
      -j[0-9]|-j[0-9][0-9])
        jobs="${1#-j}"
        shift
        ;;
      -*)
        echo "[-] unknown option: $1" >&2
        return 1
        ;;
      full|report)
        echo "[-] use scan -f or scan --$1 (positional '$1' removed)" >&2
        return 1
        ;;
      *)
        if [[ "$1" =~ $(_recon-ip-re) ]]; then
          ip="$1"
        else
          echo "[-] expected ip, got: $1" >&2
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -n "$report" && -n "$profile" ]]; then
    echo "[-] use either --full/-f or --report/-r, not both" >&2
    return 1
  fi
  if [[ -n "$report" && ( -n "$force" || -n "$dry" || -n "$quiet" || -n "$jobs" ) ]]; then
    echo "[-] --report does not take --force, -n, -q, or -j" >&2
    return 1
  fi

  if [[ -z "$ip" ]]; then
    ip="$(target-current 2>/dev/null)" || {
      echo "[-] no target (target-set <ip> / case-set <room>)" >&2
      return 1
    }
  fi

  (( $+functions[_case-resolve-from-pwd] )) && _case-resolve-from-pwd 2>/dev/null

  local -a args=(scan)
  if [[ -n "$report" ]]; then
    args+=(--report "$ip")
  else
    [[ -n "$profile" ]] && args+=(--full)
    args+=("$ip")
    [[ -n "$force" ]] && args+=("$force")
    [[ -n "$dry" ]] && args+=(-n)
    [[ -n "$quiet" ]] && args+=(-q)
    [[ -n "$jobs" ]] && args+=(-j "$jobs")
  fi

  python3 "$RECON_APP" "${args[@]}"
}

_scan() {
  _arguments \
    '-h[usage]' '--help[usage]' \
    '-f[full TCP 1-65535]' \
    '--full[full TCP 1-65535]' \
    '-r[report only]' \
    '--report[report only]' \
    '--force[rescan]' \
    '-n[dry-run]' \
    '-q[no port tables]' \
    '-j[parallel workers (--full)]::jobs:' \
    '*:ip:($IP)'
}

compdef _scan scan
