# ========================
# borg backup helpers
# ========================

_borg_bin() {
  whence -p borg 2>/dev/null || echo /usr/bin/borg
}

_borg_find_repo() {
  local root="$1" f

  if [[ -d "$root" && -f "$root/README" ]] && grep -q 'Borg Backup' "$root/README" 2>/dev/null; then
    print -r -- "$(realpath "$root" 2>/dev/null || echo "$root")"
    return 0
  fi

  for f in "$root"/**/README(.N); do
    if grep -q 'Borg Backup' "$f" 2>/dev/null; then
      print -r -- "$(realpath "${f:h}" 2>/dev/null || echo "${f:h}")"
      return 0
    fi
  done

  return 1
}

_borg_pass_from_cl() {
  local ip user pass

  ip="$(_recon-ip-default 2>/dev/null)" || {
    echo "[-] no target ip for cl (ts <ip> or cs <case> with target)" >&2
    return 1
  }

  user="${1:-}"
  if [[ -z "$user" ]]; then
    user="${RECON_BORG_CREDS_USER:-borg}"
    if pass="$(_recon-creds-for-user "$ip" "$user" 2>/dev/null)" && [[ -n "$pass" ]]; then
      echo "[*] passphrase: from cl (${user}@${ip})" >&2
      print -r -- "$pass"
      return 0
    fi
    if ! _recon-has-creds "$ip"; then
      echo "[-] no creds for $ip (cl empty; try: hash-crack -b ...)" >&2
      return 1
    fi
    user="$(_recon-pick-user "$ip" 1)" || return 1
  fi

  pass="$(_recon-creds-for-user "$ip" "$user" 2>/dev/null)" || pass=""
  if [[ -z "$pass" ]]; then
    echo "[-] no password for ${user}@${ip} (cl)" >&2
    return 1
  fi

  echo "[*] passphrase: from cl (${user}@${ip})" >&2
  print -r -- "$pass"
}

# フォルダ内の Borg リポジトリを探して全アーカイブを extract
# usage: borg-crack [-n] [-u user] [-p pass] <dir> [pass]
#   borg-crack <dir>                    # cl ($IP) からパスフレーズ
#   borg-crack -u <user> <dir>          # cl の指定ユーザ
#   borg-crack -p <passphrase> <dir>
# -n: borg list のみ（extract しない）
borg-crack() {
  local do_extract=1
  local pass="${BORG_PASSPHRASE:-}"
  local cred_user=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n) do_extract=0; shift ;;
      -u) cred_user="$2"; shift 2 ;;
      -p) pass="$2"; shift 2 ;;
      -h|--help)
        cat <<'EOF'
usage: borg-crack [-n] [-u user] [-p pass] <dir> [pass]

  <dir>   Borg リポジトリ、またはその配下に README があるフォルダ
  pass    -p / 第2引数 / $BORG_PASSPHRASE / cl ($IP) の順で使用
  -u      cl のユーザ（省略時は borg → なければ対話選択）

  -n  borg list のみ（extract しない）

  on success: borg list → extract every archive under exports/<repo名>/borg/

examples:
  borg-crack <dir>
  borg-crack -u <user> <dir>
  borg-crack -p <passphrase> <dir>
  borg-crack <dir> <passphrase>
EOF
        return 0
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -lt 1 ]]; then
    echo "usage: borg-crack [-n] [-u user] [-p pass] <dir> [pass]"
    return 1
  fi

  local target="$1"
  [[ $# -ge 2 && -z "$pass" ]] && pass="$2"

  if [[ -z "$pass" ]]; then
    pass="$(_borg_pass_from_cl "$cred_user")" || return 1
  fi

  if [[ ! -d "$target" ]]; then
    echo "[-] not a directory: $target" >&2
    return 1
  fi

  local borg_bin
  borg_bin="$(_borg_bin)"
  if [[ ! -x "$borg_bin" ]]; then
    echo "borg not found (install borgbackup)"
    return 1
  fi

  local repo
  repo="$(_borg_find_repo "$target")" || {
    echo "[-] no Borg repository under $target" >&2
    return 1
  }
  echo "[*] repo: $repo"

  export BORG_PASSPHRASE="$pass"

  "$borg_bin" break-lock "$repo" 2>/dev/null || true

  echo ""
  echo "[*] archives:"
  if ! "$borg_bin" list "$repo"; then
    echo "[-] borg list failed (wrong passphrase?)" >&2
    return 1
  fi

  local archives=("${(@f)$("$borg_bin" list --short "$repo")}")
  if [[ ${#archives[@]} -eq 0 ]]; then
    echo "[-] no archives in repository" >&2
    return 1
  fi

  (( do_extract )) || return 0

  local out_dir extract_dir
  out_dir="$(case-exports-dir)" || return 1
  extract_dir="${out_dir}/${repo:t}/borg"
  mkdir -p "$extract_dir"

  local arch rc=0
  for arch in "${archives[@]}"; do
    [[ -z "$arch" ]] && continue
    echo ""
    echo "[*] extracting ${repo}::${arch} → $extract_dir"
    (
      cd "$extract_dir" || exit 1
      "$borg_bin" extract "${repo}::${arch}"
    ) || rc=1
  done

  echo ""
  if (( rc == 0 )); then
    echo "[+] extracted to: $extract_dir"
    find "$extract_dir" -maxdepth 4 -type f 2>/dev/null | head -30
  else
    echo "[-] one or more archives failed to extract" >&2
  fi

  return $rc
}
