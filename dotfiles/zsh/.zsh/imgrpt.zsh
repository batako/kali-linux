# ========================
# imgrpt — image metadata / forensics report
# imgmap — Google Maps URL from image GPS
# imgsearch — Google Lens reverse image search (local file)
# ========================

# stdout: "LAT LON" (decimal). exit 0 = found, 1 = no GPS, 2 = error
_img-gps-coords() {
  local file="$1" pos lat lon

  [[ -n "$file" && -f "$file" ]] || return 2
  command -v exiftool >/dev/null 2>&1 || return 2

  pos="$(exiftool -s3 -n -GPSPosition "$file" 2>/dev/null)"
  if [[ "$pos" =~ '^([-+]?[0-9]*\.?[0-9]+)[[:space:]]+([-+]?[0-9]*\.?[0-9]+)$' ]]; then
    print -r -- "${match[1]} ${match[2]}"
    return 0
  fi

  lat="$(exiftool -s3 -n -GPSLatitude "$file" 2>/dev/null)"
  lon="$(exiftool -s3 -n -GPSLongitude "$file" 2>/dev/null)"
  if [[ -z "$lat" || -z "$lon" ]]; then
    lat="$(exiftool -s3 -n -XMP:GPSLatitude "$file" 2>/dev/null)"
    lon="$(exiftool -s3 -n -XMP:GPSLongitude "$file" 2>/dev/null)"
  fi
  if [[ "$lat" =~ '^[-+]?[0-9]*\.?[0-9]+$' && "$lon" =~ '^[-+]?[0-9]*\.?[0-9]+$' ]]; then
    print -r -- "$lat $lon"
    return 0
  fi

  return 1
}

# Print Google Maps URL if image has GPS; otherwise report no location.
imgmap() {
  local file="" quiet=false
  local lat lon coords url

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: imgmap [-q] <image>"
        echo "  print Google Maps URL from EXIF/XMP GPS (decimal degrees)"
        echo "  no GPS → message on stderr, exit 1"
        echo ""
        echo "options:"
        echo "  -q   URL only (no stderr on success)"
        echo ""
        echo "examples:"
        echo "  imgmap photo.jpg"
        echo "  imgmap -q photo.jpg | xargs open   # macOS"
        return 0
        ;;
      -q|--quiet)
        quiet=true
        shift
        ;;
      *)
        file="$1"
        shift
        ;;
    esac
  done

  [[ -n "$file" && -f "$file" ]] || {
    echo "usage: imgmap [-q] <image>" >&2
    [[ -n "$file" ]] && echo "[-] not a file: $file" >&2
    return 2
  }

  file="$(realpath "$file" 2>/dev/null || echo "$file")"
  coords="$(_img-gps-coords "$file")"
  case $? in
    0)
      lat="${coords%% *}"
      lon="${coords#* }"
      url="https://www.google.com/maps?q=${lat},${lon}"
      $quiet || echo "[+] GPS: ${lat}, ${lon}" >&2
      print -r -- "$url"
      return 0
      ;;
    1)
      echo "[i] 位置情報なし（画像に GPS タグがありません）" >&2
      return 1
      ;;
    *)
      echo "[-] imgmap: exiftool required or cannot read $file" >&2
      return 2
      ;;
  esac
}

# stdout: temporary public URL for image file
_img-upload-public() {
  local file="$1" body url

  if ! command -v curl >/dev/null 2>&1; then
    echo "[-] imgsearch: curl required" >&2
    return 1
  fi

  body="$(curl -fsS -F "file=@${file}" https://0x0.st 2>/dev/null)" || body=""
  url="${body%%$'\n'*}"
  url="${url//[[:space:]]/}"
  if [[ "$url" =~ '^https?://' ]]; then
    print -r -- "$url"
    return 0
  fi

  body="$(curl -fsS -F "reqtype=fileupload" -F "fileToUpload=@${file}" \
    https://catbox.moe/user/api.php 2>/dev/null)" || {
    echo "[-] imgsearch: upload failed (0x0.st / catbox.moe)" >&2
    return 1
  }
  url="${body%%$'\n'*}"
  url="${url//[[:space:]]/}"
  if [[ "$url" =~ '^https?://' ]]; then
    print -r -- "$url"
    return 0
  fi

  echo "[-] imgsearch: unexpected upload response" >&2
  return 1
}

_img-google-lens-url() {
  python3 - "$1" <<'PY'
import sys
import urllib.parse

print(
    "https://lens.google.com/uploadbyurl?url="
    + urllib.parse.quote(sys.argv[1], safe="")
)
PY
}

_imgsearch-open-url() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
    return 0
  fi
  if command -v firefox >/dev/null 2>&1; then
    firefox "$url" >/dev/null 2>&1 &
    return 0
  fi
  echo "[-] imgsearch: no browser (xdg-open / firefox); copy URL above" >&2
  return 1
}

# Upload local image (or use -u URL) → Google Lens reverse image search URL
imgsearch() {
  local file="" image_url="" quiet=false do_open=false
  local upload_url lens_url

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        cat <<'EOF'
usage: imgsearch [-q] [-O] [-u image-url] <image>

  Reverse image search via Google Lens.
  Local files are uploaded to a temporary public host (0x0.st → catbox fallback),
  then opened as Lens search-by-URL.

options:
  -q         print Lens URL only
  -O, --open open in browser (xdg-open / firefox)
  -u URL     skip upload; use existing public image URL

examples:
  imgsearch photo.jpg
  imgsearch -O EsiNRuRU0AEH32u.jpg
  imgsearch -q photo.jpg | xargs open    # macOS host
  imgsearch -u 'https://example.com/a.jpg'
EOF
        return 0
        ;;
      -q|--quiet)
        quiet=true
        shift
        ;;
      -O|--open)
        do_open=true
        shift
        ;;
      -u|--url)
        image_url="$2"
        shift 2
        ;;
      *)
        file="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$image_url" ]]; then
    [[ -n "$file" && -f "$file" ]] || {
      echo "usage: imgsearch [-q] [-O] [-u image-url] <image>" >&2
      [[ -n "$file" ]] && echo "[-] not a file: $file" >&2
      return 2
    }
    file="$(realpath "$file" 2>/dev/null || echo "$file")"
    $quiet || echo "[*] imgsearch: uploading (temporary public URL)…" >&2
    image_url="$(_img-upload-public "$file")" || return 1
    $quiet || echo "[+] upload: ${image_url}" >&2
  elif [[ -z "$file" ]]; then
    :
  else
    echo "[-] imgsearch: use either <image> or -u URL, not both" >&2
    return 1
  fi

  lens_url="$(_img-google-lens-url "$image_url")" || return 1
  $quiet || echo "[+] lens: ${lens_url}" >&2
  print -r -- "$lens_url"

  if [[ "$do_open" == true ]]; then
    _imgsearch-open-url "$lens_url"
  fi
}

_imgrpt-out-path() {
  local file="$1" out="${2:-}"
  if [[ -n "$out" ]]; then
    echo "$out"
    return 0
  fi
  local home ts base
  base="${file:t:r}"
  if home="$(case-exports-dir 2>/dev/null)"; then
    ts="$(date +%Y%m%d-%H%M%S)"
    echo "$home/${base}_imgrpt_${ts}.md"
    return 0
  fi
  echo "${file:h}/${base}_imgrpt.md"
}

_imgrpt-usage() {
  echo "usage: imgrpt [-o path] [-q] [-B] <image>"
  echo "  collect metadata and write a Markdown report"
  echo ""
  echo "sections: file, exiftool, magic (fixmagic), steghide, binwalk, strings"
  echo "  default output: cases/<room>/exports/<name>_imgrpt_<ts>.md"
  echo ""
  echo "options:"
  echo "  -o path   report file path"
  echo "  -q        print output path only"
  echo "  -B        skip binwalk (faster)"
  echo ""
  echo "examples:"
  echo "  imgrpt photo.jpg"
  echo "  imgrpt -o report.md WindowsXP.jpg"
}

_imgrpt-section() {
  local title="$1"
  local body="${2:-}"
  print -r -- ""
  print -r -- "## ${title}"
  print -r -- ""
  if [[ -n "$body" ]]; then
    print -r -- "$body"
  else
    print -r -- "(none)"
  fi
}

_imgrpt-fence() {
  local text="${1:-}"
  if [[ -n "$text" ]]; then
    print -r -- '```'
    print -r -- "$text"
    print -r -- '```'
  else
    print -r -- "(empty)"
  fi
}

imgrpt() {
  local quiet=false skip_binwalk=false
  local out="" file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _imgrpt-usage
        return 0
        ;;
      -q|--quiet)
        quiet=true
        shift
        ;;
      -B|--no-binwalk)
        skip_binwalk=true
        shift
        ;;
      -o|--output)
        out="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "[-] unknown option: $1  (try: imgrpt -h)" >&2
        return 1
        ;;
      *)
        file="$1"
        shift
        ;;
    esac
  done

  [[ -n "$file" && -f "$file" ]] || {
    echo "usage: imgrpt [-o path] [-q] [-B] <image>" >&2
    [[ -n "$file" ]] && echo "[-] not a file: $file" >&2
    return 1
  }

  file="$(realpath "$file" 2>/dev/null || echo "$file")"
  local report
  report="$(_imgrpt-out-path "$file" "$out")"
  mkdir -p "${report:h}"

  $quiet || echo "[*] imgrpt: $file" >&2
  $quiet || echo "[*] writing: $report" >&2

  {
    print -r -- "# Image report: ${file:t}"
    print -r -- ""
    print -r -- "- generated: $(date -Iseconds 2>/dev/null || date)"
    print -r -- "- path: \`$file\`"
    if [[ -n "${CASE:-}" ]]; then
      print -r -- "- case: ${CASE}"
    fi

    _imgrpt-section "File" "$(
      local size md5 sha
      size="$(wc -c <"$file" | tr -d ' ')"
      md5="$(md5sum "$file" 2>/dev/null | awk '{print $1}')"
      sha="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
      print -r -- "- size: ${size} bytes"
      [[ -n "$md5" ]] && print -r -- "- md5: \`$md5\`"
      [[ -n "$sha" ]] && print -r -- "- sha256: \`$sha\`"
      print -r -- ""
      print -r -- '```'
      file -b "$file" 2>/dev/null || echo "(file unavailable)"
      print -r -- '```'
    )"

    _imgrpt-section "EXIF / metadata (exiftool)" "$(
      if command -v exiftool >/dev/null 2>&1; then
        _imgrpt-fence "$(exiftool -a -u -g1 "$file" 2>/dev/null)"
      else
        echo "(exiftool not installed)"
      fi
    )"

    _imgrpt-section "GPS (exiftool)" "$(
      if command -v exiftool >/dev/null 2>&1; then
        local gps coords lat lon url
        gps="$(exiftool -gpsposition -gpslatitude -gpslongitude -gpsaltitude \
          -xmp:gpslatitude -xmp:gpslongitude -n "$file" 2>/dev/null)"
        if [[ -n "$gps" ]]; then
          _imgrpt-fence "$gps"
          if coords="$(_img-gps-coords "$file" 2>/dev/null)"; then
            lat="${coords%% *}"
            lon="${coords#* }"
            url="https://www.google.com/maps?q=${lat},${lon}"
            print -r -- ""
            print -r -- "- Google Maps: [$url]($url)"
          fi
        else
          echo "(no GPS tags)"
        fi
      else
        echo "(exiftool not installed)"
      fi
    )"

    _imgrpt-section "Magic bytes (fixmagic check)" "$(
      if (( $+functions[_fixmagic-analyze] )); then
        local analyze line status detail
        analyze="$(_fixmagic-analyze "$file" 2>/dev/null)" || analyze=""
        if [[ -n "$analyze" ]]; then
          line="${analyze%%$'\n'*}"
          IFS=$'\t' read -r _ status detail <<< "$line"
          print -r -- "- status: **${status:-unknown}**"
          [[ -n "$detail" ]] && print -r -- "- detail: $detail"
          if [[ "$analyze" == *$'\n'* ]]; then
            print -r -- ""
            print -r -- '```'
            print -r -- "${analyze#*$'\n'}"
            print -r -- '```'
          fi
        else
          echo "(unknown format or not checkable)"
        fi
      else
        echo "(fixmagic not loaded)"
      fi
    )"

    _imgrpt-section "Steghide" "$(
      if (( $+functions[_steg-steghide-supported] )) && _steg-steghide-supported "$file"; then
        if (( $+functions[_steg-info] )); then
          _imgrpt-fence "$(_steg-info "$file" 2>/dev/null)"
        else
          _imgrpt-fence "$(steghide info "$file" 2>/dev/null)"
        fi
      else
        local kind
        kind="$(file -b "$file" 2>/dev/null)"
        echo "not applicable ($kind)"
        echo ""
        echo "steghide supports JPEG / BMP / WAV / AU only"
      fi
    )"

    if ! $skip_binwalk; then
      _imgrpt-section "Binwalk" "$(
        if command -v binwalk >/dev/null 2>&1; then
          _imgrpt-fence "$(binwalk "$file" 2>/dev/null)"
        else
          echo "(binwalk not installed)"
        fi
      )"
    fi

    _imgrpt-section "Strings (filtered)" "$(
      if command -v strings >/dev/null 2>&1; then
        local hits
        hits="$(strings -n 4 "$file" 2>/dev/null | grep -iE \
          'http|www\.|ftp|@|flag|thm\{|password|gps|comment|camera|author|latitude|longitude|location|hidden|secret|key|bash|/bin/|\.php|\.txt' \
          | head -80)"
        if [[ -n "$hits" ]]; then
          _imgrpt-fence "$hits"
        else
          echo "(no interesting strings in first pass — try: strings ${file:t} | less)"
        fi
      else
        echo "(strings not available)"
      fi
    )"

    print -r -- ""
    print -r -- "---"
    print -r -- ""
    print -r -- "next: \`stegx ${file:t}\` · \`fixmagic ${file:t}\` · open image visually"
  } >"$report"

  if $quiet; then
    print -r -- "$report"
  else
    echo "[+] report: $report" >&2
    print -r -- "$report"
  fi
}

_imgrpt() {
  _arguments \
    '-q[print output path only]' \
    '-B[skip binwalk]' \
    '-o[output path]:file:_files' \
    '1:image file:_files'
}

_imgmap() {
  _arguments '-q[URL only]' '1:image file:_files'
}

compdef _imgrpt imgrpt
compdef _imgmap imgmap
