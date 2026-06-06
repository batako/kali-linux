# ========================
# fixmagic — check magic bytes; repair only when needed
# ========================

_fixmagic-out-path() {
  local file="$1" out="${2:-}"
  if [[ -n "$out" ]]; then
    echo "$out"
    return 0
  fi
  echo "${file:h}/${file:t:r}_fixed.${file:t:e}"
}

# stdout: status line + optional fix lines (tab-separated)
# exit 0 = ok or fixable; exit 1 = unknown
_fixmagic-analyze() {
  local file="$1"
  python3 -c '
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
fixes = []
kind = "unknown"
detail = ""

PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPG_SIG = b"\xff\xd8\xff"
GIF_TAGS = (b"GIF89a", b"GIF87a")

def note(fix_kind, fix_detail, start, end, new_bytes):
    fixes.append({
        "kind": fix_kind,
        "detail": fix_detail,
        "start": start,
        "end": end,
        "new": new_bytes,
    })

# PNG
if len(data) >= 16 and bytes(data[12:16]) == b"IHDR":
    kind = "png"
    cur = bytes(data[0:8])
    if cur == PNG_SIG:
        detail = "PNG signature OK"
    elif bytes(data[4:8]) == PNG_SIG[4:8]:
        note("png", "first 4 bytes -> 89 50 4E 47 (.PNG)", 0, 4, PNG_SIG[:4])
    else:
        note("png", "PNG signature (8 bytes)", 0, 8, PNG_SIG)

# JPEG
elif len(data) >= 3:
    if bytes(data[0:3]) == JPG_SIG:
        kind = "jpeg"
        detail = "JPEG signature OK"
    elif JPG_SIG in data[:4096]:
        pos = data.index(JPG_SIG)
        if 0 < pos < 64:
            kind = "jpeg"
            note("jpeg", "move JPEG header from offset {}".format(pos), 0, pos, b"")

# GIF
if kind == "unknown":
    for tag in GIF_TAGS:
        if len(data) >= 6 and bytes(data[0:6]) == tag:
            kind = "gif"
            detail = "{} signature OK".format(tag.decode())
            break
        if tag in data[:4096]:
            pos = data.index(tag)
            if 0 < pos < 64:
                kind = "gif"
                note("gif", "move {} header from offset {}".format(tag.decode(), pos), 0, pos, b"")
                break

if kind == "unknown" and not fixes:
    sys.exit(1)

if fixes:
    print("status\tfix\t{}".format(kind))
    for f in fixes:
        print("fix\t{kind}\t{detail}\t{start}\t{end}\t{new}".format(
            kind=f["kind"],
            detail=f["detail"],
            start=f["start"],
            end=f["end"],
            new=f["new"].hex(),
        ))
else:
    print("status\tok\t{}".format(kind))
    print("detail\t{}".format(detail))
' "$file"
}

_fixmagic-apply() {
  local file="$1" dest="$2"
  python3 -c '
import sys
from pathlib import Path

src = Path(sys.argv[1])
dest = Path(sys.argv[2])
plans = [line.rstrip("\n").split("\t", 5) for line in sys.stdin if line.strip()]

data = bytearray(src.read_bytes())
for row in plans:
    if row[0] != "fix" or row[1] == "status":
        continue
    kind, detail, start, end, new_hex = row[1], row[2], int(row[3]), int(row[4]), row[5]
    new = bytes.fromhex(new_hex) if new_hex else b""
    if kind in ("png",) and end - start == len(new):
        data[start:end] = new
    elif kind in ("jpeg", "gif") and end > start and not new:
        data = data[start:]
    elif new and end - start == len(new):
        data[start:end] = new
    else:
        print("fixmagic: unsupported plan: {} {}".format(kind, detail), file=sys.stderr)
        sys.exit(1)

dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(data)
' "$file" "$dest"
}

fixmagic() {
  local in_place=false check_only=false
  local out="" file=""
  local analyze fm_status kind detail plan fix_lines dest line summary

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        echo "usage: fixmagic [-o out] [-i] [-n] <file>"
        echo "  check magic bytes; repair only when needed"
        echo "  default output: <name>_fixed.<ext> beside input"
        echo ""
        echo "supported:"
        echo "  png   wrong signature but IHDR chunk at offset 12"
        echo "  jpeg  FF D8 FF header shifted within first 64 bytes"
        echo "  gif   GIF87a / GIF89a header shifted within first 64 bytes"
        echo ""
        echo "options:"
        echo "  -i   overwrite input when repair needed (backup: <file>.bak)"
        echo "  -n   check only (no write, even if repair needed)"
        echo "  -o   output path"
        echo ""
        echo "examples:"
        echo "  fixmagic broken.png         # ok -> skip; broken -> broken_fixed.png"
        echo "  fixmagic -n image.png       # check only"
        echo "  fixmagic -i corrupt.png     # repair in place"
        return 0
        ;;
      -o)
        out="$2"
        shift 2
        ;;
      -i)
        in_place=true
        shift
        ;;
      -n)
        check_only=true
        shift
        ;;
      --)
        shift
        file="$1"
        break
        ;;
      -*)
        echo "fixmagic: unknown option: $1" >&2
        return 1
        ;;
      *)
        file="$1"
        shift
        ;;
    esac
  done

  [[ -n "$file" && -f "$file" ]] || {
    echo "usage: fixmagic [-o out] [-i] [-n] <file>" >&2
    return 1
  }

  file="${file:A}"
  analyze="$(_fixmagic-analyze "$file" 2>/dev/null)" || {
    echo "[-] fixmagic: cannot check $file (unknown or unsupported format)" >&2
    echo "[i] try: file $file  &&  xxd $file | head" >&2
    return 1
  }

  IFS=$'\t' read -r _ fm_status kind <<< "${analyze%%$'\n'*}"

  echo "[*] file:   $(file -b "$file")"

  if [[ "$fm_status" == "ok" ]]; then
    detail="${analyze#*$'\n'}"
    detail="${detail#detail	}"
    echo "[=] ok:     no repair needed ($kind — ${detail:-magic OK})"
    return 0
  fi

  fix_lines="${analyze#*$'\n'}"
  plan=""
  while IFS= read -r line; do
    [[ "$line" == fix* ]] || continue
    summary="${line#fix	}"
    summary="${summary#*	}"
    echo "[!] fix:    ${summary%%	*}"
    plan+="${line}"$'\n'
  done <<< "$fix_lines"

  if $check_only; then
    echo "[i] check-only (-n): not writing"
    return 0
  fi

  if $in_place; then
    dest="$file"
    cp -p "$file" "${file}.bak"
    echo "[*] backup: ${file}.bak"
  else
    dest="$(_fixmagic-out-path "$file" "$out")"
  fi

  _fixmagic-apply "$file" "$dest" <<< "$plan" || return 1

  echo "[+] wrote:  $dest"
  echo "[+] after:  $(file -b "$dest")"
}
