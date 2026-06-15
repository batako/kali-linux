# ========================
# fixmagic — check magic bytes; repair only when needed
# ========================

_magic-help() {
  echo "usage:"
  echo "  magic <file>"
  echo "  magic -r TYPE [-o out] <file>"
  echo ""
  echo "  guess a file type from magic bytes"
  echo "  repair by trimming fake prefixes and restoring the target header"
  echo "  -r always writes a repaired file; -o changes the output path"
  echo "  default output: <name>_<type>.<ext>"
  echo ""
  echo "flags:"
  echo "  -r TYPE   choose the target format to repair to"
  echo "  -o out    save the repaired file under another name"
  echo "  -h        show this help"
  echo ""
  echo "TYPE (case-insensitive):"
  echo "  PNG, JPEG, GIF, BMP, WEBP, ICO"
  echo "  ZIP, RAR, 7Z, GZIP, PDF, ELF"
  echo ""
  echo "repair behavior:"
  echo "  PNG   uses IHDR to infer the real start; prepends PNG signature when needed"
  echo "  JPEG  uses FF DB / FF C0 / FF C2 / FF DA / FF D9 markers"
  echo "  others trim to the first target signature found in the file"
}

_magic-out-path() {
  local file="$1" out="${2:-}" kind="${3:-}"
  if [[ -n "$out" ]]; then
    echo "$out"
    return 0
  fi
  if [[ -n "$kind" ]]; then
    echo "${file:h}/${file:t:r}_${kind}.${file:t:e}"
    return 0
  fi
  echo "${file:h}/${file:t:r}_magic.${file:t:e}"
}

_magic-guess() {
  local file="$1"
  python3 -c '
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = path.read_bytes()

def hexbytes(buf, count=16):
    return " ".join(f"{b:02x}" for b in buf[:count])

def emit(kind, detail):
    print("status\tok\t{}".format(kind))
    print("detail\t{}".format(detail))
    print("magic\t{}".format(hexbytes(data)))
    sys.exit(0)

if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
    emit("PNG", "PNG signature")

if len(data) >= 2 and data[:2] == b"\xff\xd8":
    emit("JPEG", "JPEG signature")

if len(data) >= 6 and data[:6] in (b"GIF87a", b"GIF89a"):
    emit("GIF", "{} signature".format(data[:6].decode("ascii")))

if len(data) >= 2 and data[:2] == b"BM":
    emit("BMP", "BMP signature")

if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
    emit("WEBP", "RIFF....WEBP container")

if len(data) >= 4 and data[:4] == b"\x00\x00\x01\x00":
    emit("ICO", "ICO signature")

if len(data) >= 4 and data[:4] == b"PK\x03\x04":
    emit("ZIP", "ZIP local file header")

if len(data) >= 8 and data[:8] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"):
    emit("RAR", "RAR signature")

if len(data) >= 6 and data[:6] == b"7z\xbc\xaf\x27\x1c":
    emit("7Z", "7-Zip signature")

if len(data) >= 2 and data[:2] == b"\x1f\x8b":
    emit("GZIP", "gzip signature")

if len(data) >= 5 and data[:5] == b"%PDF-":
    emit("PDF", "PDF signature")

if len(data) >= 4 and data[:4] == b"\x7fELF":
    emit("ELF", "ELF signature")

print("status\tunknown\tunknown")
print("detail\tno known file magic byte matched")
print("magic\t{}".format(hexbytes(data)))
sys.exit(1)
' "$file"
}

_magic-repair-plan() {
  local file="$1" kind="$2"
  python3 - "$file" "$kind" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
kind = sys.argv[2].upper()
data = bytearray(src.read_bytes())
scan_limit = min(len(data), 1024 * 1024)

signatures = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF": b"GIF89a",
    "BMP": b"BM",
    "WEBP": b"RIFF\x00\x00\x00\x00WEBP",
    "ICO": b"\x00\x00\x01\x00",
    "ZIP": b"PK\x03\x04",
    "RAR": b"Rar!\x1a\x07\x00",
    "7Z": b"7z\xbc\xaf\x27\x1c",
    "GZIP": b"\x1f\x8b",
    "PDF": b"%PDF-",
    "ELF": b"\x7fELF",
}

def emit(mode, skip, prefix=b"", notes=None, detail=""):
    print("status\tok\t{}".format(kind))
    print("mode\t{}".format(mode))
    print("skip\t{}".format(skip))
    print("prefix\t{}".format(prefix.hex()))
    print("detail\t{}".format(detail))
    if notes:
        for label, pos in notes:
            print("found\t{}\t{}".format(label, pos))
    sys.exit(0)

def unknown(detail):
    print("status\tunknown\t{}".format(kind))
    print("detail\t{}".format(detail))
    sys.exit(1)

def search(pat):
    return data.find(pat, 0, scan_limit)

sig = signatures.get(kind)
if sig is None:
    unknown("unsupported type")

if kind == "PNG":
    sig_pos = search(sig)
    ihdr_pos = search(b"IHDR")
    notes = []
    if sig_pos != -1:
        notes.append(("PNG signature", sig_pos))
        if ihdr_pos != -1:
            notes.append(("IHDR", ihdr_pos))
        emit("trim", sig_pos, b"", notes, "PNG signature already present; trimming fake prefix only")
    if ihdr_pos != -1 and ihdr_pos >= 12:
        skip = ihdr_pos - 12
        emit("prepend", skip, sig, [("IHDR", ihdr_pos)], "IHDR suggests PNG starts before it; restoring signature")
    emit("prepend", 0, sig, [], "fallback: PNG signature prepended")

if kind == "JPEG":
    soi = search(b"\xff\xd8")
    markers = []
    for label, pat in (("FF DB", b"\xff\xdb"), ("FF C0", b"\xff\xc0"), ("FF C2", b"\xff\xc2"), ("FF DA", b"\xff\xda"), ("FF D9", b"\xff\xd9")):
        pos = search(pat)
        if pos != -1:
            markers.append((label, pos))
    if soi != -1:
        notes = [("SOI", soi)] + markers
        emit("trim", soi, b"", notes, "JPEG SOI found; trimming to it")
    if markers:
        markers.sort(key=lambda item: item[1])
        emit("prepend", markers[0][1], b"\xff\xd8", markers, "JPEG markers suggest the real structure starts here")
    emit("prepend", 0, b"\xff\xd8", [], "fallback: JPEG signature prepended")

for label, pat in (
    ("GIF", b"GIF89a"),
    ("GIF", b"GIF87a"),
    ("BMP", b"BM"),
    ("WEBP", b"RIFF"),
    ("ICO", b"\x00\x00\x01\x00"),
    ("ZIP", b"PK\x03\x04"),
    ("RAR", b"Rar!\x1a\x07\x00"),
    ("RAR", b"Rar!\x1a\x07\x01\x00"),
    ("7Z", b"7z\xbc\xaf\x27\x1c"),
    ("GZIP", b"\x1f\x8b"),
    ("PDF", b"%PDF-"),
    ("ELF", b"\x7fELF"),
):
    pos = search(pat)
    if kind == "WEBP" and pos != -1:
        if pos + 12 <= len(data) and data[pos + 8:pos + 12] == b"WEBP":
            emit("trim", pos, b"", [(label, pos)], "WEBP signature found")
    elif pos != -1:
        emit("trim", pos, b"", [(label, pos)], "{} signature found".format(label))

emit("prepend", 0, sig, [], "fallback: target signature prepended")
PY
}

_magic-repair-apply() {
  local file="$1" kind="$2" dest="$3" mode="$4" skip="$5" prefix_hex="${6:-}"
  python3 - "$file" "$kind" "$dest" "$mode" "$skip" "$prefix_hex" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
kind = sys.argv[2].upper()
dest = Path(sys.argv[3])
mode = sys.argv[4]
skip = int(sys.argv[5])
prefix_hex = sys.argv[6]
data = src.read_bytes()

if skip < 0 or skip > len(data):
    print("magic: invalid skip offset", file=sys.stderr)
    sys.exit(1)

prefix = bytes.fromhex(prefix_hex) if prefix_hex else b""
body = data[skip:]

if mode == "trim":
    output = body
elif mode == "prepend":
    output = prefix + body
else:
    print("magic: unsupported repair mode: {}".format(mode), file=sys.stderr)
    sys.exit(1)

dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(output)
PY
}

_magic-analyze() {
  local file="$1"
  _magic-guess "$file"
}

magic() {
  local file="" replace_kind="" out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--replace)
        replace_kind="${2:-}"
        shift 2
        ;;
      -o)
        out="$2"
        shift 2
        ;;
      -h|--help)
        _magic-help
        return 0
        ;;
      -*)
        echo "magic: unknown option: $1" >&2
        return 1
        ;;
      *)
        file="$1"
        shift
        ;;
    esac
  done

  [[ -n "$file" && -f "$file" ]] || {
    echo "usage: magic <file>" >&2
    return 1
  }

  file="${file:A}"
  local analyze guess_status kind detail magic dest mode skip prefix_hex line
  local -a lines found_lines
  if [[ -n "$replace_kind" ]]; then
    replace_kind="${replace_kind:u}"
    case "$replace_kind" in
      PNG|JPEG|GIF|BMP|WEBP|ICO|ZIP|RAR|7Z|GZIP|PDF|ELF)
        ;;
      *)
        echo "magic: unsupported replace type: $replace_kind" >&2
        return 1
        ;;
    esac
    analyze="$(_magic-repair-plan "$file" "$replace_kind" 2>/dev/null)" || true
    lines=("${(@f)analyze}")
    IFS=$'\t' read -r _ guess_status kind <<< "${lines[1]}"
    mode=""
    skip=""
    prefix_hex=""
    detail=""
    found_lines=()
    for line in "${lines[@]:1}"; do
      case "$line" in
        mode$'\t'*) mode="${line#mode$'\t'}" ;;
        skip$'\t'*) skip="${line#skip$'\t'}" ;;
        prefix$'\t'*) prefix_hex="${line#prefix$'\t'}" ;;
        detail$'\t'*) detail="${line#detail$'\t'}" ;;
        found$'\t'*) found_lines+=("${line#found$'\t'}") ;;
      esac
    done

    echo "[*] file:   $(file -b "$file")"
    if [[ "$guess_status" != "ok" ]]; then
      echo "[?] repair target: $replace_kind"
      echo "[i] detail: ${detail:-no repair plan}"
      return 1
    fi

    echo "[+] repair target: ${kind}"
    echo "[i] mode:    ${mode}"
    echo "[i] skip:    ${skip}"
    if [[ -n "$prefix_hex" ]]; then
      echo "[i] prefix:  ${prefix_hex}"
    fi
    for line in "${found_lines[@]}"; do
      echo "[i] found:   ${line}"
    done

    dest="$(_magic-out-path "$file" "$out" "${replace_kind:l}")"
    if [[ "$dest" == "$file" ]]; then
      cp -p "$file" "${file}.bak"
      echo "[*] backup: ${file}.bak"
    fi

    if [[ "$mode" != "trim" && "$mode" != "prepend" ]]; then
      echo "magic: unsupported repair mode: $mode" >&2
      return 1
    fi

    _magic-repair-apply "$file" "$kind" "$dest" "$mode" "$skip" "$prefix_hex" || return 1
    echo "[+] wrote:  $dest"
    echo "[i] after:  $(file -b "$dest")"
    return 0
  fi

  analyze="$(_magic-analyze "$file" 2>/dev/null)" || true

  lines=("${(@f)analyze}")
  IFS=$'\t' read -r _ guess_status kind <<< "${lines[1]}"
  detail="${lines[2]#detail	}"
  magic="${lines[3]#magic	}"

  echo "[*] file:   $(file -b "$file")"
  if [[ "$guess_status" == "ok" ]]; then
    echo "[+] guess:  ${kind} (${detail})"
  else
    echo "[?] guess:  unknown"
    echo "[i] detail: ${detail}"
  fi
  echo "[i] magic:  ${magic}"
}

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
