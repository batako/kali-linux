#!/usr/bin/env bash
set -euo pipefail

MKLIST_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
MKLIST_CACHE_VERSION="16"
MKLIST_TMPDIR=""
MKLIST_MODE="passwords"
MKLIST_INPUT=""
MKLIST_INPUT_TYPE=""
MKLIST_OUTPUT=""
MKLIST_REFRESH=0
MKLIST_SEED=""
MKLIST_PIN=""
MKLIST_MAX_LINES=100000
MKLIST_SCOPE_ROOT=""
MKLIST_INTERNAL_DIR=""
MKLIST_RAW_DIR=""
MKLIST_WORK_DIR=""
MKLIST_CACHE_DIR=""
MKLIST_RAW_HTML_FILE=""
MKLIST_RAW_FILE=""
MKLIST_CLEAN_FILE=""
MKLIST_VALUE_LINES_FILE=""
MKLIST_MATERIAL_LINES_FILE=""
MKLIST_PAIRS_FILE=""
MKLIST_HINT_LINES_FILE=""
MKLIST_HINT_KEYWORDS_FILE=""
MKLIST_HINT_RULES_FILE=""
MKLIST_CONTEXT_NUMBERS_FILE=""
MKLIST_CONTEXT_YEARS_FILE=""
MKLIST_BASE_FILE=""
MKLIST_META_FILE=""
MKLIST_OUTPUT_FILE=""
MKLIST_STOPWORDS_FILE="$MKLIST_SCRIPT_DIR/mklist-stopwords.txt"
MKLIST_ENTRY_COUNT=0
MKLIST_CACHE_INPUT=""
MKLIST_CACHE_INPUT_TYPE=""
MKLIST_CACHE_MODE=""
MKLIST_CACHE_VERSION_SAVED=""

usage() {
  cat <<'EOF'
usage:
  mklist <URL|HTML_FILE> [options]
  mklist passwords <URL|HTML_FILE> [options]

options:
  --refresh          refresh cached raw words from the current input
  --seed <file>      append seed words to base.txt
  --pin <4|6>        append numeric PINs via crunch when available
  --max-lines <n>    cap output entries (default: 100000)
  -o <file>          output path (default: exports/passwords.txt)
  -h, --help         show this help

layout:
  .mklist/raw/html.html
  .mklist/raw/cewl.txt
  .mklist/work/clean.txt
  .mklist/work/value_lines.txt
  .mklist/work/material_lines.txt
  .mklist/work/pairs.tsv
  .mklist/work/hint_lines.txt
  .mklist/work/hint_keywords.txt
  .mklist/work/base.txt
  .mklist/cache/meta.env
  exports/passwords.txt
EOF
}

check_dependencies() {
  local dep
  for dep in awk sed sort tr mktemp; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      echo "[-] mklist: required command not found: $dep" >&2
      exit 1
    fi
  done
}

check_input_dependencies() {
  case "$MKLIST_INPUT_TYPE" in
    url)
      if ! command -v cewl >/dev/null 2>&1; then
        echo "[-] mklist: required command not found: cewl" >&2
        exit 1
      fi
      ;;
    html)
      :
      ;;
  esac
}

cleanup() {
  if [[ -n "${MKLIST_TMPDIR:-}" && -d "${MKLIST_TMPDIR:-}" ]]; then
    rm -rf "$MKLIST_TMPDIR"
  fi
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

to_upper() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

to_title() {
  printf '%s' "$1" | awk '
    {
      first = substr($0, 1, 1)
      rest = substr($0, 2)
      printf "%s%s", toupper(first), rest
    }
  '
}

resolve_case_home() {
  local pwd_path room_name

  if [[ -n "${CASE_HOME:-}" && -d "${CASE_HOME:-}" ]]; then
    printf '%s\n' "$CASE_HOME"
    return 0
  fi

  pwd_path="$(pwd -P 2>/dev/null || pwd)"
  case "$pwd_path" in
    /workspace/cases/*)
      room_name="${pwd_path#/workspace/cases/}"
      room_name="${room_name%%/*}"
      if [[ -n "$room_name" && "$room_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        printf '/workspace/cases/%s\n' "$room_name"
        return 0
      fi
      ;;
  esac

  return 1
}

resolve_scope_root() {
  local case_home=""

  if case_home="$(resolve_case_home 2>/dev/null)"; then
    printf '%s\n' "$case_home"
  else
    pwd -P 2>/dev/null || pwd
  fi
}

canonicalize_path() {
  local input_path="$1"
  local dir base

  dir="$(cd "$(dirname "$input_path")" && pwd -P)" || return 1
  base="$(basename "$input_path")"
  printf '%s/%s\n' "$dir" "$base"
}

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      passwords)
        MKLIST_MODE="passwords"
        shift
        ;;
      --refresh)
        MKLIST_REFRESH=1
        shift
        ;;
      --seed)
        [[ -n "${2:-}" ]] || {
          echo "[-] mklist: --seed requires a file" >&2
          usage >&2
          exit 1
        }
        MKLIST_SEED="$2"
        shift 2
        ;;
      --pin)
        [[ -n "${2:-}" ]] || {
          echo "[-] mklist: --pin requires a value" >&2
          usage >&2
          exit 1
        }
        MKLIST_PIN="$2"
        shift 2
        ;;
      --max-lines)
        [[ -n "${2:-}" ]] || {
          echo "[-] mklist: --max-lines requires a value" >&2
          usage >&2
          exit 1
        }
        MKLIST_MAX_LINES="$2"
        shift 2
        ;;
      -o)
        [[ -n "${2:-}" ]] || {
          echo "[-] mklist: -o requires a path" >&2
          usage >&2
          exit 1
        }
        MKLIST_OUTPUT="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -*)
        echo "[-] mklist: unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
      *)
        if [[ -z "$MKLIST_INPUT" ]]; then
          MKLIST_INPUT="$1"
        else
          echo "[-] mklist: unexpected argument: $1" >&2
          usage >&2
          exit 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$MKLIST_INPUT" ]]; then
    echo "[-] mklist: URL or HTML file is required" >&2
    usage >&2
    exit 1
  fi

  if [[ "$MKLIST_INPUT" =~ ^https?:// ]]; then
    MKLIST_INPUT_TYPE="url"
  elif [[ -f "$MKLIST_INPUT" ]]; then
    MKLIST_INPUT_TYPE="html"
    MKLIST_INPUT="$(canonicalize_path "$MKLIST_INPUT")"
  else
    echo "[-] mklist: input must be http(s) URL or an existing HTML file" >&2
    exit 1
  fi

  if [[ ! "$MKLIST_MAX_LINES" =~ ^[0-9]+$ ]] || [[ "$MKLIST_MAX_LINES" -le 0 ]]; then
    echo "[-] mklist: --max-lines must be a positive integer" >&2
    exit 1
  fi

  if [[ -n "$MKLIST_PIN" && ! "$MKLIST_PIN" =~ ^(4|6)$ ]]; then
    echo "[-] mklist: --pin supports only 4 or 6" >&2
    exit 1
  fi

  if [[ -n "$MKLIST_SEED" && ! -f "$MKLIST_SEED" ]]; then
    echo "[-] mklist: seed file not found: $MKLIST_SEED" >&2
    exit 1
  fi
}

init_paths() {
  MKLIST_SCOPE_ROOT="$(resolve_scope_root)"
  MKLIST_INTERNAL_DIR="$MKLIST_SCOPE_ROOT/.mklist"
  MKLIST_RAW_DIR="$MKLIST_INTERNAL_DIR/raw"
  MKLIST_WORK_DIR="$MKLIST_INTERNAL_DIR/work"
  MKLIST_CACHE_DIR="$MKLIST_INTERNAL_DIR/cache"
  MKLIST_RAW_HTML_FILE="$MKLIST_RAW_DIR/html.html"
  MKLIST_RAW_FILE="$MKLIST_RAW_DIR/cewl.txt"
  MKLIST_CLEAN_FILE="$MKLIST_WORK_DIR/clean.txt"
  MKLIST_VALUE_LINES_FILE="$MKLIST_WORK_DIR/value_lines.txt"
  MKLIST_MATERIAL_LINES_FILE="$MKLIST_WORK_DIR/material_lines.txt"
  MKLIST_PAIRS_FILE="$MKLIST_WORK_DIR/pairs.tsv"
  MKLIST_HINT_LINES_FILE="$MKLIST_WORK_DIR/hint_lines.txt"
  MKLIST_HINT_KEYWORDS_FILE="$MKLIST_WORK_DIR/hint_keywords.txt"
  MKLIST_HINT_RULES_FILE="$MKLIST_WORK_DIR/hint_rules.env"
  MKLIST_CONTEXT_NUMBERS_FILE="$MKLIST_WORK_DIR/context_numbers.txt"
  MKLIST_CONTEXT_YEARS_FILE="$MKLIST_WORK_DIR/context_years.txt"
  MKLIST_BASE_FILE="$MKLIST_WORK_DIR/base.txt"
  MKLIST_META_FILE="$MKLIST_CACHE_DIR/meta.env"

  mkdir -p "$MKLIST_RAW_DIR" "$MKLIST_WORK_DIR" "$MKLIST_CACHE_DIR"

  if [[ -n "$MKLIST_OUTPUT" ]]; then
    MKLIST_OUTPUT_FILE="$MKLIST_OUTPUT"
  else
    MKLIST_OUTPUT_FILE="$MKLIST_SCOPE_ROOT/exports/passwords.txt"
  fi

  mkdir -p "$(dirname "$MKLIST_OUTPUT_FILE")"
}

load_cache() {
  echo "[*] Loading cache..."

  if [[ -f "$MKLIST_META_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$MKLIST_META_FILE"
  fi
}

strip_noise_blocks() {
  local input_file="$1"
  local output_file="$2"

  if ! awk '
    function emit_prefix(prefix) {
      if (prefix != "") {
        printf "%s", prefix
      }
    }
    {
      line = $0 "\n"
      while (length(line) > 0) {
        lower = tolower(line)

        if (in_comment) {
          end = index(lower, "-->")
          if (!end) {
            line = ""
            break
          }
          line = substr(line, end + 3)
          in_comment = 0
          continue
        }

        if (in_script) {
          end = index(lower, "</script>")
          if (!end) {
            line = ""
            break
          }
          line = substr(line, end + 9)
          in_script = 0
          continue
        }

        if (in_style) {
          end = index(lower, "</style>")
          if (!end) {
            line = ""
            break
          }
          line = substr(line, end + 8)
          in_style = 0
          continue
        }

        if (in_svg) {
          end = index(lower, "</svg>")
          if (!end) {
            line = ""
            break
          }
          line = substr(line, end + 6)
          in_svg = 0
          continue
        }

        comment_pos = index(lower, "<!--")
        script_pos = index(lower, "<script")
        style_pos = index(lower, "<style")
        svg_pos = index(lower, "<svg")

        next_pos = 0
        next_kind = ""

        if (comment_pos && (!next_pos || comment_pos < next_pos)) {
          next_pos = comment_pos
          next_kind = "comment"
        }
        if (script_pos && (!next_pos || script_pos < next_pos)) {
          next_pos = script_pos
          next_kind = "script"
        }
        if (style_pos && (!next_pos || style_pos < next_pos)) {
          next_pos = style_pos
          next_kind = "style"
        }
        if (svg_pos && (!next_pos || svg_pos < next_pos)) {
          next_pos = svg_pos
          next_kind = "svg"
        }

        if (!next_pos) {
          emit_prefix(line)
          line = ""
          break
        }

        emit_prefix(substr(line, 1, next_pos - 1))
        line = substr(line, next_pos)
        lower = tolower(line)

        if (next_kind == "comment") {
          line = substr(line, 5)
          in_comment = 1
          continue
        }

        tag_end = index(lower, ">")
        if (!tag_end) {
          line = ""
          if (next_kind == "script") {
            in_script = 1
          } else if (next_kind == "style") {
            in_style = 1
          } else {
            in_svg = 1
          }
          break
        }

        line = substr(line, tag_end + 1)
        if (next_kind == "script") {
          in_script = 1
        } else if (next_kind == "style") {
          in_style = 1
        } else {
          in_svg = 1
        }
      }
    }
  ' "$input_file" >"$output_file"; then
    echo "[-] mklist: failed to strip HTML noise blocks: $input_file" >&2
    exit 1
  fi
}

filter_low_priority_html() {
  local input_file="$1"
  local output_file="$2"

  if ! awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function should_skip(tag, attrs, lower_attrs) {
      if (tag == "nav" || tag == "button" || tag == "label") {
        return 1
      }
      if (lower_attrs ~ /(^|[[:space:]])id[[:space:]]*=[[:space:]]*["\047]toast["\047]/) {
        return 1
      }
      if (lower_attrs ~ /(^|[[:space:]])class[[:space:]]*=[[:space:]]*["\047][^"\047]*(navbar|nav|toast|toast-header|toast-body|btn|btn-|form-label)[^"\047]*["\047]/) {
        return 1
      }
      return 0
    }
    BEGIN {
      skip_tag = ""
      skip_depth = 0
    }
    {
      line = $0
      while (match(line, /<[^>]+>/)) {
        prefix = substr(line, 1, RSTART - 1)
        if (skip_depth == 0 && trim(prefix) != "") {
          printf "%s\n", trim(prefix)
        }

        tag_text = substr(line, RSTART, RLENGTH)
        lower_tag = tolower(tag_text)
        line = substr(line, RSTART + RLENGTH)

        if (lower_tag ~ /^<!--/) {
          continue
        }

        if (lower_tag ~ /^<\//) {
          tag_name = lower_tag
          sub(/^<\//, "", tag_name)
          sub(/[[:space:]>].*$/, "", tag_name)
          if (skip_depth > 0 && tag_name == skip_tag) {
            skip_depth--
            if (skip_depth == 0) {
              skip_tag = ""
            }
          }
          continue
        }

        if (lower_tag ~ /^<!/) {
          continue
        }

        tag_name = lower_tag
        sub(/^</, "", tag_name)
        sub(/[[:space:]>\/].*$/, "", tag_name)
        self_closing = (lower_tag ~ /\/>$/)

        if (skip_depth > 0) {
          if (!self_closing && tag_name == skip_tag) {
            skip_depth++
          }
          continue
        }

        attrs = tag_text
        sub(/^<[[:alnum:]]+/, "", attrs)
        sub(/>$/, "", attrs)
        lower_attrs = tolower(attrs)

        if (should_skip(tag_name, attrs, lower_attrs)) {
          if (!self_closing) {
            skip_tag = tag_name
            skip_depth = 1
          }
          continue
        }
      }

      if (skip_depth == 0 && trim(line) != "") {
        printf "%s\n", trim(line)
      }
    }
  ' "$input_file" >"$output_file"; then
    echo "[-] mklist: failed to filter low-priority HTML: $input_file" >&2
    exit 1
  fi
}

filter_meaningful_lines() {
  local input_file="$1"
  local output_file="$2"

  if ! awk -v stopwords_file="$MKLIST_STOPWORDS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    BEGIN {
      while ((getline line < stopwords_file) > 0) {
        sub(/\r$/, "", line)
        if (line == "" || line ~ /^#/) continue
        kind = line
        sub(/[[:space:]].*$/, "", kind)
        rest = line
        sub(/^[^[:space:]]+[[:space:]]+/, "", rest)
        rest = tolower(trim(rest))
        if (kind == "token") token_stop[rest] = 1
        else if (kind == "phrase") phrase_stop[rest] = 1
      }
      close(stopwords_file)
    }
    {
      line = trim($0)
      gsub(/[[:space:]]+/, " ", line)
      if (line == "") next

      lower_line = tolower(line)
      gsub(/[^a-z0-9]+/, " ", lower_line)
      lower_line = trim(lower_line)
      if (lower_line in phrase_stop) next

      work = line
      gsub(/[^A-Za-z0-9]+/, " ", work)
      work = trim(work)
      n = split(work, parts, /[[:space:]]+/)
      keep = 0
      for (i = 1; i <= n; i++) {
        token = parts[i]
        lower = tolower(token)
        if (lower == "") continue
        if (token ~ /^[0-9]{4,8}$/) {
          keep = 1
          continue
        }
        if (!(lower in token_stop) && length(token) >= 2) {
          keep = 1
        }
      }
      if (keep) print line
    }
  ' "$input_file" >"$output_file"; then
    echo "[-] mklist: failed to filter meaningful lines: $input_file" >&2
    exit 1
  fi
}

filter_material_lines() {
  local input_file="$1"
  local output_file="$2"

  if ! awk -v stopwords_file="$MKLIST_STOPWORDS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function has_hint_term(lower_line,    normalized, count, i, parts, token) {
      normalized = lower_line
      gsub(/[^a-z]+/, " ", normalized)
      normalized = trim(normalized)
      count = split(normalized, parts, /[[:space:]]+/)
      for (i = 1; i <= count; i++) {
        token = parts[i]
        if (token ~ /^(keyword|password|pass|rule|tip|hint|strong|capitalize|uppercase|lowercase|year|number|append|suffix|prefix|symbol|mark|exclamation|capitalized)$/) {
          return 1
        }
      }
      return 0
    }
    BEGIN {
      while ((getline line < stopwords_file) > 0) {
        sub(/\r$/, "", line)
        if (line == "" || line ~ /^#/) continue
        kind = line
        sub(/[[:space:]].*$/, "", kind)
        rest = line
        sub(/^[^[:space:]]+[[:space:]]+/, "", rest)
        rest = tolower(trim(rest))
        if (kind == "token") token_stop[rest] = 1
        else if (kind == "phrase") phrase_stop[rest] = 1
      }
      close(stopwords_file)
    }
    {
      line = trim($0)
      gsub(/[[:space:]]+/, " ", line)
      if (line == "") next

      lower_line = tolower(line)
      normalized_line = lower_line
      gsub(/[^a-z0-9]+/, " ", normalized_line)
      normalized_line = trim(normalized_line)
      if (normalized_line in phrase_stop) next
      if (has_hint_term(lower_line)) next

      work = line
      gsub(/[^A-Za-z0-9_-]+/, " ", work)
      work = trim(work)
      if (work == "") next

      count = split(work, parts, /[[:space:]]+/)
      total = 0
      good = 0
      for (i = 1; i <= count; i++) {
        token = parts[i]
        lower = tolower(token)
        if (lower == "") continue
        total++
        if (token ~ /^[0-9]{4,8}$/) {
          good++
          continue
        }
        if (length(token) < 3 || length(token) > 24) continue
        if (lower in token_stop) continue
        good++
      }

      if (good == 0) next
      if (total >= 4 && good * 2 < total) next
      print line
    }
  ' "$input_file" >"$output_file"; then
    echo "[-] mklist: failed to filter material lines: $input_file" >&2
    exit 1
  fi
}

extract_material_words() {
  local input_file="$1"
  local output_file="$2"

  if ! awk -v stopwords_file="$MKLIST_STOPWORDS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    BEGIN {
      while ((getline line < stopwords_file) > 0) {
        sub(/\r$/, "", line)
        if (line == "" || line ~ /^#/) continue
        kind = line
        sub(/[[:space:]].*$/, "", kind)
        rest = line
        sub(/^[^[:space:]]+[[:space:]]+/, "", rest)
        rest = tolower(trim(rest))
        if (kind == "token") token_stop[rest] = 1
      }
      close(stopwords_file)
    }
    {
      line = $0
      gsub(/[^A-Za-z0-9_-]+/, " ", line)
      line = trim(line)
      if (line == "") next

      count = split(line, parts, /[[:space:]]+/)
      for (i = 1; i <= count; i++) {
        token = parts[i]
        lower = tolower(token)
        if (lower == "") continue
        if (token ~ /^[0-9]{4,8}$/) {
          print token
          continue
        }
        if (length(token) < 4 || length(token) > 24) continue
        if (lower in token_stop) continue
        print token
      }
    }
  ' "$input_file" >"$output_file"; then
    echo "[-] mklist: failed to extract material words: $input_file" >&2
    exit 1
  fi
}

extract_hint_material() {
  local input_file="$1"
  local hint_lines_file="$2"
  local hint_keywords_file="$3"
  local hint_rules_file="$4"

  : >"$hint_lines_file"
  : >"$hint_keywords_file"
  : >"$hint_rules_file"

  if ! awk -v stopwords_file="$MKLIST_STOPWORDS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function load_stopwords(    line, kind, rest) {
      while ((getline line < stopwords_file) > 0) {
        sub(/\r$/, "", line)
        if (line == "" || line ~ /^#/) continue
        kind = line
        sub(/[[:space:]].*$/, "", kind)
        rest = line
        sub(/^[^[:space:]]+[[:space:]]+/, "", rest)
        rest = tolower(trim(rest))
        if (kind == "token") token_stop[rest] = 1
      }
      close(stopwords_file)
    }
    function has_hint_term(lower_line,    normalized, count, i, parts, token) {
      normalized = lower_line
      gsub(/[^a-z]+/, " ", normalized)
      normalized = trim(normalized)
      count = split(normalized, parts, /[[:space:]]+/)
      for (i = 1; i <= count; i++) {
        token = parts[i]
        if (token ~ /^(keyword|password|pass|rule|tip|hint|strong|capitalize|uppercase|lowercase|year|number|append|suffix|prefix|symbol|mark|exclamation|capitalized)$/) {
          return 1
        }
      }
      return 0
    }
    function parse_flags(lower_line) {
      if (lower_line ~ /capitalize|capitalized/) rule_capitalize = 1
      if (lower_line ~ /uppercase/) rule_uppercase = 1
      if (lower_line ~ /lowercase/) rule_lowercase = 1
      if (lower_line ~ /year/) rule_year = 1
      if (lower_line ~ /number/) rule_number = 1
      if (lower_line ~ /append|suffix/) rule_append = 1
      if (lower_line ~ /prefix/) rule_prefix = 1
      if (lower_line ~ /symbol|mark|exclamation|!/) rule_symbol = 1
      if (lower_line ~ /exclamation|!/) rule_exclamation = 1
    }
    function add_keyword(token, lower) {
      lower = tolower(token)
      if (lower == "") return
      if (lower in token_stop) return
      if (lower ~ /^(ddmmyyyy|mmddyyyy|yyyymmdd)$/) return
      if (lower ~ /^(keyword|password|pass|rule|tip|strong|capitalize|capitalized|uppercase|lowercase|year|number|append|suffix|prefix|symbol|mark|exclamation)$/) return
      if (length(token) < 3 || length(token) > 24) return
      if (!(token ~ /^[A-Za-z][A-Za-z0-9_-]*$/)) return
      hint_keyword[lower] = token
    }
    function harvest_keywords(line,    cleaned, count, i, parts) {
      cleaned = line
      gsub(/[^A-Za-z0-9_-]+/, " ", cleaned)
      cleaned = trim(cleaned)
      count = split(cleaned, parts, /[[:space:]]+/)
      for (i = 1; i <= count; i++) add_keyword(parts[i])
    }
    function candidate_score(line,    cleaned, count, i, parts, token, lower, good) {
      cleaned = line
      gsub(/[^A-Za-z0-9_-]+/, " ", cleaned)
      cleaned = trim(cleaned)
      if (cleaned == "") return 0
      count = split(cleaned, parts, /[[:space:]]+/)
      if (count < 1 || count > 8) return 0
      good = 0
      for (i = 1; i <= count; i++) {
        token = parts[i]
        lower = tolower(token)
        if (lower == "") continue
        if (lower in token_stop) continue
        if (lower ~ /^(keyword|password|pass|rule|tip|hint|strong|capitalize|capitalized|uppercase|lowercase|year|number|append|suffix|prefix|symbol|mark|exclamation)$/) continue
        if (token ~ /^[0-9]+$/) continue
        if (length(token) < 3 || length(token) > 24) continue
        good++
      }
      return good
    }
    function harvest_candidate_line(line, lower_line,    score) {
      if (trim(line) == "") return
      if (has_hint_term(lower_line)) return
      score = candidate_score(line)
      if (score < 1) return
      harvest_keywords(line)
    }
    BEGIN {
      load_stopwords()
      rule_capitalize = rule_uppercase = rule_lowercase = 0
      rule_year = rule_number = rule_append = rule_prefix = 0
      rule_symbol = rule_exclamation = 0
    }
    {
      raw[NR] = $0
      lower[NR] = tolower($0)
    }
    END {
      for (i = 1; i <= NR; i++) {
        line = trim(raw[i])
        lower_line = lower[i]
        if (line == "") continue
        if (!has_hint_term(lower_line)) continue

        print line >> hint_lines_path
        parse_flags(lower_line)

        for (j = i - 2; j <= NR && j <= i + 4; j++) {
          if (j < 1 || j == i) continue
          nearby = trim(raw[j])
          if (nearby == "") continue
          if (length(nearby) > 120) continue
          harvest_candidate_line(nearby, lower[j])
        }
      }

      for (k in hint_keyword) {
        print hint_keyword[k] >> hint_keywords_path
      }

      print "MKLIST_HINT_CAPITALIZE=" rule_capitalize > hint_rules_path
      print "MKLIST_HINT_UPPERCASE=" rule_uppercase >> hint_rules_path
      print "MKLIST_HINT_LOWERCASE=" rule_lowercase >> hint_rules_path
      print "MKLIST_HINT_YEAR=" rule_year >> hint_rules_path
      print "MKLIST_HINT_NUMBER=" rule_number >> hint_rules_path
      print "MKLIST_HINT_APPEND=" rule_append >> hint_rules_path
      print "MKLIST_HINT_PREFIX=" rule_prefix >> hint_rules_path
      print "MKLIST_HINT_SYMBOL=" rule_symbol >> hint_rules_path
      print "MKLIST_HINT_EXCLAMATION=" rule_exclamation >> hint_rules_path
    }
  ' hint_lines_path="$hint_lines_file" hint_keywords_path="$hint_keywords_file" hint_rules_path="$hint_rules_file" "$input_file"; then
    echo "[-] mklist: failed to extract hint material: $input_file" >&2
    exit 1
  fi

  [[ -f "$hint_lines_file" ]] || : >"$hint_lines_file"
  [[ -f "$hint_keywords_file" ]] || : >"$hint_keywords_file"
  [[ -f "$hint_rules_file" ]] || : >"$hint_rules_file"
  sort -u "$hint_keywords_file" -o "$hint_keywords_file"
}

append_bootstrap_secondary_values() {
  local input_file="$1"
  local output_file="$2"

  awk '
    /class="[^"]*(text-secondary[[:space:]]+small|small[[:space:]]+text-secondary)[^"]*"/ {
      line = $0
      gsub(/<[^>]*>/, " ", line)
      gsub(/[[:space:]]+/, " ", line)
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$input_file" >>"$output_file"
}

extract_label_value_pairs() {
  local input_file="$1"
  local output_file="$2"

  if ! awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function extract_text(raw, text) {
      text = raw
      gsub(/<[^>]*>/, " ", text)
      gsub(/[[:space:]]+/, " ", text)
      return trim(text)
    }
    function is_label_line(lower) {
      return lower ~ /class="[^"]*(small[[:space:]]+text-secondary|text-secondary[[:space:]]+small|form-label)[^"]*"/
    }
    function is_value_line(lower) {
      return lower ~ /class="[^"]*(fw-semibold|fw-bold|form-control-plaintext)[^"]*"/
    }
    BEGIN {
      pending_label = ""
      pending_ttl = 0
    }
    {
      lower = tolower($0)
      text = extract_text($0)
      if (text == "") next

      if (pending_label != "") {
        pending_ttl--
        if (pending_ttl <= 0) {
          pending_label = ""
        }
      }

      if (is_label_line(lower)) {
        pending_label = text
        pending_ttl = 4
        next
      }

      if (pending_label != "" && is_value_line(lower)) {
        printf "%s\t%s\n", pending_label, text
        pending_label = ""
        pending_ttl = 0
        next
      }

      if (pending_label != "" && lower ~ /<\/div>/) {
        pending_label = ""
        pending_ttl = 0
      }
    }
  ' "$input_file" >"$output_file"; then
    echo "[-] mklist: failed to extract label/value pairs: $input_file" >&2
    exit 1
  fi
}

run_cewl() {
  echo "[*] Running CeWL..."

  if ! cewl -d 1 -m 4 "$MKLIST_INPUT" >"$MKLIST_RAW_FILE"; then
    echo "[-] mklist: CeWL failed for URL: $MKLIST_INPUT" >&2
    exit 1
  fi
}

load_html_file() {
  local stripped_file=""

  echo "[*] Loading HTML file..."

  if ! cat "$MKLIST_INPUT" >"$MKLIST_RAW_HTML_FILE"; then
    echo "[-] mklist: failed to copy HTML file: $MKLIST_INPUT" >&2
    exit 1
  fi

  stripped_file="$MKLIST_TMPDIR/clean.blocks"
  strip_noise_blocks "$MKLIST_RAW_HTML_FILE" "$stripped_file"
  filter_low_priority_html "$stripped_file" "$MKLIST_CLEAN_FILE"
  filter_meaningful_lines "$MKLIST_CLEAN_FILE" "$MKLIST_VALUE_LINES_FILE"
  append_bootstrap_secondary_values "$MKLIST_RAW_HTML_FILE" "$MKLIST_VALUE_LINES_FILE"
  filter_meaningful_lines "$MKLIST_VALUE_LINES_FILE" "$MKLIST_VALUE_LINES_FILE.tmp"
  mv "$MKLIST_VALUE_LINES_FILE.tmp" "$MKLIST_VALUE_LINES_FILE"
  sort -u "$MKLIST_VALUE_LINES_FILE" -o "$MKLIST_VALUE_LINES_FILE"
  extract_label_value_pairs "$MKLIST_RAW_HTML_FILE" "$MKLIST_PAIRS_FILE"
  extract_hint_material "$MKLIST_CLEAN_FILE" "$MKLIST_HINT_LINES_FILE" "$MKLIST_HINT_KEYWORDS_FILE" "$MKLIST_HINT_RULES_FILE"
  filter_material_lines "$MKLIST_VALUE_LINES_FILE" "$MKLIST_MATERIAL_LINES_FILE"

  if ! extract_material_words "$MKLIST_MATERIAL_LINES_FILE" "$MKLIST_RAW_FILE"; then
    echo "[-] mklist: failed to extract material words from HTML file: $MKLIST_INPUT" >&2
    exit 1
  fi
}

write_cache_meta() {
  cat >"$MKLIST_META_FILE" <<EOF
MKLIST_CACHE_VERSION_SAVED='$MKLIST_CACHE_VERSION'
MKLIST_CACHE_INPUT='$MKLIST_INPUT'
MKLIST_CACHE_INPUT_TYPE='$MKLIST_INPUT_TYPE'
MKLIST_CACHE_MODE='$MKLIST_MODE'
EOF
}

normalize_words() {
  echo "[*] Normalizing words..."

  sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$MKLIST_RAW_FILE" |
    sed '/^$/d' |
    awk '
      /^[[:space:]]*$/ { next }
      /^https?:\/\// { next }
      /@/ { next }
      /<[[:alnum:]!\/?][^>]*>/ { next }
      /^-?[0-9]+px$/ { next }
      /^-?[0-9]+rem$/ { next }
      /^-?[0-9]+em$/ { next }
      /^-?[0-9]+vh$/ { next }
      /^-?[0-9]+vw$/ { next }
      /^[0-9A-Fa-f]{6}$/ { next }
      /^[0-9A-Fa-f]{8}$/ { next }
      /^[0-9]+$/ {
        if (length($0) >= 4 && length($0) <= 8) {
          print $0
        }
        next
      }
      /^[A-Za-z0-9_-]+$/ {
        if (length($0) >= 4 && length($0) <= 24) {
          print $0
        }
      }
    ' |
    sort -u >"$MKLIST_BASE_FILE"
}

filter_stopwords() {
  local input_file="$1"
  local output_file="$2"

  awk -v stopwords_file="$MKLIST_STOPWORDS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    BEGIN {
      while ((getline line < stopwords_file) > 0) {
        sub(/\r$/, "", line)
        if (line == "" || line ~ /^#/) continue
        kind = line
        sub(/[[:space:]].*$/, "", kind)
        rest = line
        sub(/^[^[:space:]]+[[:space:]]+/, "", rest)
        rest = tolower(trim(rest))
        if (kind == "token") token_stop[rest] = 1
      }
      close(stopwords_file)
    }
    {
      token = tolower($0)
      if (token in token_stop) next
      print
    }
  ' "$input_file" >"$output_file"
}

append_compound_words() {
  local input_file="$1"
  local output_file="$2"

  awk -v stopwords_file="$MKLIST_STOPWORDS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    BEGIN {
      while ((getline line < stopwords_file) > 0) {
        sub(/\r$/, "", line)
        if (line == "" || line ~ /^#/) continue
        kind = line
        sub(/[[:space:]].*$/, "", kind)
        rest = line
        sub(/^[^[:space:]]+[[:space:]]+/, "", rest)
        rest = tolower(trim(rest))
        if (kind == "token") token_stop[rest] = 1
      }
      close(stopwords_file)
    }
    {
      line = $0
      gsub(/[^A-Za-z0-9]+/, " ", line)
      line = trim(line)
      count = split(line, parts, /[[:space:]]+/)
      kept = 0
      concat = ""
      concat_lower = ""
      for (i = 1; i <= count; i++) {
        token = parts[i]
        lower = tolower(token)
        if (token ~ /^[0-9]+$/) continue
        if (length(token) < 3) continue
        if (lower in token_stop) continue
        kept++
        concat = concat token
        concat_lower = concat_lower lower
      }
      if (kept >= 2) {
        print concat
        print concat_lower
      }
    }
  ' "$input_file" >>"$output_file"
}

extract_context_numbers() {
  local input_file="$1"
  local numbers_file="$2"
  local years_file="$3"

  : >"$numbers_file"
  : >"$years_file"

  awk '
    {
      line = $0
      gsub(/[^A-Za-z0-9]+/, " ", line)
      count = split(line, parts, /[[:space:]]+/)
      for (i = 1; i <= count; i++) {
        token = parts[i]
        if (token ~ /^[0-9]{4}$/) {
          print token >> numbers_out
          print token >> years_out
        } else if (token ~ /^[0-9]{8}$/) {
          print token >> numbers_out
          year = substr(token, 5, 4)
          if (year ~ /^(19|20)[0-9][0-9]$/) {
            print year >> years_out
          }
        }
      }
    }
  ' numbers_out="$numbers_file" years_out="$years_file" "$input_file"

  sort -u "$numbers_file" -o "$numbers_file"
  sort -u "$years_file" -o "$years_file"
}

generate_context_number_variants() {
  local input_file="$1"
  local numbers_file="$2"
  local years_file="$3"
  local output_file="$4"
  local word lower title num

  : >"$output_file"
  [[ -s "$numbers_file" || -s "$years_file" ]] || return 0

  while IFS= read -r word; do
    [[ -n "$word" ]] || continue
    [[ "$word" =~ ^[0-9]+$ ]] && continue
    lower="$(to_lower "$word")"
    title="$(to_title "$lower")"

    if [[ -s "$years_file" ]]; then
      while IFS= read -r num; do
        [[ -n "$num" ]] || continue
        printf '%s\n' "${word}${num}" "${lower}${num}" "${title}${num}" >>"$output_file"
      done <"$years_file"
    fi

    if [[ -s "$numbers_file" ]]; then
      while IFS= read -r num; do
        [[ -n "$num" ]] || continue
        [[ "${#num}" -eq 8 ]] || continue
        printf '%s\n' "${word}${num}" "${lower}${num}" "${title}${num}" >>"$output_file"
      done <"$numbers_file"
    fi
  done <"$input_file"
}

generate_label_date_variants() {
  local pairs_file="$1"
  local output_file="$2"

  awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function normalize_label(s, out) {
      out = tolower(s)
      gsub(/[^a-z0-9]+/, " ", out)
      gsub(/[[:space:]]+/, " ", out)
      return trim(out)
    }
    function add_name(raw, normalized, token_count, parts, i, joined, joined_lower) {
      normalized = trim(raw)
      if (normalized == "") return
      gsub(/[[:space:]]+/, " ", normalized)
      name_values[normalized] = 1

      token_count = split(normalized, parts, /[[:space:]]+/)
      joined = ""
      for (i = 1; i <= token_count; i++) {
        joined = joined parts[i]
      }
      if (joined != normalized) {
        name_values[joined] = 1
      }
      joined_lower = tolower(joined)
      if (joined_lower != "") {
        name_values[joined_lower] = 1
      }
    }
    function add_variant(name, suffix) {
      if (name != "" && suffix != "") {
        print name suffix
      }
    }
    BEGIN {
      dd = mm = yyyy = yy = m = d_full = d_tail = ""
    }
    {
      label = normalize_label($1)
      value = trim($2)
      if (label == "" || value == "") next

      if (label ~ /(^| )(birthdate|dob|date)( |$)/ && value ~ /^[0-9]{8}$/) {
        dd = substr(value, 1, 2)
        mm = substr(value, 3, 2)
        yyyy = substr(value, 5, 4)
        yy = substr(value, 7, 2)
        m = mm + 0
        d_full = dd + 0
        d_tail = substr(dd, 2, 1)
        next
      }

      if (label ~ /(^| )(surname|lastname|family name|familyname|first name|firstname|given name|givenname|nickname|fullname|full name)( |$)/) {
        add_name(value)
      }
    }
    END {
      if (yyyy == "" && yy == "" && dd == "" && mm == "") exit

      for (name in name_values) {
        add_variant(name, yyyy)
        add_variant(name, yy)
        add_variant(name, dd mm)
        add_variant(name, mm dd)
        add_variant(name, d_full m yy)
        add_variant(name, m d_full yy)
        add_variant(name, d_tail m yy)
        add_variant(name, m d_tail yy)
      }
    }
  ' FS=$'\t' "$pairs_file" | sort -u >"$output_file"
}

generate_hint_rule_variants() {
  local keywords_file="$1"
  local rules_file="$2"
  local output_file="$3"
  local hint_capitalize=0 hint_uppercase=0 hint_lowercase=0 hint_year=0 hint_number=0 hint_append=0 hint_symbol=0 hint_exclamation=0
  local word lower title upper year suffix

  : >"$output_file"
  [[ -s "$keywords_file" ]] || return 0
  [[ -f "$rules_file" ]] || return 0

  # shellcheck disable=SC1090
  . "$rules_file"
  hint_capitalize="${MKLIST_HINT_CAPITALIZE:-0}"
  hint_uppercase="${MKLIST_HINT_UPPERCASE:-0}"
  hint_lowercase="${MKLIST_HINT_LOWERCASE:-0}"
  hint_year="${MKLIST_HINT_YEAR:-0}"
  hint_number="${MKLIST_HINT_NUMBER:-0}"
  hint_append="${MKLIST_HINT_APPEND:-0}"
  hint_symbol="${MKLIST_HINT_SYMBOL:-0}"
  hint_exclamation="${MKLIST_HINT_EXCLAMATION:-0}"

  while IFS= read -r word; do
    [[ -n "$word" ]] || continue
    lower="$(to_lower "$word")"
    title="$(to_title "$lower")"
    upper="$(to_upper "$word")"

    if [[ "$hint_lowercase" -eq 1 ]]; then
      printf '%s\n' "$lower" >>"$output_file"
    fi
    if [[ "$hint_capitalize" -eq 1 ]]; then
      printf '%s\n' "$title" >>"$output_file"
    fi
    if [[ "$hint_uppercase" -eq 1 ]]; then
      printf '%s\n' "$upper" >>"$output_file"
    fi

    if [[ "$hint_number" -eq 1 ]]; then
      printf '%s\n' "${lower}1" "${lower}12" "${lower}123" "${lower}1234" >>"$output_file"
      if [[ "$hint_capitalize" -eq 1 ]]; then
        printf '%s\n' "${title}1" "${title}12" "${title}123" "${title}1234" >>"$output_file"
      fi
      if [[ "$hint_uppercase" -eq 1 ]]; then
        printf '%s\n' "${upper}1" "${upper}12" "${upper}123" "${upper}1234" >>"$output_file"
      fi
    fi

    if [[ "$hint_year" -eq 1 ]]; then
      for year in 2024 2025 2026; do
        printf '%s\n' "${lower}${year}" >>"$output_file"
        if [[ "$hint_capitalize" -eq 1 ]]; then
          printf '%s\n' "${title}${year}" >>"$output_file"
        fi
        if [[ "$hint_uppercase" -eq 1 ]]; then
          printf '%s\n' "${upper}${year}" >>"$output_file"
        fi
        if [[ "$hint_exclamation" -eq 1 || "$hint_symbol" -eq 1 ]]; then
          printf '%s\n' "${lower}${year}!" >>"$output_file"
          if [[ "$hint_capitalize" -eq 1 ]]; then
            printf '%s\n' "${title}${year}!" >>"$output_file"
          fi
          if [[ "$hint_uppercase" -eq 1 ]]; then
            printf '%s\n' "${upper}${year}!" >>"$output_file"
          fi
        fi
      done
    fi

    if [[ "$hint_exclamation" -eq 1 || "$hint_symbol" -eq 1 ]]; then
      printf '%s\n' "${lower}!" >>"$output_file"
      if [[ "$hint_capitalize" -eq 1 ]]; then
        printf '%s\n' "${title}!" >>"$output_file"
      fi
      if [[ "$hint_uppercase" -eq 1 ]]; then
        printf '%s\n' "${upper}!" >>"$output_file"
      fi
    fi

    if [[ "$hint_append" -eq 1 && "$hint_number" -eq 1 && ("$hint_exclamation" -eq 1 || "$hint_symbol" -eq 1) ]]; then
      for suffix in 123 1234; do
        printf '%s\n' "${lower}${suffix}!" >>"$output_file"
        if [[ "$hint_capitalize" -eq 1 ]]; then
          printf '%s\n' "${title}${suffix}!" >>"$output_file"
        fi
      done
    fi
  done <"$keywords_file"

  sort -u "$output_file" -o "$output_file"
}

load_seed() {
  if [[ -z "$MKLIST_SEED" ]]; then
    return 0
  fi

  sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$MKLIST_SEED" |
    sed '/^$/d' |
    awk '
      /^[[:space:]]*$/ { next }
      /^https?:\/\// { next }
      /@/ { next }
      /<[[:alnum:]!\/?][^>]*>/ { next }
      /^-?[0-9]+px$/ { next }
      /^-?[0-9]+rem$/ { next }
      /^-?[0-9]+em$/ { next }
      /^-?[0-9]+vh$/ { next }
      /^-?[0-9]+vw$/ { next }
      /^[0-9A-Fa-f]{6}$/ { next }
      /^[0-9A-Fa-f]{8}$/ { next }
      /^[0-9]+$/ {
        if (length($0) >= 4 && length($0) <= 8) {
          print $0
        }
        next
      }
      /^[A-Za-z0-9_-]+$/ {
        if (length($0) >= 4 && length($0) <= 24) {
          print $0
        }
      }
    ' >>"$MKLIST_BASE_FILE"

  sort -u "$MKLIST_BASE_FILE" -o "$MKLIST_BASE_FILE"
}

generate_base_variants() {
  local input_file="$1"
  local output_file="$2"
  local word lower title upper

  : >"$output_file"
  while IFS= read -r word; do
    [[ -n "$word" ]] || continue
    lower="$(to_lower "$word")"
    upper="$(to_upper "$word")"
    title="$(to_title "$lower")"

    printf '%s\n%s\n%s\n' "$lower" "$title" "$upper" >>"$output_file"
  done <"$input_file"
}

generate_number_variants() {
  local input_file="$1"
  local output_file="$2"
  local word lower title

  : >"$output_file"
  while IFS= read -r word; do
    [[ -n "$word" ]] || continue
    lower="$(to_lower "$word")"
    title="$(to_title "$lower")"

    printf '%s\n' \
      "${lower}1" \
      "${lower}12" \
      "${lower}123" \
      "${lower}1234" \
      "${title}123" \
      "${title}123!" >>"$output_file"
  done <"$input_file"
}

generate_year_variants() {
  local input_file="$1"
  local output_file="$2"
  local word lower title

  : >"$output_file"
  while IFS= read -r word; do
    [[ -n "$word" ]] || continue
    lower="$(to_lower "$word")"
    title="$(to_title "$lower")"

    printf '%s\n' \
      "${lower}2024" \
      "${lower}2025" \
      "${lower}2026" \
      "${title}2026!" >>"$output_file"
  done <"$input_file"
}

generate_symbol_variants() {
  local input_file="$1"
  local output_file="$2"
  local word lower

  : >"$output_file"
  while IFS= read -r word; do
    [[ -n "$word" ]] || continue
    lower="$(to_lower "$word")"

    printf '%s\n' \
      "${lower}!" \
      "${lower}@" \
      "${lower}#" \
      "${lower}123!" \
      "${lower}2026!" >>"$output_file"
  done <"$input_file"
}

generate_common_passwords() {
  local output_file="$1"

  cat >"$output_file" <<'EOF'
password
password1
password123
Password123
Password123!
admin
admin123
administrator
welcome
welcome123
changeme
qwerty
letmein
EOF
}

generate_pin_list() {
  local output_file="$1"

  : >"$output_file"
  [[ -n "$MKLIST_PIN" ]] || return 0

  echo "[*] Generating PINs..."

  if ! command -v crunch >/dev/null 2>&1; then
    echo "[!] crunch not found; skipping PIN generation" >&2
    return 0
  fi

  if ! crunch "$MKLIST_PIN" "$MKLIST_PIN" 0123456789 >"$output_file"; then
    echo "[-] mklist: crunch failed for --pin $MKLIST_PIN" >&2
    exit 1
  fi
}

merge_results() {
  local final_file="$1"
  shift

  cat "$@" |
    awk 'length($0) >= 4 && length($0) <= 32 && $0 != ""' |
    sort -u |
    awk -v max_lines="$MKLIST_MAX_LINES" 'NR <= max_lines { print }' >"$final_file"
}

write_output() {
  local generated_file="$1"

  echo "[*] Writing output..."

  if ! cat "$generated_file" >"$MKLIST_OUTPUT_FILE"; then
    echo "[-] mklist: cannot write output file: $MKLIST_OUTPUT_FILE" >&2
    exit 1
  fi

  MKLIST_ENTRY_COUNT="$(awk 'END { print NR + 0 }' "$MKLIST_OUTPUT_FILE")"
  echo "[+] Output : $MKLIST_OUTPUT_FILE"
  echo "[+] Entries: $MKLIST_ENTRY_COUNT"
}

main() {
  local base_variants_file=""
  local number_variants_file=""
  local year_variants_file=""
  local symbol_variants_file=""
  local common_passwords_file=""
  local pin_file=""
  local context_number_variants_file=""
  local label_date_variants_file=""
  local hint_rule_variants_file=""
  local merged_file=""

  check_dependencies
  parse_arguments "$@"
  check_input_dependencies
  init_paths
  MKLIST_TMPDIR="$(mktemp -d)"
  trap cleanup EXIT INT TERM
  load_cache

  if [[ "$MKLIST_REFRESH" -eq 1 || ! -s "$MKLIST_RAW_FILE" || "${MKLIST_CACHE_INPUT:-}" != "$MKLIST_INPUT" || "${MKLIST_CACHE_INPUT_TYPE:-}" != "$MKLIST_INPUT_TYPE" || "${MKLIST_CACHE_VERSION_SAVED:-}" != "$MKLIST_CACHE_VERSION" ]]; then
    case "$MKLIST_INPUT_TYPE" in
      url)
        run_cewl
        ;;
      html)
        load_html_file
        ;;
    esac
    write_cache_meta
  fi

  normalize_words
  filter_stopwords "$MKLIST_BASE_FILE" "$MKLIST_BASE_FILE.tmp"
  mv "$MKLIST_BASE_FILE.tmp" "$MKLIST_BASE_FILE"
  if [[ "$MKLIST_INPUT_TYPE" == "html" && -s "$MKLIST_MATERIAL_LINES_FILE" ]]; then
    append_compound_words "$MKLIST_MATERIAL_LINES_FILE" "$MKLIST_BASE_FILE"
    sort -u "$MKLIST_BASE_FILE" -o "$MKLIST_BASE_FILE"
    extract_context_numbers "$MKLIST_MATERIAL_LINES_FILE" "$MKLIST_CONTEXT_NUMBERS_FILE" "$MKLIST_CONTEXT_YEARS_FILE"
    if [[ -s "$MKLIST_HINT_KEYWORDS_FILE" ]]; then
      cat "$MKLIST_HINT_KEYWORDS_FILE" >>"$MKLIST_BASE_FILE"
      sort -u "$MKLIST_BASE_FILE" -o "$MKLIST_BASE_FILE"
    fi
  else
    : >"$MKLIST_CONTEXT_NUMBERS_FILE"
    : >"$MKLIST_CONTEXT_YEARS_FILE"
  fi
  load_seed

  base_variants_file="$MKLIST_TMPDIR/base_variants.txt"
  number_variants_file="$MKLIST_TMPDIR/number_variants.txt"
  year_variants_file="$MKLIST_TMPDIR/year_variants.txt"
  symbol_variants_file="$MKLIST_TMPDIR/symbol_variants.txt"
  common_passwords_file="$MKLIST_TMPDIR/common_passwords.txt"
  pin_file="$MKLIST_TMPDIR/pins.txt"
  context_number_variants_file="$MKLIST_TMPDIR/context_number_variants.txt"
  label_date_variants_file="$MKLIST_TMPDIR/label_date_variants.txt"
  hint_rule_variants_file="$MKLIST_TMPDIR/hint_rule_variants.txt"
  merged_file="$MKLIST_TMPDIR/passwords.txt"

  echo "[*] Generating passwords..."
  generate_base_variants "$MKLIST_BASE_FILE" "$base_variants_file"
  generate_number_variants "$MKLIST_BASE_FILE" "$number_variants_file"
  generate_year_variants "$MKLIST_BASE_FILE" "$year_variants_file"
  generate_symbol_variants "$MKLIST_BASE_FILE" "$symbol_variants_file"
  generate_common_passwords "$common_passwords_file"
  generate_pin_list "$pin_file"
  generate_context_number_variants "$MKLIST_BASE_FILE" "$MKLIST_CONTEXT_NUMBERS_FILE" "$MKLIST_CONTEXT_YEARS_FILE" "$context_number_variants_file"
  if [[ "$MKLIST_INPUT_TYPE" == "html" && -s "$MKLIST_PAIRS_FILE" ]]; then
    generate_label_date_variants "$MKLIST_PAIRS_FILE" "$label_date_variants_file"
  else
    : >"$label_date_variants_file"
  fi
  if [[ "$MKLIST_INPUT_TYPE" == "html" && -s "$MKLIST_HINT_KEYWORDS_FILE" ]]; then
    generate_hint_rule_variants "$MKLIST_HINT_KEYWORDS_FILE" "$MKLIST_HINT_RULES_FILE" "$hint_rule_variants_file"
  else
    : >"$hint_rule_variants_file"
  fi
  merge_results \
    "$merged_file" \
    "$MKLIST_BASE_FILE" \
    "$base_variants_file" \
    "$number_variants_file" \
    "$year_variants_file" \
    "$symbol_variants_file" \
    "$common_passwords_file" \
    "$pin_file" \
    "$context_number_variants_file" \
    "$label_date_variants_file" \
    "$hint_rule_variants_file"
  write_output "$merged_file"
}

main "$@"
