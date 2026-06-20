# ========================
# repolog — clone mirror + full git history → commit URLs / email audit
# ========================

_repolog-usage() {
  cat <<'EOF'
usage: repolog [-o path] [-q] [-F] [-U] [-M] [-S] <repo-url> ...
       repolog [-o dir] [-q] [-F] [-U] [-M] [-S] -f <url-list-file>
       repolog [-u <github-user>] [-l] [--forks] [-o list-file] [other flags...]
       repolog <@github-user> ...

  Thorough commit enumeration: mirror clone (all refs) → git log --all --date-order.
  Mirrors live under cases/<room>/exports/repolog/ (cases set required).
  Re-run fetches into the existing mirror — no redundant full clone.

  <repo-url>  https://github.com/o/r , git@github.com:o/r.git , o/r (GitHub shorthand)
  <@user>     @name or bare github username → same as -u / --user

options:
  -u, --user U  fetch repos for GitHub user U (type=owner; forks excluded)
  --forks    with --user: include forked repos
  -l         with --user: fetch repo list only (no mirror / scan)
  -o path   report path, or with --user: repo list file (default: github_repos.txt)
  -q        print report path(s) only
  -F        fresh mirror (rm + re-clone); default is fetch if mirror exists
  -U        stdout: one commit URL per line (no Markdown)
  -M        stdout: unique name+email pairs (author + committer); batch merges & dedupes
  -S        with -M: only non-noreply emails (personal / check)
  -R        with -M: prefix each line with repo name (owner/repo)
  -f file   one URL per line (# comments and blanks skipped)

mirror path (always kept):
  cases/<room>/exports/repolog/<host>_<owner>_<repo>.git

examples:
  cases set myroom
  repolog -u sakurasnowangelaiko
  repolog @sakurasnowangelaiko -M -S
  repolog sakurasnowangelaiko -l
  repolog --user someuser --forks
  repolog https://github.com/user/project
  repolog -F user/repo
  repolog -M -f github_repos.txt
EOF
}

# stdout: host owner repo web_base clone_url  (tab-separated)
_repolog-parse-url() {
  local raw="$1" url host owner repo web_base clone_url

  url="${raw%%#*}"
  url="${url//[[:space:]]/}"
  [[ -n "$url" ]] || return 1

  url="${url%.git}"
  url="${url%/}"

  if [[ "$url" =~ '^git@github\.com:([^/]+)/(.+)$' ]]; then
    host=github
    owner="${match[1]}"
    repo="${match[2]}"
  elif [[ "$url" =~ '^https?://github\.com/([^/]+)/([^/?#]+)' ]]; then
    host=github
    owner="${match[1]}"
    repo="${match[2]}"
  elif [[ "$url" =~ '^git@gitlab\.com:([^/]+)/(.+)$' ]]; then
    host=gitlab
    owner="${match[1]}"
    repo="${match[2]}"
  elif [[ "$url" =~ '^https?://gitlab\.com/([^/]+)/([^/?#]+)' ]]; then
    host=gitlab
    owner="${match[1]}"
    repo="${match[2]}"
  elif [[ "$url" =~ '^([^/]+)/([^/]+)$' ]]; then
    host=github
    owner="${match[1]}"
    repo="${match[2]}"
  else
    echo "[-] repolog: cannot parse repo URL: $raw" >&2
    return 1
  fi

  case "$host" in
    github)
      web_base="https://github.com/${owner}/${repo}"
      clone_url="${web_base}.git"
      ;;
    gitlab)
      web_base="https://gitlab.com/${owner}/${repo}"
      clone_url="${web_base}.git"
      ;;
  esac

  print -r -- "${host}"$'\t'"${owner}"$'\t'"${repo}"$'\t'"${web_base}"$'\t'"${clone_url}"
}

_repolog-commit-url() {
  local host="$1" web_base="$2" sha="$3"
  case "$host" in
    github) print -r -- "${web_base}/commit/${sha}" ;;
    gitlab) print -r -- "${web_base}/-/commit/${sha}" ;;
    *)      print -r -- "$sha" ;;
  esac
}

_repolog-mirror-path() {
  local host="$1" owner="$2" repo="$3" home
  home="$(case-exports-dir 2>/dev/null)" || return 1
  print -r -- "${home}/repolog/${host}_${owner}_${repo}.git"
}

_repolog-repolog-dir() {
  local home
  home="$(case-exports-dir 2>/dev/null)" || return 1
  mkdir -p "${home}/repolog"
  print -r -- "${home}/repolog"
}

_repolog-out-path() {
  local repo="$1" out="${2:-}"
  if [[ -n "$out" && -d "$out" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    print -r -- "${out%/}/${repo}_repolog_${ts}.md"
    return 0
  fi
  if [[ -n "$out" ]]; then
    print -r -- "$out"
    return 0
  fi
  local home ts
  if home="$(case-exports-dir 2>/dev/null)"; then
    ts="$(date +%Y%m%d-%H%M%S)"
    print -r -- "${home}/${repo}_repolog_${ts}.md"
    return 0
  fi
  ts="$(date +%Y%m%d-%H%M%S)"
  print -r -- "./${repo}_repolog_${ts}.md"
}

# stdout: github-noreply | noreply | check
_repolog-email-flag() {
  local email="${1,,}"
  [[ -n "$email" ]] || return 0
  if [[ "$email" == *@users.noreply.github.com ]]; then
    print -r -- "github-noreply"
    return 0
  fi
  if [[ "$email" == *noreply* ]]; then
    print -r -- "noreply"
    return 0
  fi
  print -r -- "check"
}

# stdout: unique "name<TAB>email" from mirror (author + committer)
_repolog-identities-from-mirror() {
  local mirror="$1"
  git -C "$mirror" log --all \
    --pretty=format:'%an%x1f%ae%n%cn%x1f%ce' 2>/dev/null \
    | awk -F'\x1f' 'NF>=2 && $2!="" {print $1 "\t" $2}' \
    | sort -u
}

_repolog-format-person() {
  local name="$1" email="$2"
  if [[ -n "$name" && -n "$email" ]]; then
    print -r -- "${name} <${email}>"
  elif [[ -n "$email" ]]; then
    print -r -- "<${email}>"
  else
    print -r -- "$name"
  fi
}

_repolog-identities-out-path() {
  local repo="$1" out="${2:-}"
  if [[ -n "$out" ]]; then
    print -r -- "$out"
    return 0
  fi
  local home ts
  if home="$(case-exports-dir 2>/dev/null)"; then
    ts="$(date +%Y%m%d-%H%M%S)"
    print -r -- "${home}/${repo}_idents_${ts}.txt"
    return 0
  fi
  ts="$(date +%Y%m%d-%H%M%S)"
  print -r -- "./${repo}_idents_${ts}.txt"
}

_repolog-sync-mirror() {
  local clone_url="$1" dest="$2" fresh="$3"
  command -v git >/dev/null 2>&1 || {
    echo "[-] repolog: git not found" >&2
    return 1
  }

  mkdir -p "${dest:h}"

  if [[ -d "$dest" ]]; then
    if [[ "$fresh" == true ]]; then
      echo "[*] repolog: fresh mirror clone → $dest" >&2
      rm -rf "$dest"
      GIT_TERMINAL_PROMPT=0 git clone --mirror --quiet "$clone_url" "$dest" || {
        echo "[-] repolog: clone failed: $clone_url" >&2
        return 1
      }
      return 0
    fi
    echo "[*] repolog: fetch --all --prune → $dest" >&2
    git -C "$dest" fetch --all --prune --quiet || return 1
    return 0
  fi

  echo "[*] repolog: mirror clone → $dest" >&2
  GIT_TERMINAL_PROMPT=0 git clone --mirror --quiet "$clone_url" "$dest" || {
    echo "[-] repolog: clone failed: $clone_url" >&2
    return 1
  }
}

# Print name+email from mirror. suspect=true → non-noreply only. repo_tag → prefix repo.
_repolog-print-identities() {
  local mirror="$1" suspect="$2" repo_tag="${3:-}"
  local name email flag

  while IFS=$'\t' read -r name email; do
    [[ -n "$email" ]] || continue
    if [[ "$suspect" == true ]]; then
      flag="$(_repolog-email-flag "$email")"
      [[ "$flag" == check ]] || continue
    fi
    if [[ -n "$repo_tag" ]]; then
      print -r -- "${repo_tag}"$'\t'"${name}"$'\t'"${email}"
    else
      print -r -- "${name}"$'\t'"${email}"
    fi
  done < <(_repolog-identities-from-mirror "$mirror")
}

# One repo: mirror path must exist. Writes report or URLs/emails to stdout.
_repolog-emit() {
  local mirror="$1" host="$2" web_base="$3" repo_name="$4"
  local report="$5" urls_only="$6" emails_only="$7" quiet="$8"
  local suspect="$9" repo_tag="${10:-}"

  local ref_summary n_commits n_refs

  ref_summary="$(git -C "$mirror" for-each-ref --format='%(refname:short)' refs/heads refs/tags 2>/dev/null | sort)"
  n_refs="$(print -r -- "$ref_summary" | grep -c . 2>/dev/null || echo 0)"
  n_commits="$(git -C "$mirror" rev-list --all --count 2>/dev/null || echo 0)"

  if [[ "$urls_only" == true ]]; then
    while IFS= read -r sha; do
      [[ -n "$sha" ]] || continue
      _repolog-commit-url "$host" "$web_base" "$sha"
    done < <(git -C "$mirror" log --all --date-order --pretty=format:'%H' 2>/dev/null)
    return 0
  fi

  if [[ "$emails_only" == true ]]; then
    _repolog-print-identities "$mirror" "$suspect" "$repo_tag"
    return 0
  fi

  mkdir -p "${report:h}"
  $quiet || echo "[*] repolog: writing $report ($n_commits commits, $n_refs refs)" >&2

  {
    print -r -- "# repolog: ${repo_name}"
    print -r -- ""
    print -r -- "- source: ${web_base}"
    print -r -- "- generated: $(date -Iseconds 2>/dev/null || date)"
    print -r -- "- commits: ${n_commits}"
    print -r -- "- refs (branches + tags): ${n_refs}"
    print -r -- ""
    print -r -- "## refs"
    print -r -- ""
    if [[ -n "$ref_summary" ]]; then
      print -r -- '```'
      print -r -- "$ref_summary"
      print -r -- '```'
    else
      print -r -- "(none)"
    fi
    print -r -- ""
    print -r -- "## commits (chronological, all refs)"
    print -r -- ""
    print -r -- "| date | commit | author | committer | subject |"
    print -r -- "|------|--------|--------|-----------|---------|"

    while IFS=$'\t' read -r sha an ae cn ce ad subj; do
      [[ -n "$sha" ]] || continue
      curl="$(_repolog-commit-url "$host" "$web_base" "$sha")"
      author="$(_repolog-format-person "$an" "$ae")"
      committer="$(_repolog-format-person "$cn" "$ce")"
      subj="${subj//|/\\|}"
      print -r -- "| ${ad} | [${sha:0:7}](${curl}) | ${author} | ${committer} | ${subj} |"
    done < <(git -C "$mirror" log --all --date-order \
      --pretty=format:'%H%x09%an%x09%ae%x09%cn%x09%ce%x09%ad%x09%s' \
      --date=short 2>/dev/null)

    print -r -- ""
    print -r -- "## unique identities (name + email)"
    print -r -- ""
    print -r -- "| name | email | note |"
    print -r -- "|------|-------|------|"

    while IFS=$'\t' read -r name email; do
      [[ -n "$email" ]] || continue
      note="$(_repolog-email-flag "$email")"
      name="${name//|/\\|}"
      print -r -- "| ${name} | ${email} | ${note} |"
    done < <(_repolog-identities-from-mirror "$mirror")
  } >"$report"

  $quiet || print -r -- "$report"
}

# stdout: github username
_repolog-github-user-parse() {
  local raw="$1" user

  user="${raw%%#*}"
  user="${user%%\?*}"
  user="${user//[[:space:]]/}"
  user="${user%/}"

  if [[ "$user" =~ '(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)' ]]; then
    print -r -- "${match[1]}"
    return 0
  fi
  if [[ "$user" =~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$' ]]; then
    print -r -- "$user"
    return 0
  fi

  echo "[-] repolog: invalid GitHub user: $raw" >&2
  return 1
}

# stdout: github username if arg is @user or bare username (not owner/repo)
_repolog-arg-github-user() {
  local arg="$1" user

  if [[ "$arg" =~ '^@([A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?)$' ]]; then
    print -r -- "${match[1]}"
    return 0
  fi

  if [[ "$arg" == */* || "$arg" == *://* || "$arg" == git@* ]]; then
    return 1
  fi

  user="$(_repolog-github-user-parse "$arg")" || return 1
  print -r -- "$user"
}

# stdout: one repo URL per line
_repolog-github-fetch-repos() {
  local user="$1" include_forks="$2"
  python3 - "$user" "$include_forks" <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

user = sys.argv[1]
include_forks = sys.argv[2] == "true"
headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "kali-linux-repolog",
}
token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
if token:
    headers["Authorization"] = f"Bearer {token}"

urls = []
page = 1
while True:
    api = (
        f"https://api.github.com/users/{user}/repos"
        f"?type=owner&per_page=100&page={page}"
    )
    req = urllib.request.Request(api, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        print(f"[-] GitHub API HTTP {e.code}: {body[:200]}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] GitHub API error: {e}", file=sys.stderr)
        sys.exit(1)

    if not data:
        break
    for repo in data:
        if include_forks or not repo.get("fork"):
            urls.append(repo["html_url"])
    if len(data) < 100:
        break
    page += 1

for url in urls:
    print(url)
PY
}

repolog() {
  local fresh=false urls_only=false emails_only=false suspect=false repo_tag=false
  local list_only=false include_forks=false
  local quiet=false
  local out="" list_file="" email_accum="" gh_user=""
  local -a urls=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        _repolog-usage
        return 0
        ;;
      -u|--user)
        [[ -n "${2:-}" ]] || {
          echo "[-] repolog: -u requires github username" >&2
          return 1
        }
        gh_user="$2"
        shift 2
        ;;
      --forks)
        include_forks=true
        shift
        ;;
      -l|--list-only)
        list_only=true
        shift
        ;;
      -F|--fresh)
        fresh=true
        shift
        ;;
      -k|--keep|--update)
        # deprecated: mirrors are always kept under cases/<room>/exports/repolog/
        shift
        ;;
      -U|--urls-only)
        urls_only=true
        shift
        ;;
      -M|--emails-only)
        emails_only=true
        shift
        ;;
      -S|--suspect)
        suspect=true
        shift
        ;;
      -R|--repo-tag)
        repo_tag=true
        shift
        ;;
      -q|--quiet)
        quiet=true
        shift
        ;;
      -o|--output)
        out="$2"
        shift 2
        ;;
      -f|--file)
        list_file="$2"
        shift 2
        ;;
      --)
        shift
        urls+=("$@")
        break
        ;;
      -*)
        echo "[-] unknown option: $1  (try: repolog -h)" >&2
        return 1
        ;;
      *)
        if [[ -z "$gh_user" ]] && user="$(_repolog-arg-github-user "$1" 2>/dev/null)"; then
          if [[ ${#urls[@]} -gt 0 ]]; then
            echo "[-] repolog: cannot mix repo URLs with github user ($1)" >&2
            return 1
          fi
          gh_user="$user"
        else
          urls+=("$1")
        fi
        shift
        ;;
    esac
  done

  if [[ -n "$gh_user" && ${#urls[@]} -gt 0 ]]; then
    echo "[-] repolog: cannot mix --user with repo URLs" >&2
    return 1
  fi

  if [[ -n "$list_file" ]]; then
    [[ -r "$list_file" ]] || {
      echo "[-] repolog: cannot read: $list_file" >&2
      return 1
    }
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line//[[:space:]]/}"
      [[ -n "$line" ]] && urls+=("$line")
    done <"$list_file"
  fi

  if [[ -n "$gh_user" ]]; then
    _repolog-repolog-dir >/dev/null || {
      echo "[-] repolog: cases set <room> required (mirror → cases/<room>/exports/repolog/)" >&2
      return 1
    }

    gh_user="$(_repolog-github-user-parse "$gh_user")" || return 1

    local list_save="$out" repos count
    if [[ -z "$list_save" ]]; then
      list_save="${CASE_HOME:-.}/github_repos.txt"
    fi

    $quiet || echo "[*] repolog: fetching repos for ${gh_user} (forks=${include_forks})" >&2

    repos="$(_repolog-github-fetch-repos "$gh_user" "$include_forks")" || return 1
    if [[ -z "$repos" ]]; then
      echo "[-] repolog: no repos matched for ${gh_user}" >&2
      return 1
    fi

    mkdir -p "${list_save:h}"
    print -r -- "$repos" >"$list_save"
    count="$(print -r -- "$repos" | grep -c .)"
    $quiet || echo "[+] ${count} repos → ${list_save}" >&2

    if [[ "$list_only" == true ]]; then
      return 0
    fi

    list_file="$list_save"
    urls=()
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line//[[:space:]]/}"
      [[ -n "$line" ]] && urls+=("$line")
    done <"$list_file"
    out=""
  fi

  [[ ${#urls[@]} -gt 0 ]] || {
    _repolog-usage >&2
    return 1
  }

  if [[ "$list_only" == true ]]; then
    echo "[-] repolog: -l requires --user" >&2
    return 1
  fi

  _repolog-repolog-dir >/dev/null || {
    echo "[-] repolog: cases set <room> required (mirror → cases/<room>/exports/repolog/)" >&2
    return 1
  }

  if [[ "$suspect" == true && "$emails_only" != true ]]; then
    echo "[-] repolog: -S requires -M" >&2
    return 1
  fi
  if [[ "$repo_tag" == true && "$emails_only" != true ]]; then
    echo "[-] repolog: -R requires -M" >&2
    return 1
  fi
  if [[ "$urls_only" == true && "$emails_only" == true ]]; then
    echo "[-] repolog: -U and -M are mutually exclusive" >&2
    return 1
  fi

  if [[ ${#urls[@]} -gt 1 && -n "$out" && "$out" != */ && ! -d "$out" && "$emails_only" != true ]]; then
    echo "[-] repolog: -o with multiple repos must be a directory (or omit -o)" >&2
    return 1
  fi

  if [[ "$emails_only" == true && ${#urls[@]} -gt 1 ]]; then
    email_accum="$(_repolog-repolog-dir)/_batch_accum.$$"
    : >"$email_accum"
  fi

  local u rc=0 batch_out=""
  if [[ ${#urls[@]} -gt 1 && -z "$out" && "$emails_only" != true ]]; then
    batch_out="$(case-exports-dir 2>/dev/null || echo ".")"
  elif [[ -d "$out" ]]; then
    batch_out="$out"
  fi

  for u in "${urls[@]}"; do
    local parsed host owner repo web_base clone_url
    parsed="$(_repolog-parse-url "$u")" || { rc=1; continue }

    IFS=$'\t' read -r host owner repo web_base clone_url <<<"$parsed"

    local mirror one_out="$out" tag=""
    [[ -n "$batch_out" ]] && one_out="$batch_out"
    [[ "$repo_tag" == true ]] && tag="${owner}/${repo}"

    mirror="$(_repolog-mirror-path "$host" "$owner" "$repo")" || {
      rc=1
      continue
    }
    _repolog-sync-mirror "$clone_url" "$mirror" "$fresh" || { rc=1; continue }

    if [[ "$emails_only" == true ]]; then
      if [[ -n "$email_accum" ]]; then
        _repolog-emit "$mirror" "$host" "$web_base" "$repo" "" false true "$quiet" \
          "$suspect" "$tag" >>"$email_accum" || rc=1
      elif [[ -n "$out" ]]; then
        local email_file
        email_file="$(_repolog-identities-out-path "$repo" "$out")"
        mkdir -p "${email_file:h}"
        _repolog-emit "$mirror" "$host" "$web_base" "$repo" "" false true "$quiet" \
          "$suspect" "$tag" >"$email_file" || rc=1
        $quiet || print -r -- "$email_file"
      else
        _repolog-emit "$mirror" "$host" "$web_base" "$repo" "" false true "$quiet" \
          "$suspect" "$tag" || rc=1
      fi
    else
      local report
      report="$(_repolog-out-path "$repo" "$one_out")"
      _repolog-emit "$mirror" "$host" "$web_base" "$repo" "$report" "$urls_only" false "$quiet" \
        false "" || rc=1
    fi

  done

  if [[ -n "$email_accum" ]]; then
    sort -u "$email_accum"
  fi
  [[ -n "$email_accum" ]] && rm -f "$email_accum"

  return $rc
}
