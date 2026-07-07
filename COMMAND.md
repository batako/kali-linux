# Command Reference (kali-linux)

How to use the **custom wrappers** loaded in zsh inside the Kali container.

For flag details, each command's `-h` / `--help` is the source of truth.

**Convention:** This document uses **full command names** in the main text. Short aliases are supplementary (listed at the end of each section/table).

## Prerequisites

| Variable / Concept | Description |
|------------|------|
| `$IP` | Target IP (`target-set` / `cases/<room>/.target`, auto-restored by `cases sync`) |
| `cases set <room>` | Prepare and select `cases/<room>/` for a room (see "Rooms" below. short: `c set <room>`) |
| Recon CLI | `recon/` (inside container: `/opt/recon/recon.py`). Use through zsh wrappers |
| `recon.db` | Recon CLI database (`/opt/recon/data/recon.db`, host `recon/data/recon.db`) |
| `RECON_PASSLIST` | Default wordlist for john / hydra / stegcracker |
| `GB_VHOST_WORDLIST` | For `scout -v` IP mode (default: raft-small-words) |
| `GB_DNS_WORDLIST` | For `gb-dns` (`gb-set-dns`) |
| `GB_THREADS` | Threads for `gb-dns` / `scout -v` (default 40) |
| `GB_VHOST_EXCLUDE_LENGTH` | Manual ffuf `-fs` for `scout -v` domain mode (default: 3× probe → `-fs` or `-ac`) |
| `GB_VHOST_MATCH_CODES` | Auxiliary ffuf `-mc` for `scout -v` domain mode (default: `200-299,301,302,307,401,403,405,421,422,500`) |
| `GB_VHOST_NO_MC` | When set, omit `-mc` and rely on diff filters (`-fs`/`-ac`) only |
| `GB_VHOST_SKIP_HTTP_REDIRECT` | When set, skip HTTP ffuf on strong redirect suspicion (default: advisory only) |
| `SCOUT_STATUS_SLOTS` | Max number of **completed dirs jobs** shown by `scout -s` / `-ws` (default **4**) |
| `CASE_LOOSE=1` | Fallback to `cases/_unscoped/` when room is unset |
| `CASE_ROOT` | `/workspace/cases` (parent of `CASE_HOME`) |
| `RECON_DATA` | `/opt/recon/data` (DB directory) |
| `RECON_DB` / `RECON_DB_PATH` | `/opt/recon/data/recon.db` |

```bash
cases set startup
target-set 10.49.140.156
# In another tab (if cwd is cases/startup/):
cases sync                # or just target-set (reload .target)
target-show
```

Raw OpenSSH / ftp clients: `command ssh ...` / `command ftp ...`

---

## workspace (`/workspace`)

Host `./workspace` is mounted to container `/workspace`.

| Path | Contents |
|------|------|
| `cases/<room>/` | Files per TryHackMe room (see below) |
| `exploits/` | Downloaded PoCs / third-party exploits (not room-specific) |
| `payloads/` | Custom payloads (webshell, etc. `upload-shell` default is `payloads/webshells/shell.phtml`) |

Structured data goes to Recon CLI -> `recon.db`; shell logs, cracking output, and handwritten notes go to `cases/<room>/` (`logs/` `exports/` or room root).

---

## Rooms (`cases/`)

`cases set` is **not only cd**. It **creates and selects** a working directory for one TryHackMe room (or one scope). Short form: `c set`.

### What `cases set <room>` does

1. **Create directories** - if missing, `mkdir -p`
   `/workspace/cases/<room>/`
   and required subdirectories `logs/` `exports/`
2. **Session variables** - `CASE=<room>`, `CASE_HOME=/workspace/cases/<room>`
3. **Working directory** - `cd "$CASE_HOME"`
4. **On-enter hook** (`_case-on-enter`)
   - If `cases/<room>/.target` exists -> load `$IP`
   - If `cases/<room>/ftp-shell` exists -> load path for `ftp-revshell` (with message)

**Not auto-created** (place manually if needed): `.target`, `ftp-shell`, `memo.md`, files pulled from the room like `*.jpg`, etc.
Those can be placed directly under `CASE_HOME`.

**When TryHackMe IP changes:** `target-set <newIP>` — auto-inherit when the previous target has recon or creds data; older IPs accumulate in `cases/<room>/lineage` (3+ reboots stay in scope). `hosts <room>.thm` is also applied automatically, so the room apex follows the current target IP. Lines in `cases/<room>/.hosts` with the **previous target IP are rewritten to the new IP** and `/etc/hosts` is updated. `exec-list` / `creds-list` / `scout -r` use **lineage + current IP** as recon scope. Pivot: `target-set <ip> --new` (clears lineage; no hosts IP rewrite). Manual pick: `target-set <ip> --pick` or `cases ips` for the list.

```bash
cases set startup
# [+] case: startup
# [+] path: /workspace/cases/startup
# [+] target: 10.49.140.156  (.../.target)   # if .target exists
# [+] ftp-shell: .../ftp-shell               # if it exists
```

### Directory example (after first `cases set startup`)

```
/workspace/cases/startup/
├── logs/          # always created by cases set (listen -l, ssh -l, etc.)
├── exports/       # always created by cases set (steg-extract, john output, etc.)
├── .target        # created by target-set (optional but recommended)
├── .hosts         # hosts command (THM vhost → auto-apply /etc/hosts)
├── ftp-shell      # optional (room-specific FTP/HTTP path)
└── ...            # downloaded files, MEMO.md, locks.txt, etc. can be placed at root
```

### Other commands

| Command | Description |
|----------|------|
| `cases show` | Current `CASE` / `CASE_HOME` / `.target` / `load_from` / `lineage` |
| `cases ips` | Case IP list (lineage / scope / activity; `+` = in lineage, `*` = load_from) |
| `cases load <ip\|--new\|--pick>` | Keep current IP, change inherit source (lineage) only |
| `cases clear` | Unset `CASE` / `CASE_HOME` (does not delete directories) |
| `cases reset [-y] [<room>]` | **Wipe room** — delete all files under `cases/<room>/` (recreate empty `logs/` `exports/`) + recon DB rows for the room |
| `cases open` | Re-enter `CASE_HOME` without changing room |

### Room naming rules

- Must start with alphanumeric, rest can be alphanumeric / `.` / `_` / `-`
- `_unscoped` is reserved (fallback when `CASE_LOOSE=1`)

### When room is not set

Commands with **file output** like `listen -l`, `ssh -l`, `steg-extract` require `CASE_HOME` via `case-home`.
If unset -> error. With `export CASE_LOOSE=1`, output falls back to `cases/_unscoped/` with warning.

---

## exploit (PoC runner)

Select an exploit per room and run it inside an **isolated venv**. Requires `cases set`. State in `cases/<room>/exploit` (shared across tabs).

Wrapper meta (short forms). Exploit args like `-u` pass through unchanged.

| form | description |
|------|-------------|
| `<CVE-id>` | select + venv + pip (e.g. `CVE-2021-44228`) |
| `use <id>` | same |
| `<git-url>` | `git clone` (`https://github.com/<org>/<repo>.git`, etc.) |
| `fetch\|f <url> [id]` | same (explicit) |
| `show` `clear` `prepare` | status / unset / re-pip |
| `--use` `--fetch` … | long flags (same) |
| `-h` | help |

```bash
exploit https://github.com/<org>/<repo>.git
exploit CVE-2021-44228
exploit CVE-2021-44228 -u https://target/
exploit -u https://target/
```

Optional: `/workspace/exploits/<id>/exploit.manifest` (`entry=` `python=` `fetch=`).

**Note:** third-party PoCs always run via venv python (never system `pip install`). Distinct from scout's `exploit-reject` (`erj`).

---

## Target IP

| Command | Description |
|----------|------|
| `target-set <ip>` | Save to `cases/<room>/.target` and set `$IP`. On IP change, **auto-inherit** when recon or creds data exists for previous target; **applies `hosts <room>.thm`** and **rewrites matching `hosts` lines** to the new IP (alias: `ts`) |
| `target-set` | Reload `$IP` from `.target` (can infer room if cwd is under `cases/<room>/`) |
| `target-set <ip> --new` | Pivot — no load_from, no hosts IP rewrite (do not inherit old IP scan/dirs) |
| `target-set <ip> --pick` | Select inheritance source IP by number (last_seen + open/dirs count) |
| `cases sync` | If `$PWD` is under `cases/<room>/`, restore `CASE` + `$IP` (for another tab) |
| `target-show` | Current target IP (RHOST) |
| `lhost` | Print attacker IP only (LHOST: tun0 → eth0) |
| `target-clear` | Clear IP |
| `hosts <host> [aliases...]` | Upsert `cases/<room>/.hosts` (same hostname replaces line; IP from `$IP` / `target`), apply `/etc/hosts` |
| `hosts <ip> <host> [aliases...]` | Append with explicit IP (`hosts -h`) |
| `hosts` / `hosts --off` / `hosts -e` | Show / remove recon block / edit (`cases set` auto-applies; `target-set` rewrites old IP lines) |
| `scout [ip]` | **First recon action** (orchestrator). See "Recon (scout)" below |
| `scan [ip]` | nmap **top 1000** (`-sC -sV`) -> DB, prints **OPEN + CLOSED** at end |
| `scan -f` / `scan --full` | **TCP 1-65535 automatically to completion** (single command end-to-end) |
| `scan --quick` / `scan -f --quick` | **Light scan** (`-sS` only, no `-sC -sV`) — for deceptive mass-open hosts |
| `scan -f -j 4` | Run full scan in **4 parallel jobs** (up to 4000 ports per wave, merged with `recon.db.lock`) |
| `scan --force` | Re-scan (basic=top 1000, full=`-p-`) |
| `scan -r` / `scan --report` | Print DB OPEN + CLOSED only (same shape as post-`scan`, no nmap) |
| `scan -n` / `-q` | dry-run / hide port table |

```bash
cases set startup && target-set 10.49.140.156
scout             # first recon action (scan -> probes -> dirs BG -> auto watch until dirs done)
scout -r          # recon summary (ports + probes + PATHS, no re-run)
scout --force     # rescan / re-dispatch dirs (overwrite DB, no wipe)
scout -s            # dirs status (one-shot)
scout -ws           # auto-refresh status only until done (pair of -s)
exec-list && exec-view <id>     # output of synchronous probes
scan              # ports only (classic top 1000)
scan -f           # auto through all 65535
scan -f -j 4      # 4-way parallel (2-4 recommended on THM, can stop with Ctrl+C)
scan -r           # print only port table again (lightweight)
cases reset -y    # wipe whole room (all IPs + lineage)
```

coverage is **per port number** (`scan`-covered ports are skipped even in `scan -f`). Port recon is only via **`scan` / `scan -f` / `scan -r`**.

---

## Recon (scout)

**Recon orchestrator** (alias: `s`). Executes port scan, service probes, and directory discovery in order. Exploitation and full room completion are out of scope.

| Command | Description |
|----------|------|
| `scout [ip]` | Run Phase 1-3 + **exploit search**. **After dirs dispatch, auto-watch like `-ws`** (ends when running=0) |
| `scout -r` / `--report [ip]` | Recon summary from DB (**room-merged** ports + **OS** + probes + **TASKS** + **PATHS** + **HINTS** + **EXPLOITS**). No re-run |
| `scout -rp` / `--report-ports [ip]` | **OPEN + UNKNOWN + CLOSED** only (DB) |
| `scout -re` / `--report-exploits [ip]` | **EXPLOITS** only (DB, no re-search) |
| `scout -ep` / `--exploit-pack [ip]` | **AI submission pack** — refresh searchsploit + Metasploit, save Markdown under `cases/<room>/plans/` (prints paths only) |
| `scout -rt` / `--report-paths [ip]` | **PATHS** tree only (DB, merged dirs hits) |
| `scout -se` / `--search-exploits [ip]` | Run and cache searchsploit |
| `scout -r -se [ip]` | Search first, then full report |
| `scout -fp` / `--full-ports [ip]` | **TCP 1-65535** (`-sC -sV`) only. **Auto `-se`** after scan (after `searchsploit -u`, run `-se` manually) |
| `scout -fp --quick` / `scout --quick` | **Light scan** (`-sS` only). `--quick` stops after ports (no probes/dirs); `-fp --quick` skips `-se` |
| `scout -fp -j N` | Same with N parallel nmap workers |
| `scout -d` / `scout --dirs [path] [ip]` | gobuster dir only. `-d /admin` -> `http://$IP/admin/`. **Auto-watch to completion** |
| `scout -d -x <ext> [path]` | Extension fuzz (`-x` only uses catalog **dirs-ext** default: `common`) |
| `scout -d -w <id>` | Catalog id (e.g. `dirbuster-small`) or absolute path |
| `scout -d` (`-w` omitted) | Catalog default (`common`, etc.) |
| `scout -d` (no URL) | All DB web ports — capped at **24** by default (`SCOUT_DIRS_AUTO_MAX`); **running/done/failed** jobs skip re-dispatch |
| `scout -d -w` | Interactive picker (`-x` switches dirs / dirs-ext) |
| `scout -d -w browse` | Browse all categories |
| `scout -ds` / `-ds [path]` | **Parallel dir** - up to **standard** tier (3 jobs cumulative) |
| `-ds -x <ext>` | ext fuzz - up to **standard** tier (2 jobs cumulative) |
| `scout -ds -p next [path]` | Only add next-tier jobs (skip already completed jobs) |
| `scout -ds -p light\|standard\|wide\|deep` | Cumulative up to specified tier |
| `scout -ds -w id -w id` | Parallel with explicit ids only |
| `scout -d -H <hostname>` / `-ds -H <name>` | vhost dir bust — `http://$IP/` + gobuster `-H Host:<name>` (no `/etc/hosts` needed) |
| `scout -d -A <ua>` / `-ds -A <ua>` | set `User-Agent` for dir discovery |
| `scout -d -C <cookie>` / `-ds -C <cookie>` | set `Cookie` header for dir discovery and wildcard probe |
| `scout -d mafialive.thm` | dotted FQDN is treated like `-H` (not as `/mafialive.thm/` path) |
| `scout -v` / `--vhosts [domain\|ip]` | vhost discovery. Domain: ffuf **HTTPS→HTTP**; 3× probe (status/size/redirect/hash/headers) → **`-fs` or `-ac`**; HTTP redirect-only is advisory (`GB_VHOST_SKIP_HTTP_REDIRECT` to skip); hits auto-added to `hosts` |
| `scout -s` / `--status [ip]` | Show dirs job status **once** |
| `scout -ws` / `--wait-dirs [sec]` | Auto-refresh dirs status. **Ends when running=0** (pair of `-s`) |
| `scout -n` | Show command plan without execution |
| `scout --no-plan` | Skip Phase 2.5 auth enqueue during full scout |
| `scout --plan [ip]` | Auth enqueue only (phase 2.5; no hydra) |
| `scout --force` | Re-scan Phase 1 and re-dispatch Phase 3 dirs (**not needed for `-se`** - `-se` always refreshes) |

**Prerequisite:** `$IP` or `[ip]`. Web exploration targets ports marked **open** in DB and with **web-like service** (`http` / `https` / `nginx`, etc.). `scout -d` requires Phase 1 already done (run `scout` first if not scanned).

### Phase 1 - Port scan

Internally runs `scan` once (top 1000, `-sC -sV`). Results are recorded in `recon.db` ports / coverage.

### Phase 2 - Service probes (synchronous)

Scans **all open ports**, and runs short probes only where DB **service** matches **SSH / Web type** (and ftp) (not fixed to 22/80; tomcat on 8080 is included).

| service (examples) | Probe |
|---------------|----------|
| `ssh` | nmap `ssh2-enum-algos` |
| `ftp` (excluding `sftp`) | `curl` ftp |
| Web-like (`http` / `nginx` / `apache` / `tomcat`, etc.) | `curl` |

Ports with unknown service are skipped (probe results do not overwrite service). Output goes to console and **`executions`** (`exec-list` / `exec-view`). `task_type`: `scout-ssh`, `scout-http`, `scout-https`, `scout-ftp`.

**Re-run behavior:** For same `ip` + **command**, if a previous run **succeeded** (`done`, `exit_code=0`), it does not rerun and shows `(cached)`. URL normalization treats `http://IP/` and `http://IP:80/` as same, and `https://IP/` and `https://IP:443/` as same. Non-standard ports (e.g. `:8080`) remain separate probes. **`scout --force` does not affect probes** (dirs / scan / exploit only).

### Phase 2.5 - task-plan (sync, enqueue only)

After Phase 2, enqueue **auth-quick** tasks into `tasks` from open port services (**does not run hydra**). Run them with **`strike`**.

| service (examples) | task_type | Action |
|---------------|-----------|------|
| `ftp` (excluding `sftp`) | `auth-ftp-anon` | `ftp-quick-userpass.txt` (anonymous / ftp / guest quick pairs) |
| `ssh` (excluding `sftp`) | `auth-ssh-quick` | `ssh-quick-userpass.txt` (empty pass, then user-as-pass, then retries) |
| `postgres` / `postgresql` | `auth-pg-quick` | seclists postgres betterdefaultpasslist |
| `mysql` / `mariadb` | `auth-my-quick` | `hydra -l root -e ns` |

Dedupe key: `{case}:{ip}:{port}:{task_type}`. Skips re-enqueue when `done` or `running`. Non-standard ports use `-s {port}` in the command.

```bash
scout                    # task-plan at end
scout --no-plan          # skip enqueue
scout --plan [ip]        # manual enqueue only
scout --plan -n          # dry-run
strike [ip]              # run pending auth tasks -> cl
strike -l                  # list tasks
strike -l --all-case     # all IPs in case
strike --force           # redo completed auth tasks
strike -n                # dry-run
```

Env: `SCOUT_NO_PLAN=1` disables task-plan.

### Phase search-exploits - searchsploit (synchronous)

After Phase 2 (during normal `scout` run), runs `searchsploit -j` using `service` / `version` (nmap `product` + `version` + `extrainfo`) from **open ports**. DoS / PoC are excluded via `--exclude`, and up to **5** prioritized **remote / webapps** items per port are saved to `artifacts` as `exploit_report` JSON.

**No re-search needed for EXPLOITS in `scout -r`:** each candidate includes **title / absolute path / run command / `searchsploit -m EDB`**. Raw JSON remains in `exec-view <id>` (`executions` cache).

If you tried a candidate and confirmed it is not applicable, reject it manually to hide it from `scout -re` / `scout -r` (untested items remain visible).

```bash
exploit-reject 50383                      # hide EDB-50383 (for $IP)
exploit-reject --port 80/tcp 50383        # port-scoped
exploit-reject 50383 --note "400 Bad Request"
exploit-rejects                           # list rejects
exploit-unreject 50383                    # restore
```

(alias: `erj` / `erl` / `eru`)

Rejects persist even after re-search with `scout -se`.

| Input example | searchsploit query |
|--------|---------------------|
| `http` + `Apache httpd 2.4.49` | `Apache httpd 2.4.49` |
| `mysql` + `5.7.33` | `5.7.33` or product line |
| `http` only (product unknown) | Skip (too broad) |

`task_type`: `scout-exploit`. Detailed stdout is in `exec-view <id>`. Summary appears under `--- EXPLOITS ---` in **`scout -r`**.

```bash
scout -se                # searchsploit -> cache
scout -re                # show cached EXPLOITS
scout -rp                # ports only
scout -r                 # full report
scout -r -se             # search, then full report
scout -se                # explicit re-search after searchsploit -u, etc. (always refresh)
```

### Phase 3 - Directory discovery (asynchronous)

After Phase 1, if web-like open ports exist, starts gobuster dir **in background** **per port** (e.g. 80 and 8080 both web -> 2 parallel jobs).

- **Default wordlist:** when **`-w` is omitted**, use catalog default. **`-w` only** opens picker.
- **Logs:** `cases/<room>/logs/` (same naming convention as `gb-dirs`).
- **Job management:** `scout_jobs` in `recon.db` (type, URL, status, log path). For same **URL + wordlist**, if a job is **running** or **done**, do not dispatch again (`http://IP/` and `http://IP:80/` are equivalent. use **`scout --force`** to rerun). **`-x` (extensions) is not part of cache key** - to run same wordlist with different extensions, `--force` is required (e.g. rerun `common` with `-x ticket` after already doing `-x html`).
- **Console:** no real-time gobuster stream. After `scout` / `scout -d`, **dirs watch starts automatically** (`-ws` equivalent). For ad-hoc checks, use **`scout -s`** / **`scout -ws`**.

```bash
scout
scout -r
scout -s
scout -ws
scout --dirs -w dirbuster-small -t 20
scout -d /admin
scout -d /admin -x bak,old,txt
scout -d /assets -x php,bak -t 50 -w dirbuster-small
scout -d /admin -x ticket
scout -d /admin -x ticket -w
scout -d /admin -x ticket -w dirbuster-small
scout -d /admin -w browse
scout -d http://$IP:8080/
scout -d -H mafialive.thm
scout -d -A 'Mozilla/5.0'
scout -d -C 'PHPSESSID=abc123'
scout -ds -H mafialive.thm /admin
scout -ds -C 'PHPSESSID=abc123; role=admin' /admin
scout -ds /assets
scout -ds -p next /assets
scout -ds -p wide /uploads
scout -ds -x php /backup
scout -ds -x bak -p next /api
scout -ds -p deep -t 10
scout --force              # redo dirs / scan
```

### PATHS in `scout -s` / `-ws` / `-r` / `-rt`

`-s` / `-r` / **`-rt`** show **job list (metadata)** and **PATHS (merged tree)** separately (`-rt` shows PATHS only).

| Block | Content |
|----------|------|
| **jobs** | id, URL, wordlist name, status, pid, log path (no hit body shown) |
| **`--- PATHS ---`** | Merge dirs hits from shown jobs into a **site-root-based hierarchical tree** |

Jobs in `-s` are ordered as **completed first from oldest** (newest lower), and **running always at the end**. Display limit for completed jobs is **`SCOUT_STATUS_SLOTS`** (default **4**, tune to your parallel dirs count). Hidden overflow is shown as `N older hidden` in header.

PATHS in `-r` / `-rt` merge only the **latest dirs job per URL** (no re-execution, DB-only).

**PATHS example** (merged from root dirs + `-d /etc/`):

```
--- PATHS ---
http://10.49.140.183/
  admin/  301
  etc/  301
    squid/  301
```

Numbers are gobuster HTTP status. Only 200 / 301 / 302 / 401 are shown (noise and extension fuzz are excluded).

### How to read outputs

| Type | How to check |
|------|----------|
| Recon summary (ports + PROBES + PATHS + HINTS + EXPLOITS) | **`scout -r`** |
| Ports only | **`scout -rp`** |
| PATHS tree only | **`scout -rt`** |
| exploit list (DB) | **`scout -re`** |
| AI submission pack (searchsploit + MSF) | **`scout -ep`** |
| exploit search (refresh cache) | **`scout -se`** / **`scout -r -se`** |
| scan and synchronous probes | Console, `exec-list` / `exec-view` (probe shows `(cached)` if already successful) |
| directory discovery (jobs + PATHS tree) | **`scout -s`** / **`scout -ws`**, log files |

For manual gobuster runs, use **`scout -ds`** (parallel) or **`scout -d`** (single wordlist).

---

## Hints / Notes (recon DB)

Save strings, codewords, and "investigate later" notes from pages into DB **per room (`CASE`)**. If `cases set` is done, IP is not required. Also appears in **HINTS** section of `scout -r`.

| Command | Description |
|----------|------|
| `hint-add [-t tag] text...` | Save hint (alias: `ha`) |
| `hint-list` | List hints with id (alias: `hl`) |
| `hint-rm <id>` | Delete hint (alias: `hr`) |

```bash
cases set lianyu
hint-add go!go!go!
hint-add -t codeword vigilante
hint-add -t island-page 'The Code Word is: </p><h2 style="color:white"> vigilante</style><'
hint-list
scout -r          # shown under --- HINTS --- (when CASE is set)
hint-rm 3         # delete id=3
```

`-t` / `--tag` is an optional label. Same room + tag + body is deduplicated.

---

## Credentials (recon DB)

| Command | Description |
|----------|------|
| `creds-add [-c comment] [ip] <user> [pass]` | Manual add (alias: `ca`. omit `pass` to save username only) |
| `creds-list [ip]` | List creds (`user<TAB>pass<TAB>comment`). hydra / hash-crack auto-tag. **If `cases set` is active: load_from + current IP** (IP column first). `creds-list --all-case` for whole room (alias: `cl`) |
| `creds-rm [ip] [user]` | Remove creds (omit user to remove all for IP. alias: `cr`. for `?` etc, use `noglob`) |
| `hash-list [--json] [ip]` | Hash list (`user<TAB>stored<TAB>state`). alias: `hlist` |
| `hash-add [ip] <user hash-line>` | Manual add (alias: `hxa`) |
| `hash-rm [ip] [user]` | Delete hashes (omit user for all on IP; alias: `hxr`) |
| `hydrassh [-p port] [ip] <user> [wordlist]` | hydra SSH -> add to DB on success (`hydrassh -h`) |
| `hydraftp [-p port] [target] [user] [wordlist]` | hydra FTP (target: IP or FQDN; default user: anonymous, `hydraftp -h`) |
| `mklist [passwords] <url\|html> [options]` | Build a password list from a URL or saved HTML (`mklist -h`) |
| `probe <url> [options]` | Probe SSRF / LFI / PHP-wrapper style URL parameters (`probe -h`) |
| `sql <subcommand> [options]` | Short `sqlmap` wrapper for `test/dbs/tables/columns/dump/auto` |
| `reqfuzz [options] <url> <param> <start> <end>` | Simple Intruder-like request fuzzing for GET/POST (`--deep` for details, `-s` shows only diffs) |
| `ffufweb <url> <user> [-fw N ...]` | POST login password spray via ffuf (`-U` for username spray) |
| `hydraweb ...` | hydra http-post-form (`:F`/`:S`, `-H` vhost; `hydraweb -h`) |
| `hydrabasic [-p port] [ip] <user> [path] [wordlist]` | HTTP Basic Auth (hydra http-get, `hydrabasic -h`) |

`sql` is a thin wrapper around `sqlmap` for repetitive CTF flows such as `sql test -r req.txt`, `sql dbs -r req.txt`, `sql tables -r req.txt -D appdb`, `sql columns -r req.txt -D appdb -T users`, and `sql dump -r req.txt -D appdb -T users`. `sql auto` runs `--dbs` and `--tables`, filters out system databases, and only auto-dumps interesting table names such as `users`, `admins`, `accounts`, and `employees`. Dangerous actions like `--os-shell`, `--sql-shell`, and `--file-write` are intentionally not automated. Inside a room directory, the default save path follows the same `exports/sqlmap` behavior as the `sqlmap` wrapper.

`probe` replaces `FUZZ`, or the first empty query parameter (for example `?cv=` or `?mode=view&cv=`), with built-in payloads or a custom `--payloads` list to quickly test `file://`, `php://filter`, `data://`, loopback HTTP targets, and similar wrappers. Each request prints `Status`, `Length`, timeout state, and a response preview, while highlighting hits such as `/etc/passwd`, `root:x:`, `<?php`, `DB_HOST`, and `Permission denied`. When the endpoint path ends with `.php`, `probe` also tries `php://filter/convert.base64-encode/resource=...` against `index.php`, `config.php`, and the current PHP filename, then loosely decodes Base64-looking content to confirm PHP-like code. Inside a room directory, you can omit the host and use forms like `file.php?x=FUZZ`, `file.php?x=`, `/file.php?x=`, or `:8080/file.php?x=`; `probe` fills the host from `CASE.thm`, `cases/<room>/.hosts`, or the current `target-set` IP. Use `--raw` for full body output, `--save` to store responses, `--json` for machine-readable output, and `-o <dir>` to control the save directory.

`reqfuzz` prints `VALUE / STATUS / BYTES` by default. Use `--deep` to add `WORDS / LINES / HASH / NOTE`.

`mklist` runs CeWL with `-d 1 -m 4` when given a URL, or, for a saved HTML file, stores `raw/html.html`, strips `script` / `style` / `svg` / HTML comments, then drops low-priority Bootstrap-style UI elements such as `nav`, `button`, `toast`, `small text-secondary`, and `form-label` into `work/clean.txt`. It then keeps only value-like lines in `work/value_lines.txt`, extracts label/value pairs into `work/pairs.tsv`, extracts hint sentences into `work/hint_lines.txt`, gathers nearby keyword material into `work/hint_keywords.txt`, extracts words into `.mklist/raw/cewl.txt`, and writes normalized plus stopword-filtered words to `.mklist/work/base.txt`. Stopwords are managed in `dotfiles/zsh/.zsh/mklist-stopwords.txt`, and low-value UI labels plus common CSS/JS terms are excluded by default. HTML-derived compound words, meaningful 4-8 digit numbers, date-aware pair expansions, and hint-driven rule variants also produce candidates such as `MarcoBianchi`, `Marco1995`, `marky14021995`, `Bianchi2495`, and `Security2024!`. The default output is `exports/passwords.txt`. Use `--refresh` to rebuild the raw cache from the current input, `--seed <file>` to append extra seeds, `--pin 4|6` to add numeric PINs, and `--max-lines` to cap the final list.

Automatic login for `ssh` excludes **anonymous** (FTP accounts; strike `auth-ftp-anon` hits go to `cl` for `ftp`). SSH quick defaults run via **strike `auth-ssh-quick`**.

---

## SSH

| Command | Description |
|----------|------|
| `ssh [user] [ip]` | Connect using DB creds + `sshpass` or saved passwordless user |
| `ssh -i <key> [user] [ip]` | Key-based login (passphrase loaded from creds) |
| `ssh [user]` (no `-i`) | Reuses the last successful `ssh -i` key for that ip+user |
| `ssh -l` / `ssh --log` | Log session to `cases/.../logs/ssh_*` |
| `ssh-list [ip]` | List creds (same style as `creds-list`) |
| `ssh-get` | **scp download** using creds from `creds-list` or a saved passwordless user (`-o` destination, `-r` recursive; default `cases/<room>/exports/scp/`. alias: `sget`) |
| `ssh-put` | **scp upload** using creds from `creds-list` or a saved passwordless user (`-r` recursive. alias: `sput`) |
| `dav <subcommand> ...` | WebDAV helper via `curl` (`ls/get/put/cat/mkdir/rm/mv`; no auth by default, on auth challenge it lets you choose from `cl` first, otherwise tries `wampp:xampp` / `webdav:webdav` / `jigsaw:jigsaw` and saves hits to `cl`; `-u user[:pass]`, `-n/--dry-run` = print only) |

**Note:** `-l` is for **log save**, not OpenSSH login user. Specify user as argument, e.g. `ssh holt`.

```bash
ssh-get tryhackme.asc credential.pgp
ssh-get -o workspace/cases/tomghost ~/tryhackme.asc
ssh-get skyfuck ~/credential.pgp
ssh-put /workspace/payloads/postex/linpeas.sh /tmp/linpeas.sh
ssh-put -i id_rsa script.sh /home/user/script.sh
```

---

## FTP

| Command | Description |
|----------|------|
| `ftp [user] [ip]` | Connect with DB creds |
| `ftp -l` | Session log |
| `ftp -A <host>` | System ftp anonymous mode (not OpenSSH `-A`) |

---

## svcguess

| Command | Description |
|----------|------|
| `svcguess <host> <port>` | Probe TCP banner, HTTP, HTTPS, and cert info; print a service guess |

---

## Metasploit (msfr)

| Command | Description |
|----------|------|
| `msfr list` | List registered presets |
| `msfr <preset> [opts]` | Run an MSF module with case defaults |

`RHOSTS` = `$IP`, `RPORT` = scout / env / family default, `LHOST` = `lhost` (exploits). Login presets (`pg-login`, `my-login`, `ssh-login`, `ftp-login`) are **quick default checks**. DB modules use MSF built-ins; SSH/FTP use seclists `*-betterdefaultpasslist.txt`. Full spray → `hydrassh` / `hydraftp`. Hits go to `cl`; `pg-hashdump` / `my-hashdump` to `hlist`. Follow-up modules (`pg-sql`, `my-sql`, etc.) pick from `cl` for `$IP` (manual `ca` included; comments tagged `SSH`/`hydra`/etc. excluded). Use `-u USER` or `msfr pg-sql USER`.

| preset | purpose |
|--------|---------|
| `pg-login` … `pg-shell` | PostgreSQL |
| `my-login` … `my-shell` | MySQL (`mysql-*` aliases) |
| `ssh-login` | SSH quick login (defaults only → `cl`) |
| `ftp-login` | FTP quick login (anonymous etc. → `cl`) |
| `tomcat-mgr` | Tomcat manager upload (`-u` / `-U`) |

```bash
msfr pg-login
msfr pg-sql -n              # dry-run (print command + resource only)
msfr my-login
msfr my-sql -u root
msfr ssh-login
msfr tomcat-mgr -u bob -w bubbles -p 1234
msfr -m exploit/... -u user --creds --stay
```

See [docs/Metasploit.md](docs/Metasploit.md).

---

## Listener / RCE trigger

| Command | Description |
|----------|------|
| `listen [port]` | `nc -lvnp` (default 443) |
| `listen -l [port]` | Save connection log to `cases/.../logs/revshell_*` |
| `listen -d [port]` | Receive `tar` stream and extract under `cases/<room>/exports/listen_<ts>/` (`nc -lvnp PORT | tar xf - -C ...`); also prints target-side send command |
| `webrsh [options] [path\|url]` | Web RCE -> reverse shell (`?cmd=` / POST). LHOST auto-detect: `tun0` -> `eth0`. `-u user[:pass]` for HTTP Basic (pass from `cl` if omitted) |
| `lfish [options] [path\|url]` | LFI/php://filter include -> reverse shell. Builds PHP filter chain internally, defaults `LHOST=lhost`, `LPORT=443`, shell type `proc` (`-t proc|bash|nc`) |

Before `ftp-revshell`, start `listen` in **another terminal**.

---

## FTP -> webshell -> reverse shell

| Command | Description |
|----------|------|
| `ftp-put-shell [opts] [ip]` | Upload payload via FTP put -> print URL |
| `ftp-revshell` | put + `webrsh` for reverse shell (alias: `ftprsh`) |
| `ftp-revshell -u` | Skip upload (use URL of already uploaded shell only) |

### Common options

| Option | Meaning |
|------------|------|
| `-d <dir>` | Subdirectory on FTP (e.g. `ftp`) |
| `-w <prefix>` | HTTP path prefix (e.g. `/files`) |
| `-U <url>` | Full shell URL (skip path calculation) |
| `-n <name>` | Remote filename (default `shell.php`) |
| `-p <path>` | Local payload path |
| `-P <port>` | Reverse shell port (default 443) |

### Per-room settings

`cases/<room>/ftp-shell` (auto-loaded by `cases set`):

```bash
REMOTE_DIR=ftp
WEB_PREFIX=/files
```

Example (Startup): `http://$IP/files/ftp/shell.php`

Default without config: `ftp://$IP/shell.php` -> `http://$IP/shell.php`

```bash
cases set startup
listen 443           # another terminal
ftp-revshell
# or
ftp-revshell -d ftp -w /files
ftp-revshell -U http://10.49.140.156/files/ftp/shell.php -u
lfish http://$IP/secret-script.php -p file
lfish /secret-script.php -p file -t bash
lfish /secret-script.php -p page -X POST -P 5555
```

Details: `ftp-revshell -h`

---

## steghide

| Command | Description |
|----------|------|
| `steg-extract <image> [wordlist]` | info -> empty PW -> stegcracker -> extract (alias: `stegx`) |
| `imgrpt [-o path] [-B] <image>` | Collect image metadata -> Markdown report (exiftool / GPS / fixmagic / steghide / binwalk / strings) |
| `imgmap [-q] <image>` | Print Google Maps URL from GPS, or report no location |
| `imgsearch [-q] [-O] [-u url] <image>` | Temp upload -> Google Lens reverse image search URL (`-O` opens browser) |

`steg-extract` output: `cases/<room>/exports/<name>.steg.out` (if room unset, next to image)

`imgrpt` output: `cases/<room>/exports/<name>_imgrpt_<ts>.md` (`-B` skips binwalk)

Logs: `cases/<room>/logs/steg_*`

Manual commands -> [CHEATSHEET.md](CHEATSHEET.md)

---

## repolog (exhaustive Git history)

| Command | Description |
|---------|-------------|
| `repolog [-o path] [-F] [-U] [-M] <repo-url> ...` | Mirror clone -> all refs (**cases set required**) |
| `repolog -f <url-list>` | Batch repos (one URL per line, e.g. `MEMO.md`) |
| `repolog -M [-S] [-R] -f <url-list>` | Unique name+email pairs across repos (`-S` suspect only, `-R` repo prefix) |
| `repolog -u <user>` / `@user` | GitHub API repo list -> batch scan (same as `--user`) |

Uses `git clone --mirror` + `git log --all --date-order`. Mirrors always under `cases/<room>/exports/repolog/`; re-run uses **fetch only**. `-F` forces re-clone.

`--user`: `type=owner`, forks excluded by default. Optional `GITHUB_TOKEN` / `GH_TOKEN`.

| Option | Description |
|--------|-------------|
| `-F` | Remove mirror and clone from scratch |
| `-U` | Commit URLs only on stdout |
| `-M` | Unique name+email on stdout (`name<TAB>email`) |
| `-S` | With `-M`: non-noreply (suspect) only |
| `-R` | With `-M`: `owner/repo<TAB>name<TAB>email` |
| `-o` | Report path (directory when multiple repos) / email list file with `-M` |
| `-q` | Print output path(s) only |

Output: `cases/<room>/exports/<repo>_repolog_<ts>.md`

---

## Recon CLI (DB / scan)

| Command | Description |
|----------|------|
| `recon-init` | Initialize `recon.db` |
| `net-scan <cidr>` | Network scan -> DB |
| `net-view` | List registered hosts |
| `scout [ip]` | Recon orchestrator. `scout -r` / `scout -d` / `scout -s` / `scout -ws` |

## Execution history / artifacts

| Command | Description |
|----------|------|
| `exec-run [ip] <cmd...>` | Run command with record (alias: `x`) |
| `exec-run -s [ip] <cmd...>` | Silent mode (suppressed output bias. alias: `xs`) |
| `exec-cache [ip] <cmd...>` | With cache (same ip+cmd can be reused. alias: `xc` / `xcs` is with `-s`) |
| `exec-list [ip]` | Execution list. **If `cases set` is active: load_from + current IP** (reboot inheritance). `exec-list --all-case` lists all room IPs, `exec-list -l` all hosts (alias: `el`) |
| `exec-view <id> [--tail N]` | Show output (alias: `ev`) |
| `exec-form <id> [--shell]` | Parse upload form from execution stdout |
| `artifact-add [ip] <kind> <value> [key]` | Add artifact |
| `artifact-list [ip]` | List artifacts (`artifact-list -l` lists all hosts. alias: `al`) |
| `artifact-del <id>` | Delete artifact |
| `lfi-loot [-k] [--name LOGICAL=TARGET] <file\|dir\|url>...` | Parse saved responses / acquired files / **URLs** and write results to `cases/<room>/exploits/lfi-loot/` (`-k` skips TLS verify; `FUZZ` in URL tries 14 default include paths) |

Example: `exec-run curl -sS http://$IP/` -> `exec-view <id>` -> `upload-shell <id>`

---

## Gobuster

In recon flow, **`scout -d`** (single) / **`scout -ds`** (parallel) are the proper dir discovery commands. Use these for DNS / vhost:

| Command | Description |
|----------|------|
| `scout -d [path]` | Single wordlist (catalog default / `-w` / picker) - see "Recon (scout)" above |
| `scout -ds [path]` | Parallel dir (default: standard tier; upgrade with `-p next`) |
| `gb-dirs [opts] [url]` | **Deprecated** - delegated to `scout -ds` |
| `gb-dns [domain]` | DNS brute-force (real DNS queries) |
| `scout -v [domain\|ip]` | vhost discovery (see scout table above) |
| `gb-vhost [domain\|ip]` | **Deprecated** — delegates to `scout -v` |

Omitting **`-p`** in `-ds` = cumulative up to **standard** tier. **`-p next`** = only add next-tier jobs.

| tier | dirs (without `-x`) cumulative | dirs-ext (`-x`) cumulative |
|------|----------------------|---------------------|
| light | common, quickhits | common |
| standard | + raft-small-directories | + dirbuster-small |
| wide | + raft-small-files | + dirbuster-medium |
| deep | + dirbuster-small, raft-small-words | + raft-small-files |

aliases: `fast->light`, `ctf->standard`. Legacy dirs `-p deep` (4 jobs) is now **`wide`**.

Interactive DNS wordlist selection:

| Command | Description |
|----------|------|
| `gb-set-dns` | Select `GB_DNS_WORDLIST` |

```bash
cases set overpass
scout -d /admin -x php -w dirbuster-small
scout -ds /admin
scout -ds -p next /assets
scout -ds -x php /backup
scout -ds -p wide -n
hosts lookup.thm
scout -v lookup.thm       # THM: HTTPS→HTTP Host header fuzz
scout -v --https lookup.thm
scout -v              # vhost against IP
gb-dns example.com    # when real DNS exists
```

---

## Cracking (john)

| Command | Description |
|----------|------|
| `sshkey-crack [-f] [-u user] <key> [wordlist]` | ssh2john + john -> `creds-add` on success |
| `gpg-crack [-f] [-n] [-c cred.pgp] <key.asc> [wordlist]` | gpg2john + john -> decrypt `credential.pgp` -> print plaintext |
| `hash-crack [-f] [-a] [-b] [-u user] [<hash\|file\|url>] [wordlist]` | Single hash/file/URL to john. No arg (or `-a`) cracks all pending `hlist` entries → `cl` on success. `-b` saves creds as `borg@$IP` |
| `zip-crack <zip> [wordlist]` | zip hash |
| `rar-crack <rar> [wordlist]` | rar hash -> `john` -> `unrar x` on success |
| `borg-crack [-n] [-u user] [-p pass] <dir> [pass]` | Detect Borg repo in directory -> `borg extract` all archives |

```bash
msfr pg-hashdump && hlist && hash-crack      # hlist → john → cl
hash-crack -b http://$IP/etc/squid/passwd   # creds-list: borg@$IP
borg-crack <dir>                            # auto-use borg from creds-list
borg-crack -u <user> <dir>
borg-crack -p <passphrase> <dir>
```

Extraction target: `exports/<repo_name>/borg/` (`cases set` required). If `-u` is omitted, `borg-crack` prioritizes **`borg` from creds-list** (`RECON_BORG_CREDS_USER`).

---

## Web upload (form POST)

| Command | Description |
|----------|------|
| `upload-shell [opts] [<exec_id>\|]<url>` | multipart POST of `shell.phtml` (alias: `upsh`) |
| `exec-form <exec_id>` | Preview form fields from HTML seen in `exec-view` |
| `shell-url` / `shell-cmd` | Build URL / test `?cmd=` |

Default payload: `/workspace/payloads/webshells/shell.phtml`

```bash
exec-run curl -sS http://$IP/panel/
upload-shell 63
```

See `upload-shell -h`.

---

## enc (Base64 / Base32 / Base58 / Base10)

| Command | Description |
|----------|------|
| `enc -d <str>` / `... \| enc -d` | Try and decode b10 + b64 + b32 + b58 |
| `enc -d -C <str>` / `... \| enc -d -C` | Repeat smart decode until unchanged / ambiguous / no match / max depth |
| `enc -d --online <hash>` | Allow online md5 lookup explicitly |
| `enc -e <str>` | Encode in all formats |
| `enc -t b10 -d <digits>` | decimal integer -> byte sequence (ASCII) |
| `enc -t b10 -e <str>` | string -> decimal integer |
| `enc -t b64 -d <str>` | Base64 only |
| `enc -t b32 -d <str>` | Base32 only |
| `enc -t b58 -d <str>` | Base58 only |
| `enc -t hex -d <str>` | hex only |
| `enc -t ascii -d <list>` | ASCII decimals only |
| `enc -t morse -d <str>` | Morse only |
| `enc -t bcrypt -d <hash> -w <wordlist>` | bcrypt crack with john |

If `-t` is omitted, all types are tried. b10 works for input with **0-9 only**. `enc -d` (alias: `dec`). Online lookup is **off by default** and only enabled with `--online`. `-w <file>` overrides the cracking wordlist (default: `RECON_PASSLIST`) for hash types such as bcrypt / md5 / ntlm / sha1 / sha256. `-C` / `--chain` repeats decode, `--max-depth N` caps recursion depth (default 5).
Legacy names `b64d` `b64e` `b32d` `b32e` `b58d` `b58e` `b10d` `b10e` are aliases. `enc -h`

## rot (Caesar / ROT)

| Command | Description |
|----------|------|
| `rot <str>` / `rot -f <file>` / `... \| rot` | Show all shifts 0-25 |

`rot 'MAF{...}'` -> find the line with `THM{` (shift 7). Legacy name `rotall`. `rot -h`

## vig (Vigenere)

| Command | Description |
|----------|------|
| `vig -a <cipher>` | Brute-force key lengths 1-3 (only likely-flag lines) |
| `vig -a --all <cipher>` | No filtering |
| `vig -a -n 4 <cipher>` | Max key length (4+ is slow) |
| `vig -d -k KEY <cipher>` | Decrypt |
| `vig -e -k KEY <plain>` | Encrypt |
| `vig -K -p PLAIN <cipher>` | Recover key from known plaintext |

`vig -a 'CIPHER{...}'` -> `key THM: TRYHACKME{...}`. If wrapper text is known, `vig -K -p TRYHACKME '...'` -> `THM`.
Supports `-f` / pipes. Legacy `vigd` `vige` `vigall` `vigkey` are aliases. `vig -h`

## Magic byte repair

| Command | Description |
|----------|------|
| `fixmagic <file>` | Check magic byte and repair only if needed |
| `fixmagic -o out.png <file>` | Specify output path |
| `fixmagic -n <file>` | Check only (no repair) |
| `fixmagic -i <file>` | In-place only when needed (keeps `.bak`) |
| `magic <file>` | Guess file type from magic bytes |
| `magic -r TYPE [-o out] <file>` | Repair and save (`-o` omitted => auto `<name>_<type>.<ext>`) |

If no repair is needed, exits with `[=] ok`. Supports PNG / JPEG / GIF.
`fixmagic broken.png` - if broken, writes `broken_fixed.png`; if valid, writes nothing. `fixmagic -h`
`magic broken.png` - guesses `PNG` / `JPEG` / `GIF` / `BMP` / `WEBP` / `ICO` / `ZIP` / `RAR` / `7Z` / `GZIP` / `PDF` / `ELF`. `magic -h`
`magic -r PNG broken.bin` - saves as `broken_png.bin` by default; `-o` writes elsewhere. `magic -h`

---

## Aliases

### Wrappers

| Full command | alias |
|--------------|-------|
| `cases` | `c` |
| `target-set` | `ts` |
| `scout` | `s` |
| `creds-add` | `ca` |
| `creds-list` | `cl` |
| `creds-rm` | `cr` |
| `exec-run` | `x` |
| `exec-run -s` | `xs` |
| `exec-cache` | `xc` |
| `exec-cache -s` | `xcs` |
| `exec-list` | `el` |
| `exec-view` | `ev` |
| `artifact-list` | `al` |
| `hint-add` | `ha` |
| `hint-list` | `hl` |
| `hint-rm` | `hr` |
| `hash-list` | `hlist` |
| `hash-add` | `hxa` |
| `hash-rm` | `hxr` |
| `ssh-get` | `sget` |
| `ssh-put` | `sput` |
| `ftp-revshell` | `ftprsh` |
| `upload-shell` | `upsh` |
| `steg-extract` | `stegx` |
| `exploit-reject` | `erj` |
| `exploit-rejects` | `erl` |
| `exploit-unreject` | `eru` |
| `postcmd` | `pcmd` |
| `enc -d` | `dec` |
| `pop3` | `p3` |
| `pop3-list` | `p3l` |
| `pop3-get` | `p3g` |
| `pop3-dump` | `p3d` |

### Others

| Command | alias |
|----------|-------|
| `ss -tulnp` | `ports` |
| `python3 -m http.server 8000` | `http` |
| `searchsploit` | `ss` |
| `msfconsole` | `msf` |
| `tmux new -A -s ctf` | `t` |
| `dig @1.1.1.1 +short A` | `diga` |
| `dig @1.1.1.1 +short MX` | `digmx` |
| `dig @1.1.1.1 +short TXT` | `digtxt` |
| `dig @1.1.1.1 +short NS` | `digns` |

---

## Not documented for users

Internal helpers (not for direct use): `ftp-login`, `ssh-login`, `target-load`, `case-home`, `_revshell-lhost`, etc.
`python3 $RECON_APP ...` should be invoked through the zsh commands above.

---

## Help list

```bash
ftp-revshell -h
ssh -h
listen -h
steg-extract -h
imgrpt -h
imgsearch -h
repolog -h
gb-dirs -h
sshkey-crack -h
gpg-crack -h
upload-shell -h
webrsh -h
lfish -h
msfr -h
postcmd -h
enc -h
rot -h
vig -h
fixmagic -h
ftp -h
hydraweb   # shows usage when args are missing
hydrabasic -h
```

## Index (user-facing commands)

Full names only. Alias is shown in parentheses.

`cases set` (`c set`) `cases show` `cases clear` `cases reset` `cases open` `cases sync` `cases load` ·
`target-set` (`ts`) `target-show` `target-clear` ·
`scout` (`s`) `scout -r` `scout -rp` `scout -re` `scout -ep` `scout -rt` `scout -se` `scout -d` `scout -ds` `scout -s` `scout -ws` ·
`scan` ·
`creds-add` (`ca`) `creds-list` (`cl`) `creds-rm` (`cr`) `hydrassh` `hydraftp` `hydraweb` `hydrabasic` ·
`hint-add` (`ha`) `hint-list` (`hl`) `hint-rm` (`hr`) ·
`hash-list` (`hlist`) `hash-add` (`hxa`) `hash-rm` (`hxr`) ·
`ssh` `ssh-list` `ssh-get` (`sget`) `ssh-put` (`sput`) · `ftp` · `listen` `webrsh` `lfish` · `ftp-revshell` (`ftprsh`) `ftp-put-shell` ·
`steg-extract` (`stegx`) `imgrpt` `imgmap` `imgsearch` `repolog` · `recon-init` `net-scan` `net-view` ·
`exec-run` (`x`) `exec-cache` (`xc`) `exec-list` (`el`) `exec-view` (`ev`) `exec-form` ·
`artifact-add` `artifact-list` (`al`) `artifact-del` `lfi-loot` ·
`exploit` · `exploit-reject` (`erj`) `exploit-rejects` (`erl`) `exploit-unreject` (`eru`) ·
`gb-dirs` `gb-dns` `gb-vhost` `gb-set-dns` ·
`sshkey-crack` `gpg-crack` `hash-crack` `zip-crack` `rar-crack` `borg-crack` · `upload-shell` (`upsh`) `postcmd` (`pcmd`) `shell-url` `shell-cmd` ·
`pop3` (`p3`) `pop3-list` (`p3l`) `pop3-get` (`p3g`) `pop3-dump` (`p3d`) `hydrapop3` ·
`enc` (`dec`) `rot` `vig` `fixmagic` · `msfr` · `ports` `http` `ss` `msf` `t` `diga` `digmx` `digtxt` `digns`
