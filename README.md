# kali-linux

TryHackMe-oriented Kali environment (Docker + OpenVPN + zsh wrappers + Recon CLI).

## Setup

Create the local Docker Compose configuration from the checked-in example, then copy `.env.example` to `.env`. Edit the values you want to override (`VNC_PASSWORD`, optional `WPSCAN_API_TOKEN`, `TOOLKIT_LANG`, etc.). `docker-compose.yml` is local-only and is intentionally not tracked.

```bash
cp docker-compose.yml.example docker-compose.yml
cp .env.example .env
```

**OpenVPN** — Place the `.ovpn` file from TryHackMe at this fixed path (the entrypoint only reads this file).

```
config/openvpn/tryhackme.ovpn
```

The filename must be `tryhackme.ovpn` (no other name).

```bash
docker compose build
docker compose up -d
docker compose exec kali zsh -lc 'ip a show tun0'   # verify VPN
docker compose exec -it kali zsh
```

**FoxyProxy (host browser)** — Import `host/foxyproxy/profiles.json` into FoxyProxy to route the host browser through the Kali container.

- `SOCKS5 via Kali VPN`: default browsing profile. Uses the SOCKS5 proxy on `localhost:1080` so traffic goes through the container VPN
- `Burp via Kali VPN`: use this when browsing through Burp on `localhost:8080`

| Use | Endpoint |
|-----|----------|
| Shell (recommended) | `docker compose exec -it kali zsh` |
| noVNC | http://localhost:6080 |
| VNC | `localhost:5905` (`VNC_PASSWORD`, default `kali1234`) |
| ttyd | http://localhost:7681 |
| SOCKS5 | `localhost:1080` |

Published ports: 1080, 5905, 6080, 7681, 8080 (`docker-compose.yml`).

The `kali` service is the main TryHackMe environment. The other services under `services/` are test targets for validating commands and network tooling; enable them in the local `docker-compose.yml` when needed.

## Workspace

Working root is `/workspace` (host `./workspace` is mounted).

```
workspace/
├── cases/<room>/      # per TryHackMe room (select with case-set)
│   ├── target         # saved by target-set
│   ├── logs/
│   └── exports/
├── exploits/
└── payloads/
```

Recon CLI DB (`recon.db`) lives in `recon/data/` (container: `/opt/recon/data`). Ports, creds, and execution history are stored there.

Commands that **write files** (`listen -l`, `steg-extract`, `ssh -l`, etc.) require `case-set <room>` first. Details → [COMMAND.md](COMMAND.md) (workspace / room).

## Workflow

After you Start a TryHackMe room:

```bash
case-set <room>              # select room, cd to cases/<room>/
target-set <ip>              # target IP
scout                        # recon (scan / dirs, etc.)
creds-list                   # saved creds
ssh / ssh -i <key>           # connect via creds-list
```

Short aliases: `case-set` → `cs`, `target-set` → `ts`, `scout` → `s`, `creds-list` → `cl`.

If the IP changes within the same room, run `target-set <new-ip>` (auto-inherits from the previous IP when recon data exists). For a pivot, use `target-set <ip> --new`.

Playbooks → [CHEATSHEET.md](CHEATSHEET.md). Command reference → [COMMAND.md](COMMAND.md).

## Repository

```
├── docker-compose.yml
├── docker-compose.yml.example  tracked Compose template
├── services/              service definitions (`kali` plus command-test services)
├── config/openvpn/        tryhackme.ovpn (place manually)
├── host/foxyproxy/        FoxyProxy profiles for the host browser
├── dotfiles/zsh/          wrappers (mounted to /home/kali/.zsh)
├── recon/                 Recon CLI (code `/opt/recon` :ro, `data/recon.db` `/opt/recon/data` :rw)
└── workspace/             workspace above
```

## Troubleshooting

**No `tun0`** — Check `config/openvpn/tryhackme.ovpn`, `docker compose logs kali` for OpenVPN errors, re-download `.ovpn` if needed. Container needs `NET_ADMIN` and `/dev/net/tun` (already in compose).

**File output errors** — Did you run `listen -l` etc. before `case-set <room>`? Without a room, set `CASE_LOOSE=1` → `cases/_unscoped/` ([COMMAND.md](COMMAND.md)).

**Port conflicts** — If published ports from Setup are in use on the host, change `ports` in `docker-compose.yml`.
