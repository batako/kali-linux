# kali-linux

TryHackMe 向け Kali 環境（Docker + OpenVPN + zsh ラッパ + Recon CLI）。

English: [README.en.md](README.en.md)

## Setup

**OpenVPN** — TryHackMe から取得した `.ovpn` を次の固定パスに置く（entrypoint がこのファイルのみ参照する）。

```
config/openvpn/tryhackme.ovpn
```

ファイル名は `tryhackme.ovpn` 以外不可。

```bash
docker compose build
docker compose up -d
docker compose exec kali zsh -lc 'ip a show tun0'   # VPN 確認
docker compose exec -it kali zsh
```

| 用途 | 接続先 |
|------|--------|
| Shell（推奨） | `docker compose exec -it kali zsh` |
| noVNC | http://localhost:6080 |
| VNC | `localhost:5905`（`VNC_PASSWORD`, 既定 `kali1234`） |
| ttyd | http://localhost:7681 |
| SOCKS5 | `localhost:1080` |

公開ポート: 1080, 5905, 6080, 7681, 8080（`docker-compose.yml`）。

## Workspace

作業ルートは `/workspace`（ホスト `./workspace` とマウント）。

```
workspace/
├── cases/<room>/      # ルーム単位（case-set で選択）
│   ├── target         # target-set で保存
│   ├── logs/
│   └── exports/
├── exploits/
└── payloads/
```

Recon CLI の DB（`recon.db`）は `recon/data/`（コンテナ内 `/opt/recon/data`）。ポート・creds・実行履歴はここに保存。

`listen -l` / `steg-extract` / `ssh -l` など、ファイルへ書き出すコマンドは、先に `case-set <room>` を実行すること。詳細 → [COMMAND.md](COMMAND.md) の workspace / ルーム。

## Workflow

TryHackMe でルームを Start したら:

```bash
case-set <room>              # ルーム選択・cases/<room>/ へ cd
target-set <ip>              # Target IP
scout                        # 偵察（scan / dirs 等）
creds-list                   # 保存済み creds
ssh / ssh -i <key>           # creds-list 経由で接続
```

短縮 alias: `case-set` → `cs`、`target-set` → `ts`、`scout` → `s`、`creds-list` → `cl`。

同一ルームで IP が変わったら `target-set <新IP>`（recon データがあれば自動継承。旧 IP は `cases/<room>/lineage` に蓄積）。pivot は `target-set <ip> --new`。IP 一覧は `case-ips`。

定番手順 → [CHEATSHEET.md](CHEATSHEET.md)（[EN](CHEATSHEET.en.md)）。コマンド詳細 → [COMMAND.md](COMMAND.md)（[EN](COMMAND.en.md)）。

## Repository

```
├── docker-compose.yml
├── kali/                  Dockerfile, entrypoint
├── config/openvpn/        tryhackme.ovpn（手動配置）
├── dotfiles/zsh/          ラッパ（/home/kali/.zsh にマウント）
├── recon/                 Recon CLI（ソース `/opt/recon` :ro、`data/recon.db` `/opt/recon/data` :rw）
└── workspace/             上記 Workspace
```

## Troubleshooting

**`tun0` なし** — `config/openvpn/tryhackme.ovpn` の有無、`docker compose logs kali` の OpenVPN エラー、`.ovpn` の再取得。コンテナには `NET_ADMIN` と `/dev/net/tun` が必要（compose 済み）。

**ファイル出力エラー** — `case-set <room>` 前に `listen -l` 等を実行していないか。未設定時は `CASE_LOOSE=1` → `cases/_unscoped/`（[COMMAND.md](COMMAND.md)）。

**ポート競合** — Setup の公開ポートがホストで使用中なら `docker-compose.yml` の `ports` を変更。
