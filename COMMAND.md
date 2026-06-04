# コマンドリファレンス（kali-linux）

Kali コンテナの zsh に載っている **自作ラッパ** の使い方。

フラグの詳細は各コマンドの `-h` / `--help` を正とする。

## 前提

| 変数・概念 | 説明 |
|------------|------|
| `$IP` | 調査対象 IP（`ts` / `cases/<name>/target`、`cs` で自動復元） |
| `cs <name>` | 案件ディレクトリを用意して選択（下記「案件」参照） |
| `recon.db` | `/workspace/recon/recon.db`（creds・実行履歴） |
| `RECON_PASSLIST` | john / hydra / stegcracker の既定ワードリスト |
| `GB_WORDLIST` | `gb-dir` / `gb-vhost` 用（`gb-set-web` で変更可） |
| `GB_DNS_WORDLIST` | `gb-dns` 用（`gb-set-dns`） |
| `GB_THREADS` | gobuster スレッド（`gb-set-threads`、既定 30 程度） |
| `CASE_LOOSE=1` | 案件未設定時に `cases/_unscoped/` へフォールバック |

```bash
cs startup
ts 10.49.140.156    # target ファイルに保存
# 別タブ（cwd が cases/startup/ なら）:
case-sync           # または ta だけ（target 再読込）
ta 10.49.140.156    # CASE 未設定でも cwd から案件を推定
target-show
```

**注意:** oh-my-zsh **tmux プラグイン**も `ta`（= `tmux attach -t`）を定義する。`99-target-ta.zsh` で上書き。効かないときは `ti` か `ts` を使う。確認: `which ta` が `_target-attach` 経由であること。

素の OpenSSH / ftp クライアント: `command ssh ...` / `command ftp ...`

---

## 案件（cases）

`cs` は **cd だけではない**。TryHackMe の 1 ルーム（または 1 スコープ）用の作業ディレクトリを **作成・選択** する。

### `cs <name>`（`case-set`）がすること

1. **ディレクトリ作成** — 無ければ `mkdir -p`
   `/workspace/cases/<name>/`
   および必須サブディレクトリ `logs/` `exports/`
2. **セッション変数** — `CASE=<name>`, `CASE_HOME=/workspace/cases/<name>`
3. **作業ディレクトリ** — `cd "$CASE_HOME"`
4. **入場時フック**（`_case-on-enter`）
   - `cases/<name>/target` があれば → `$IP` を読み込み
   - `cases/<name>/ftp-shell` があれば → `ftprsh` 用パスを読み込み（メッセージ表示）

**自動では作らないもの**（必要なら自分で置く）: `target`, `ftp-shell`, `memo.md`, ルームから取得した `*.jpg` など。
それらは案件ルート（`CASE_HOME`）に直接置いてよい。

```bash
cs startup
# [+] case: startup
# [+] path: /workspace/cases/startup
# [+] target: 10.49.140.156  (.../target)   # target がある場合
# [+] ftp-shell: .../ftp-shell               # ある場合
```

### ディレクトリ例（初回 `cs startup` 後）

```
/workspace/cases/startup/
├── logs/          # cs で必ず作成（listen -l, ssh -l など）
├── exports/       # cs で必ず作成（stegx, john 出力など）
├── target         # ts で作成（任意だが推奨）
├── ftp-shell      # 任意（ルーム別 FTP/HTTP パス）
└── …              # notice.txt, MEMO.md 等は手動でコピー可
```

`recon.db` は **`/workspace/recon/`** にあり、案件フォルダとは別。

### その他のコマンド

| コマンド | 説明 |
|----------|------|
| `case-show` | 現在の `CASE` / `CASE_HOME` |
| `case-clear` | `CASE` / `CASE_HOME` を unset（ディレクトリは削除しない） |
| `case-open` | 案件を変えず `CASE_HOME` に cd し直す |

### 案件名のルール

- 先頭英数字、続きは英数字・`.`・`_`・`-`
- `_unscoped` は予約（`CASE_LOOSE=1` 時のフォールバック用）

### 案件未設定のとき

`listen -l`, `ssh -l`, `stegx` など **ファイル出力** は `case-home` 経由で `CASE_HOME` が要る。
未設定 → エラー。`export CASE_LOOSE=1` なら `cases/_unscoped/` に警告付きで退避。

---

## ターゲット IP

| コマンド | 説明 |
|----------|------|
| `ts <ip>` | `target-set` の短縮。`cases/<case>/target` に保存し `$IP` 設定 |
| `ta <ip>` / `ta` / `ti` | target 設定または `target` から `$IP` 再読込（**oh-my-zsh tmux の `ta` を上書き**） |
| `case-sync` | `$PWD` が `cases/<name>/` 以下なら `CASE` + `$IP` を復元（別タブ向け） |
| `target-show` | 現在の IP |
| `target-clear` | クリア |
| `scan [ip]` | nmap **top 1000**（`-sC -sV`）→ DB、終了時 **OPEN + CLOSED** |
| `scan full [ip]` | **TCP 1–65535 を自動で最後まで**（1000 ポートずつ、1 コマンドで完走） |
| `scan -f` | 再スキャン（basic=top 1000、full=`-p-`） |
| `scan -n` / `-q` | dry-run / ポート表なし |
| `host-reset [ip]` | 当該 IP の ports / coverage / scan_ranges を削除（再テスト用） |
| `host-view [ip]` | ポート全件・tasks・履歴・artifacts |

```bash
cs startup && ti 10.49.140.156
scan              # 定番 1000。終わったら OPEN / CLOSED
scan full         # 65535 完了まで自動（長い。Ctrl+C で途中停止可）
host-reset        # スキャン結果だけ消してやり直す
host-view         # タスクや履歴が欲しいときだけ
```

coverage は **ポート番号単位**（`scan` 済みは `scan full` でもスキップ）。`host-scan` は互換用（task 生成のみ推奨）。

---

## 認証情報（recon DB）

| コマンド | 説明 |
|----------|------|
| `creds-add [ip] <user> <pass>` | 手動登録 |
| `creds-list [ip]` / `cl` | 一覧 |
| `creds-rm [ip] [user]` | 削除（user 省略で IP の creds すべて） |
| `hydrassh [ip] <user> [wordlist]` | hydra SSH → 成功時 DB へ |
| `hydraftp [ip] [user] [wordlist]` | hydra FTP（既定 user: anonymous） |
| `hydraweb ...` | http-post-form 用（`hydraweb -h` 参照） |

`ssh` の自動ログインは **anonymous を除外**（FTP 用の anonymous は `ftpa` で保存）。

---

## SSH

| コマンド | 説明 |
|----------|------|
| `ssh [user] [ip]` | DB の creds + `sshpass` で接続 |
| `ssh -i <key> [user] [ip]` | 鍵（パスフレーズは creds から） |
| `ssh -l` / `ssh --log` | セッションを `cases/.../logs/ssh_*` に記録 |
| `ssh-list [ip]` | creds 一覧（`cl` と同系） |

**注意:** `-l` は OpenSSH の login user ではなく **ログ保存**。ユーザー指定は `ssh holt` のように引数で。

---

## FTP

| コマンド | 説明 |
|----------|------|
| `ftp [user] [ip]` | DB creds で接続 |
| `ftp -l` | セッションログ |
| `ftpa [ip]` | 匿名 FTP（`anonymous` / `anonymous@` を DB に保存） |
| `ftpa -l` / `ftp -l` | セッションログ（`cases/.../logs/`） |
| `ftp -A <host>` | 匿名（`ftpa` と同系、OpenSSH の `-A` とは別） |

---

## リスナー・RCE トリガー

| コマンド | 説明 |
|----------|------|
| `listen [port]` | `nc -lvnp`（既定 4444） |
| `listen -l [port]` | 接続ログを `cases/.../logs/revshell_*` に保存 |
| `rcecurl <url> [port]` | `?cmd=` RCE 用。LHOST は `tun0` → `eth0` 自動 |

`ftprsh` の前に **別ターミナルで `listen`** を起動する。

---

## FTP → webshell → reverse shell

| コマンド | 説明 |
|----------|------|
| `ftp-put-shell [opts] [ip]` | ペイロードを FTP put → URL 表示 |
| `ftprsh` / `ftp-revshell` | put + `rcecurl` で revshell |
| `ftprsh -u` | upload 省略（既に置いた shell の URL のみ） |

### よく使うオプション

| オプション | 意味 |
|------------|------|
| `-d <dir>` | FTP 上のサブディレクトリ（例: `ftp`） |
| `-w <prefix>` | HTTP パス接頭（例: `/files`） |
| `-U <url>` | shell の完全 URL（パス計算スキップ） |
| `-n <name>` | リモートファイル名（既定 `shell.php`） |
| `-p <path>` | ローカルペイロード |
| `-P <port>` | revshell ポート（既定 4444） |

### ケース別設定

`cases/<name>/ftp-shell`（`cs` で自動読込）:

```bash
REMOTE_DIR=ftp
WEB_PREFIX=/files
```

例（Startup）: `http://$IP/files/ftp/shell.php`

設定なしの既定: `ftp://$IP/shell.php` → `http://$IP/shell.php`

```bash
cs startup
listen 4444          # 別ターミナル
ftprsh
# または
ftprsh -d ftp -w /files
ftprsh -U http://10.49.140.156/files/ftp/shell.php -u
```

詳細: `ftprsh -h`

---

## steghide

| コマンド | 説明 |
|----------|------|
| `steg-extract <image> [wordlist]` | info → 空 PW → stegcracker → 展開 |
| `stegx <image>` | 上記の別名 |

出力: `cases/<case>/exports/<name>.steg.out`（案件なし時は画像横）

ログ: `cases/<case>/logs/steg_*`

手動コマンド → [CHEATSHEET.md](CHEATSHEET.md)

---

## ReconOS（DB・スキャン・タスク）

| コマンド | 説明 |
|----------|------|
| `recon-init` | `recon.db` 初期化 |
| `net-scan <cidr>` | ネットワークスキャン → DB |
| `net-view` | 登録ホスト一覧 |
| `host-scan <ip> quick\|full` | ホストスキャン |
| `host-view [ip]` | ホスト詳細 |
| `host-summary [ip]` | JSON サマリ |
| `task-view` | タスク一覧 |
| `task-done <id>` | タスク完了 |
| `task-run <id>` | タスク実行 |
| `host-run-next [ip]` | 次の pending タスクを実行 |

## 実行履歴・成果物

| コマンド | 説明 |
|----------|------|
| `x [ip] <cmd...>` | コマンド実行を記録（`exec-run`） |
| `xs ...` | サイレント（出力抑制寄り） |
| `xc` / `xcs` | キャッシュ付き（同一 ip+cmd は再利用可） |
| `el [ip]` / `exec-list` | 実行一覧（`el -l` で全ホスト） |
| `ev <id> [--tail N]` | 出力表示 |
| `exec-form <id> [--shell]` | 実行 stdout からアップロードフォーム解析 |
| `artifact-add [ip] <kind> <value> [key]` | 成果物登録 |
| `al [ip]` / `artifact-list` | 成果物一覧（`al -l` で全ホスト） |
| `artifact-del <id>` | 成果物削除 |

例: `x curl -sS http://$IP/` → `ev <id>` → `upsh <id>`

---

## Gobuster

| コマンド | 説明 |
|----------|------|
| `gb-dir [url] [-x ext]` | 単一ワードリスト（`$GB_WORDLIST`） |
| `gb-dirs [opts] [url]` | 複数リスト並列。ログは `cases/.../logs/` |
| `gb-dns [domain]` | DNS |
| `gb-vhost ...` | vhost |

`gb-dirs` プリセット: `ctf`（既定）, `fast`, `deep` — `gb-dirs -h`

対話で環境変数を設定:

| コマンド | 説明 |
|----------|------|
| `gb-set-web` | `GB_WORDLIST` を選択 |
| `gb-set-dns` | `GB_DNS_WORDLIST` を選択 |
| `gb-set-threads` | `GB_THREADS` を選択 |

```bash
cs overpass
gb-dirs
gb-dirs -p fast -n http://$IP
gb-vhost              # http + https 両方
gb-dns example.com
```

---

## クラック（john）

| コマンド | 説明 |
|----------|------|
| `sshkey-crack [-f] [-u user] <key> [wordlist]` | ssh2john + john → 成功時 `creds-add` |
| `zip-crack <zip> [wordlist]` | zip ハッシュ |

---

## Web アップロード（フォーム POST）

| コマンド | 説明 |
|----------|------|
| `upsh [opts] [<exec_id>\|]<url>` | `shell.phtml` を multipart POST |
| `upload-shell` | 同上（本体） |
| `exec-form <exec_id>` | `ev` で見た HTML からフォーム項目をプレビュー |
| `shell-url` / `shell-cmd` | URL 組み立て・`?cmd=` テスト |

既定ペイロード: `/workspace/payloads/webshells/shell.phtml`

```bash
x curl -sS http://$IP/panel/
upsh 63
```

`upsh -h` 参照。

---

## Base64

| コマンド | 説明 |
|----------|------|
| `b64d <str>` / `b64d -f <file>` / `… \| b64d` | デコード |
| `b64e <str>` / `b64e -f <file>` / `… \| b64e` | エンコード（1行） |

`x "b64d QXJlYTUx"` のように `x` 経由でも可。`b64d -h`

---

## エイリアス

| 別名 | 実体 |
|------|------|
| `ports` | `ss -tulnp` |
| `http` | `python3 -m http.server 8000` |
| `ss` | `searchsploit` |
| `msf` | `msfconsole` |
| `t` | `tmux new -A -s ctf` |
| `diga` | `dig @1.1.1.1 +short A` |
| `digmx` | MX |
| `digtxt` | TXT |
| `digns` | NS |

---

## ドキュメントに載せないもの

内部ヘルパ（直接は使わない）: `ftp-login`, `ssh-login`, `target-load`, `case-home`, `_revshell-lhost` など。
`python3 $RECON_APP …` は上記 zsh コマンド経由が正。

---

## ヘルプ一覧

```bash
ftprsh -h
ssh -h
listen -h
steg-extract -h
gb-dirs -h
sshkey-crack -h
upsh -h
rcecurl -h
b64d -h
ftp -h
ftpa -h
hydraweb   # 引数不足時に usage 表示
```

## 索引（ユーザー向けコマンド一覧）

`cs` `case-show` `case-clear` `case-open` · `ts` `target-show` `target-clear` `scan` ·
`creds-add` `cl` `creds-rm` `hydrassh` `hydraftp` `hydraweb` ·
`ssh` `ssh-list` · `ftp` `ftpa` · `listen` `rcecurl` · `ftprsh` `ftp-put-shell` ·
`stegx` · `recon-init` `net-scan` `net-view` `host-scan` `host-view` `host-summary` ·
`task-view` `task-done` `task-run` `host-run-next` ·
`x` `xs` `xc` `xcs` `el` `ev` `exec-form` · `artifact-add` `al` `artifact-del` ·
`gb-dir` `gb-dirs` `gb-dns` `gb-vhost` `gb-set-web` `gb-set-dns` `gb-set-threads` ·
`sshkey-crack` `zip-crack` · `upsh` `upload-shell` `shell-url` `shell-cmd` ·
`b64d` `b64e` · `ports` `http` `ss` `msf` `t` `diga` `digmx` `digtxt` `digns`
