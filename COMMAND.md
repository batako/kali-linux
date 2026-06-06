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
| `SCOUT_STATUS_SLOTS` | `scout -s` / `-ws` で表示する **完了 dirs ジョブ**の上限（既定 **4**） |
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
| `scout [ip]` | **偵察の初手**（司令塔）。下記「偵察（scout）」 |
| `scan [ip]` | nmap **top 1000**（`-sC -sV`）→ DB、終了時 **OPEN + CLOSED** |
| `scan -f` / `scan --full` | **TCP 1–65535 を自動で最後まで**（1 コマンドで完走） |
| `scan -f -j 4` | full を **4 並列**（1 wave あたり最大 4000 ポート、`recon.db.lock` でマージ） |
| `scan --force` | 再スキャン（basic=top 1000、full=`-p-`） |
| `scan -r` / `scan --report` | DB の OPEN + CLOSED（`scan` 終了時と同型・nmap なし） |
| `scan -n` / `-q` | dry-run / ポート表なし |
| `host-reset [ip]` | 当該 IP の ports / coverage / scan_ranges を削除（再テスト用） |
| `host-view [ip]` | ポート全件・tasks・履歴・artifacts |

```bash
cs startup && ti 10.49.140.156
scout             # 偵察初手（scan → プローブ → dirs BG → dirs 完了まで自動 watch）
scout -r          # 偵察サマリ（ポート + プローブ + PATHS、再実行なし）
scout -s            # dirs 状態（1 回）
scout -ws           # dirs 完了まで自動更新のみ（-s の対）
el && ev <id>     # 同期プローブの出力
scan              # ポートだけ（定番 1000）
scan -f           # 65535 完了まで自動
scan -f -j 4      # 並列 4（THM では 2–4 推奨。Ctrl+C で途中停止可）
host-reset        # スキャン結果だけ消してやり直す
scan -r           # ポート表だけ再表示（軽い）
host-view         # タスクや履歴が欲しいときだけ
```

coverage は **ポート番号単位**（`scan` 済みは `scan -f` でもスキップ）。ポート偵察は **`scan` / `scan -f` / `scan -r`** のみ。

---

## 偵察（scout）

**偵察の司令塔**。ポートスキャン・サービスプローブ・ディレクトリ探索を順序付きで実行する。攻撃（exploit）やルーム完走は含まない。

| コマンド | 説明 |
|----------|------|
| `scout [ip]` | Phase 1–3 + **exploit 検索** を実行。**dirs dispatch 後は自動で `-ws` 相当の watch**（running が 0 で終了） |
| `scout -r` / `--report [ip]` | DB の偵察サマリ（ポート + プローブ + **PATHS** + **EXPLOITS**）。再実行なし |
| `scout -rp` / `--report-ports [ip]` | **OPEN + CLOSED** のみ（DB） |
| `scout -re` / `--report-exploits [ip]` | **EXPLOITS** のみ（DB、再 search なし） |
| `scout -se` / `--search-exploits [ip]` | searchsploit を実行してキャッシュ |
| `scout -r -se [ip]` | search してからフルレポート |
| `scout -d` / `scout --dirs [path] [ip]` | gobuster dir のみ。`-d /admin` → `http://$IP/admin/`。**完了まで自動 watch** |
| `scout -s` / `--status [ip]` | dirs ジョブの状態を **1 回**表示 |
| `scout -ws` / `--wait-dirs [sec]` | dirs 状態を自動更新。**running が 0 になったら終了**（`-s` の対） |
| `scout -n` | 実行せずコマンド計画を表示 |
| `scout --force` | Phase 1 の再スキャン、Phase 3 dirs の再 dispatch（**`-se` には不要** — `-se` は常に refresh） |

**前提:** `$IP` または `[ip]`。Web 探索対象は DB 上 **open** かつ **service が Web 系**（`http` / `https` / `nginx` 等）のポート。`scout -d` は事前に Phase 1 が済んでいること（未スキャンなら `scout` を先に実行）。

### Phase 1 — ポートスキャン

内部で `scan`（top 1000、`-sC -sV`）を 1 回実行。結果は `recon.db` の ports / coverage に記録。

### Phase 2 — サービスプローブ（同期）

**open の全ポート**を走査し、DB の **service** 名が **SSH / Web 系**（および ftp）に合うものだけ短いプローブを実行する（22 / 80 固定ではない。8080 の tomcat 等も対象）。

| service（例） | プローブ |
|---------------|----------|
| `ssh` | nmap `ssh2-enum-algos` |
| `ftp`（`sftp` 除く） | `curl` ftp |
| Web 系（`http` / `nginx` / `apache` / `tomcat` 等） | `curl` |

service 不明のポートはスキップ（プローブ結果で service を上書きしない）。出力はコンソールと **`executions`**（`el` / `ev`）。`task_type`: `scout-ssh`, `scout-http`, `scout-https`, `scout-ftp`。

**再実行:** 同一 `ip` + **command** で過去に **成功**（`done`, `exit_code=0`）があれば再実行せず `(cached)` と表示する。`http://IP/` と `http://IP:80/`、`https://IP/` と `https://IP:443/` は URL 正規化により同一扱い。非標準ポート（例: `:8080`）はポート付きのまま別 probe。**`scout --force` は probe には効かない**（dirs / scan / exploit のみ）。

### Phase search-exploits — searchsploit（同期）

Phase 2 の後（`scout` 本番実行時）、**open ポート**の `service` / `version`（nmap `product` + `version` + `extrainfo`）から `searchsploit -j` を実行。DoS / PoC は `--exclude` で除外し、**remote / webapps** 系を優先してポートごとに最大 **5 件**を `artifacts`（`exploit_report` JSON）へ保存。

**`scout -r` の EXPLOITS は再検索不要:** 各候補に **title / 絶対パス / run コマンド / `searchsploit -m EDB`** を載せる。生 JSON は `ev <id>`（`executions` キャッシュ）に残る。

| 入力例 | searchsploit クエリ |
|--------|---------------------|
| `http` + `Apache httpd 2.4.49` | `Apache httpd 2.4.49` |
| `mysql` + `5.7.33` | `5.7.33` または product 行 |
| `http` のみ（product 不明） | スキップ（広すぎる） |

`task_type`: `scout-exploit`。詳細 stdout は `ev <id>`。サマリは **`scout -r`** の `--- EXPLOITS ---`。

```bash
scout -se                # searchsploit → キャッシュ
scout -re                # キャッシュ済み EXPLOITS を表示
scout -rp                # ポート一覧のみ
scout -r                 # フルレポート
scout -r -se             # 検索してからフルレポート
scout -se                # searchsploit -u 後など、明示的に再検索（常に refresh）
```

### Phase 3 — ディレクトリ探索（非同期）

Phase 1 後に Web 系 open ポートがあれば、**ポートごと**に gobuster dir を **バックグラウンド**で起動する（例: 80 と 8080 が両方 Web なら並列 2 本）。

- **既定:** `$GB_WORDLIST`・`$GB_THREADS`（`gb-set-web` / `gb-set-threads` と同系）。上書きは `scout --dirs` のフラグ（詳細は `scout -h`）。
- **ログ:** `cases/<case>/logs/`（`gb-dirs` と同様の命名規則）。
- **ジョブ管理:** `recon.db` の `scout_jobs`（種別・URL・状態・ログパス）。同一 **URL + ワードリスト**で **running** または **done** のジョブがあれば再 dispatch しない（`http://IP/` と `http://IP:80/` は同一扱い。**`scout --force`** で再実行）。
- **コンソール:** gobuster のリアルタイム出力は出さない。`scout` / `scout -d` 実行後は **自動で dirs watch**（`-ws` 相当）。単独確認は **`scout -s`** / **`scout -ws`**。

```bash
scout
scout -r
scout -s
scout -ws
scout --dirs -w /path/to/list.txt -t 20
scout -d /admin
scout -d http://$IP:8080/
scout --force              # dirs / scan をやり直す
```

### `scout -s` / `-ws` / `-r` の PATHS

`-s` と `-r` は **ジョブ一覧（メタデータ）** と **PATHS（統合ツリー）** を分けて表示する。

| ブロック | 内容 |
|----------|------|
| **jobs** | id・URL・wordlist 名・状態・pid・ログパス（ヒット本文は出さない） |
| **`--- PATHS ---`** | 表示対象ジョブの dirs ヒットを **サイトルート基準の階層ツリー**にマージ |

`-s` の jobs は **完了分を古い順**（新しいものが下）、**running は常に末尾**。完了ジョブの表示上限は **`SCOUT_STATUS_SLOTS`**（既定 **4**、並列 dirs 本数に合わせて調整）。超過分はヘッダに `N older hidden`。

`-r` の PATHS は **URL ごとに最新の dirs ジョブ**だけをマージする（再実行なし・DB のみ）。

**PATHS の例**（ルート dirs + `-d /etc/` の結果を統合）:

```
--- PATHS ---
http://10.49.140.183/
  admin/  301
  etc/  301
    squid/  301
```

数字は gobuster の HTTP ステータス。200 / 301 / 302 / 401 のみ表示（ノイズ・拡張子 fuzz は除外）。

### 出力の見方

| 種別 | 確認方法 |
|------|----------|
| 偵察サマリ（ポート + PROBES + PATHS + EXPLOITS） | **`scout -r`** |
| ポートのみ | **`scout -rp`** |
| exploit 一覧（DB） | **`scout -re`** |
| exploit 検索（キャッシュ更新） | **`scout -se`** / **`scout -r -se`** |
| スキャン・同期プローブ | コンソール、`el` / `ev`（probe は成功済みなら `(cached)`） |
| ディレクトリ探索（ジョブ + PATHS ツリー） | **`scout -s`** / **`scout -ws`**、ログファイル |

手動で gobuster を回す場合は下記「Gobuster」の `gb-dir` / `gb-dirs` を使う。

---

## 認証情報（recon DB）

| コマンド | 説明 |
|----------|------|
| `creds-add [ip] <user> <pass>` / `ca` | 手動登録（`???` 等の仮置きは `noglob` 付き alias。更新後は `exec zsh`） |
| `creds-list [ip]` / `cl` | 一覧 |
| `creds-rm [ip] [user]` / `cr` | 削除（user 省略で IP の creds すべて。`?` 等は `noglob` 付き alias） |
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
| `ssh-get` / `sget` | `cl` creds で **scp ダウンロード**（`-o` 保存先、`-r` 再帰） |

**注意:** `-l` は OpenSSH の login user ではなく **ログ保存**。ユーザー指定は `ssh holt` のように引数で。

```bash
sget tryhackme.asc credential.pgp
sget -o workspace/cases/tomghost ~/tryhackme.asc
sget skyfuck ~/credential.pgp
```

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
| `scout [ip]` | 偵察司令塔。`scout -r` / `scout -d` / `scout -s` / `scout -ws` |
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

偵察フローでは **`scout`** が dir 探索を起動する。直接 gobuster を回す・プリセットを細かく選ぶときはこちら。

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
| `gpg-crack [-f] [-n] [-c cred.pgp] <key.asc> [wordlist]` | gpg2john + john → `credential.pgp` 復号 → 平文の `user:pass` を `creds-add` |
| `hash-crack [-f] [-b] [-u user] <hash\|file\|url> [wordlist]` | ハッシュ文字列・ファイル・URL を john（htpasswd 等）。`-b` で creds を `borg@$IP` に保存 |
| `zip-crack <zip> [wordlist]` | zip ハッシュ |
| `borg-crack [-n] [-u user] [-p pass] <dir> [pass]` | フォルダ内の Borg リポジトリを検出 → 全アーカイブを `borg extract` |

```bash
hash-crack -b http://$IP/etc/squid/passwd   # cl: borg@$IP
borg-crack <dir>                            # cl の borg を自動使用
borg-crack -u <user> <dir>
borg-crack -p <passphrase> <dir>
```

展開先: `exports/<repo名>/borg/`（`cs` 必須）。`borg-crack` は `-u` 省略時 **cl の `borg`**（`RECON_BORG_CREDS_USER`）を優先。

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

## enc（Base64 / Base32 / Base58 / Base10）

| コマンド | 説明 |
|----------|------|
| `enc -d <str>` / `… \| enc -d` | b10 + b64 + b32 + b58 を試してデコード |
| `enc -e <str>` | 全形式でエンコード |
| `enc -t b10 -d <digits>` | 10進整数 → バイト列（ASCII） |
| `enc -t b10 -e <str>` | 文字列 → 10進整数 |
| `enc -t b64 -d <str>` | Base64 のみ |
| `enc -t b32 -d <str>` | Base32 のみ |
| `enc -t b58 -d <str>` | Base58 のみ |

`-t` 省略時は全タイプを試す。b10 は **0–9 のみ** の入力で有効。  
旧名 `b64d` `b64e` `b32d` `b32e` `b58d` `b58e` `b10d` `b10e` は alias。`enc -h`

## rot（Caesar / ROT）

| コマンド | 説明 |
|----------|------|
| `rot -a <str>` / `rot -a -f <file>` / `… \| rot -a` | シフト 0–25 をすべて表示 |

`rot -a 'MAF{...}'` → `THM{` の行（shift 7）を探す。旧名 `rotall`。`rot -h`

## vig（Vigenère）

| コマンド | 説明 |
|----------|------|
| `vig -a <cipher>` | 鍵長 1–3 を総当たり（flag らしい行だけ） |
| `vig -a --all <cipher>` | フィルタなし |
| `vig -a -n 4 <cipher>` | 鍵長上限（4 以上は遅い） |
| `vig -d -k KEY <cipher>` | 復号 |
| `vig -e -k KEY <plain>` | 暗号化 |
| `vig -K -p PLAIN <cipher>` | 既知平文から鍵を復元 |

`vig -a 'CIPHER{...}'` → `key THM: TRYHACKME{...}`。外枠が分かるとき `vig -K -p TRYHACKME '...'` → `THM`。  
`-f` / パイプ可。旧名 `vigd` `vige` `vigall` `vigkey` は alias。`vig -h`

## Magic byte 修復

| コマンド | 説明 |
|----------|------|
| `fixmagic <file>` | magic byte をチェックし、必要なときだけ修復 |
| `fixmagic -o out.png <file>` | 出力先指定 |
| `fixmagic -n <file>` | チェックのみ（修復しない） |
| `fixmagic -i <file>` | 必要時のみ上書き（`.bak` を残す） |

修復不要なら `[=] ok` で終了。PNG / JPEG / GIF に対応。  
`fixmagic broken.png` — 壊れていれば `broken_fixed.png`、正常なら何も書かない。`fixmagic -h`

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
gpg-crack -h
upsh -h
rcecurl -h
b64d -h
enc -h
rot -h
vig -h
fixmagic -h
ftp -h
ftpa -h
hydraweb   # 引数不足時に usage 表示
```

## 索引（ユーザー向けコマンド一覧）

`cs` `case-show` `case-clear` `case-open` · `ts` `target-show` `target-clear` `scout` `s` `s -rp` `s -re` `s -se` `s -r` `s -d` `s -s` `s -ws` `scan` ·
`creds-add` `ca` `cl` `creds-rm` `cr` `hydrassh` `hydraftp` `hydraweb` ·
`ssh` `ssh-list` `sget` · `ftp` `ftpa` · `listen` `rcecurl` · `ftprsh` `ftp-put-shell` ·
`stegx` · `recon-init` `net-scan` `net-view` `scan` `host-view` `host-summary` ·
`task-view` `task-done` `task-run` `host-run-next` ·
`x` `xs` `xc` `xcs` `el` `ev` `exec-form` · `artifact-add` `al` `artifact-del` ·
`gb-dir` `gb-dirs` `gb-dns` `gb-vhost` `gb-set-web` `gb-set-dns` `gb-set-threads` ·
`sshkey-crack` `gpg-crack` `hash-crack` `zip-crack` `borg-crack` · `upsh` `upload-shell` `shell-url` `shell-cmd` ·
`enc` `rot` `vig` `fixmagic` · `ports` `http` `ss` `msf` `t` `diga` `digmx` `digtxt` `digns`
