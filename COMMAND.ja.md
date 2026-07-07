# コマンドリファレンス（kali-linux）

Kali コンテナの zsh に載っている **自作ラッパ** の使い方。

フラグの詳細は各コマンドの `-h` / `--help` を正とする。

**記述:** 本文は **フルコマンド名** を正とする。短縮 alias は補助（各節・表の末尾に記載）。

## 前提

| 変数・概念 | 説明 |
|------------|------|
| `$IP` | 調査対象 IP（`target-set` / `cases/<room>/.target`、`cases sync` で自動復元） |
| `cases set <room>` | ルーム用 `cases/<room>/` を用意して選択（下記「ルーム」参照。short: `c set <room>`） |
| Recon CLI | `recon/`（コンテナ内 `/opt/recon/recon.py`）。zsh ラッパ経由で使用 |
| `recon.db` | Recon CLI の DB（`/opt/recon/data/recon.db`、ホスト `recon/data/recon.db`） |
| `RECON_PASSLIST` | john / hydra / stegcracker の既定ワードリスト |
| `GB_VHOST_WORDLIST` | `scout -v` IP モード用（既定: raft-small-words） |
| `GB_DNS_WORDLIST` | `gb-dns` 用（`gb-set-dns`） |
| `GB_THREADS` | `gb-dns` / `scout -v` のスレッド（既定 40） |
| `GB_VHOST_EXCLUDE_LENGTH` | `scout -v` domain の ffuf `-fs` 手動上書き（未設定時は 3× probe → `-fs` または `-ac`） |
| `GB_VHOST_MATCH_CODES` | `scout -v` domain の ffuf `-mc` 補助（既定: `200-299,301,302,307,401,403,405,421,422,500`） |
| `GB_VHOST_NO_MC` | 非空なら `-mc` を付けず差分フィルタ（`-fs`/`-ac`）のみ |
| `GB_VHOST_SKIP_HTTP_REDIRECT` | 非空なら HTTP が redirect-only と判断されたとき ffuf をスキップ（既定は advisory のみ） |
| `SCOUT_STATUS_SLOTS` | `scout -s` / `-ws` で表示する **完了 dirs ジョブ**の上限（既定 **4**） |
| `CASE_LOOSE=1` | ルーム未設定時に `cases/_unscoped/` へフォールバック |
| `CASE_ROOT` | `/workspace/cases`（`CASE_HOME` の親） |
| `RECON_DATA` | `/opt/recon/data`（DB ディレクトリ） |
| `RECON_DB` / `RECON_DB_PATH` | `/opt/recon/data/recon.db` |

```bash
cases set startup
target-set 10.49.140.156
# 別タブ（cwd が cases/startup/ なら）:
cases sync                # または target-set だけ（.target 再読込）
target-show
```

素の OpenSSH / ftp クライアント: `command ssh ...` / `command ftp ...`

---

## workspace（`/workspace`）

ホスト `./workspace` がコンテナ `/workspace` にマウントされる。

| パス | 内容 |
|------|------|
| `cases/<room>/` | TryHackMe ルーム単位のファイル（下記） |
| `exploits/` | ダウンロードした PoC・第三者 exploit（ルーム非依存） |
| `payloads/` | 自作ペイロード（webshell 等。`upload-shell` 既定は `payloads/webshells/shell.phtml`） |

構造化データは Recon CLI → `recon.db`、シェルログ・クラック出力・手書きメモは `cases/<room>/`（`logs/` `exports/` またはルート直下）。

---

## ルーム（`cases/`）

`cases set` は **cd だけではない**。TryHackMe の 1 ルーム（または 1 スコープ）用の作業ディレクトリを **作成・選択** する。短縮は `c set`。

### `cases set <room>` がすること

1. **ディレクトリ作成** — 無ければ `mkdir -p`
   `/workspace/cases/<room>/`
   および必須サブディレクトリ `logs/` `exports/`
2. **セッション変数** — `CASE=<room>`, `CASE_HOME=/workspace/cases/<room>`
3. **作業ディレクトリ** — `cd "$CASE_HOME"`
4. **入場時フック**（`_case-on-enter`）
   - `cases/<room>/.target` があれば → `$IP` を読み込み
   - `cases/<room>/ftp-shell` があれば → `ftp-revshell` 用パスを読み込み（メッセージ表示）

**自動では作らないもの**（必要なら自分で置く）: `.target`, `ftp-shell`, `memo.md`, ルームから取得した `*.jpg` など。
それらは `CASE_HOME` 直下に直接置いてよい。

**TryHackMe で IP が変わったとき:** `target-set <新IP>` — 直前 target に recon / creds データがあれば **自動継承**し、旧 IP は `cases/<room>/lineage` に蓄積（3 回以上の reboot も scope に残る）。さらに `hosts <room>.thm` 相当も自動適用されるため、ルームの apex も現在の target IP に追従する。`cases/<room>/.hosts` の旧 IP 行も **新 IP に自動置換**して `/etc/hosts` を更新。`exec-list` / `creds-list` / `scout -r` は **lineage + 現在 IP** の recon scope を表示。pivot は `target-set <ip> --new`（lineage クリア・hosts IP 置換なし）、継承元の手動選択は `target-set <ip> --pick` または `cases ips` で一覧。

```bash
cases set startup
# [+] case: startup
# [+] path: /workspace/cases/startup
# [+] target: 10.49.140.156  (.../.target)   # .target がある場合
# [+] ftp-shell: .../ftp-shell               # ある場合
```

### ディレクトリ例（初回 `cases set startup` 後）

```
/workspace/cases/startup/
├── logs/          # cases set で必ず作成（listen -l, ssh -l など）
├── exports/       # cases set で必ず作成（steg-extract, john 出力など）
├── .target        # target-set で作成（任意だが推奨）
├── .hosts         # hosts コマンドで作成（THM vhost → /etc/hosts 自動適用）
├── ftp-shell      # 任意（ルーム別 FTP/HTTP パス）
└── …              # 取得ファイル・MEMO.md・locks.txt 等はルートに直接置いてよい
```

### その他のコマンド

| コマンド | 説明 |
|----------|------|
| `cases show` | 現在の `CASE` / `CASE_HOME` / `.target` / `load_from` / `lineage` |
| `cases ips` | ルーム内 IP 一覧（lineage / scope / 活動サマリ。`+` = lineage、`*` = load_from） |
| `cases load <ip\|--new\|--pick>` | 現在 IP はそのまま、継承元（lineage）だけ変更 |
| `cases clear` | `CASE` / `CASE_HOME` を unset（ディレクトリは削除しない） |
| `cases reset [-y] [<room>]` | **ルーム情報を全消去** — `cases/<room>/` の全ファイル削除（`logs/` `exports/` は空で再作成）+ recon DB の当該ルーム行 |
| `cases open` | ルームを変えず `CASE_HOME` に cd し直す |

### ルーム名のルール

- 先頭英数字、続きは英数字・`.`・`_`・`-`
- `_unscoped` は予約（`CASE_LOOSE=1` 時のフォールバック用）

### ルーム未設定のとき

`listen -l`, `ssh -l`, `steg-extract` など **ファイル出力** は `case-home` 経由で `CASE_HOME` が要る。
未設定 → エラー。`export CASE_LOOSE=1` なら `cases/_unscoped/` に警告付きで退避。

---

## exploit（PoC ランナー）

ルーム単位で exploit を選択し、**隔離 venv** 内で実行する。`cases set` 必須。状態は `cases/<room>/exploit` に保存（マルチタブ共有）。

ラッパー用メタ（短い形式）。`-u` 等の exploit 引数はそのまま転送。

| 形式 | 説明 |
|------|------|
| `<CVE-id>` | 選択 + venv + pip（例: `CVE-2021-44228`） |
| `use <id>` | 同上 |
| `<git-url>` | `git clone`（`https://github.com/<org>/<repo>.git` 等） |
| `fetch\|f <url> [id]` | 同上（明示） |
| `show` `clear` `prepare` | 状態表示 / 解除 / pip 再実行 |
| `--use` `--fetch` … | 長いフラグ（上と同義） |
| `-h` | ヘルプ |

```bash
exploit https://github.com/<org>/<repo>.git
exploit CVE-2021-44228
exploit CVE-2021-44228 -u https://target/
exploit -u https://target/
```

任意: `/workspace/exploits/<id>/exploit.manifest`（`entry=` `python=` `fetch=`）。

**注意:** 第三者 PoC は常に venv 内 python で実行（システムへの `pip install` なし）。`scout` 連携の `exploit-reject`（`erj`）とは別コマンド。

---

## ターゲット IP

| コマンド | 説明 |
|----------|------|
| `target-set <ip>` | `cases/<room>/.target` に保存し `$IP` 設定。IP 変更時は直前 target に recon / creds データがあれば **自動継承**し、**`hosts <room>.thm` 相当も自動適用**（alias: `ts`） |
| `target-set` | `.target` から `$IP` を再読込（`cases/<room>/` 以下の cwd からルーム推定可） |
| `target-set <ip> --new` | pivot — load_from なし（旧 IP の scan/dirs を引き継がない） |
| `target-set <ip> --pick` | 継承元 IP を番号で選択（last_seen + open/dirs 件数） |
| `cases sync` | `$PWD` が `cases/<room>/` 以下なら `CASE` + `$IP` を復元（別タブ向け） |
| `target-show` | 現在のターゲット IP（RHOST） |
| `lhost` | 攻撃マシン側 IP のみ出力（LHOST: tun0 → eth0） |
| `target-clear` | クリア |
| `hosts <host> [aliases...]` | `cases/<room>/.hosts` に upsert（同一 hostname は行を上書き。IP は `$IP` / `target`）して `/etc/hosts` に適用 |
| `hosts <ip> <host> [aliases...]` | 明示 IP で追記（`hosts -h`） |
| `hosts` / `hosts --off` / `hosts -e` | 表示・recon ブロック削除・手編集（`cases set` でも自動適用） |
| `scout [ip]` | **偵察の初手**（司令塔）。下記「偵察（scout）」 |
| `scan [ip]` | nmap **top 1000**（`-sC -sV`）→ DB、終了時 **OPEN + CLOSED** |
| `scan -f` / `scan --full` | **TCP 1–65535 を自動で最後まで**（1 コマンドで完走） |
| `scan --quick` / `scan -f --quick` | **簡易スキャン**（`-sS` のみ。`-sC -sV` なし。大量 open 対策） |
| `scan -f -j 4` | full を **4 並列**（1 wave あたり最大 4000 ポート、`recon.db.lock` でマージ） |
| `scan --force` | 再スキャン（basic=top 1000、full=`-p-`） |
| `scan -r` / `scan --report` | DB の OPEN + CLOSED（`scan` 終了時と同型・nmap なし） |
| `scan -n` / `-q` | dry-run / ポート表なし |

```bash
cases set startup && target-set 10.49.140.156
scout             # 偵察初手（scan → プローブ → dirs BG → dirs 完了まで自動 watch）
scout -r          # 偵察サマリ（ポート + プローブ + PATHS、再実行なし）
scout --force     # スキャン・dirs を再実行（DB は消さず上書き）
scout -s            # dirs 状態（1 回）
scout -ws           # dirs 完了まで自動更新のみ（-s の対）
exec-list && exec-view <id>     # 同期プローブの出力
scan              # ポートだけ（定番 1000）
scan -f           # 65535 完了まで自動
scan -f -j 4      # 並列 4（THM では 2–4 推奨。Ctrl+C で途中停止可）
scan -r           # ポート表だけ再表示（軽い）
cases reset -y    # ルーム全消去（複数 IP・lineage 含む）
```

coverage は **ポート番号単位**（`scan` 済みは `scan -f` でもスキップ）。ポート偵察は **`scan` / `scan -f` / `scan -r`** のみ。

---

## 偵察（scout）

**偵察の司令塔**（alias: `s`）。ポートスキャン・サービスプローブ・ディレクトリ探索を順序付きで実行する。攻撃（exploit）やルーム完走は含まない。

| コマンド | 説明 |
|----------|------|
| `scout [ip]` | Phase 1–3 + **exploit 検索** を実行。**dirs dispatch 後は自動で `-ws` 相当の watch**（running が 0 で終了） |
| `scout -r` / `--report [ip]` | DB の偵察サマリ（**ルーム統合**ポート + **OS** + プローブ + **TASKS** + **PATHS** + **HINTS** + **EXPLOITS**）。再実行なし |
| `scout -rp` / `--report-ports [ip]` | **OPEN + UNKNOWN + CLOSED** のみ（DB） |
| `scout -re` / `--report-exploits [ip]` | **EXPLOITS** のみ（DB、再 search なし） |
| `scout -ep` / `--exploit-pack [ip]` | **AI 提出資料** — searchsploit + Metasploit を更新し `cases/<room>/plans/` に Markdown 保存（パスのみ表示） |
| `scout -rt` / `--report-paths [ip]` | **PATHS** ツリーのみ（DB、dirs ヒット統合） |
| `scout -se` / `--search-exploits [ip]` | searchsploit を実行してキャッシュ |
| `scout -r -se [ip]` | search してからフルレポート |
| `scout -fp` / `--full-ports [ip]` | **TCP 1–65535**（`-sC -sV`）のみ。完了後 **自動で `-se`**（`searchsploit -u` 後は手動で `-se`） |
| `scout -fp --quick` / `scout --quick` | **簡易スキャン**（`-sS` のみ）。`--quick` はポートのみ（probe/dirs なし）、`-fp --quick` は `-se` も省略 |
| `scout -fp -j N` | 上記を N 並列 nmap で実行 |
| `scout -d` / `scout --dirs [path] [ip]` | gobuster dir のみ。`-d /admin` → `http://$IP/admin/`。**完了まで自動 watch** |
| `scout -d -x <ext> [path]` | gobuster 拡張子 fuzz（`-x` のみなら catalog **dirs-ext** の default: `common`） |
| `scout -dx /path/stem[.ext]` | **ffuf** + **ext-fuzz** リスト（`-dx` 必須。`script.txt` → `script.FUZZ`） |
| `scout -dx /path/stem.FUZZ` | 同上（stem に `.` があるときの明示マーカー） |
| `scout -dx /path/stem.*` | stem 固定で拡張子のみ fuzz |
| `scout -d /path/stem.FUZZ/` | **リテラル dir** として gobuster（末尾 `/` でマーカー無効） |
| `scout -d /path/stem.FUZZ` | **リテラル path** として gobuster（`-dx` なしでは ext fuzz しない） |
| `scout -d /path/file.ext` | **通常 gobuster** |
| `scout -d -w <id>` | カタログ id（例: `dirbuster-small`）または絶対 path |
| `scout -d`（`-w` 省略） | catalog default（`common` 等） |
| `scout -d`（URL 省略） | DB 上の全 web ポートを対象。既定では **24 個** まで（`SCOUT_DIRS_AUTO_MAX`）。**running/done/failed** の job は再 dispatch しない |
| `scout -d -w` | 対話ピッカー（`-x` で dirs / dirs-ext） |
| `scout -d -w browse` | 全カテゴリ browse |
| `scout -ds` / `-ds [path]` | **並列 dir** — **standard** tier まで（累積 3 本） |
| `-ds -x <ext>` | ext fuzz — **standard** tier まで（累積 2 本） |
| `scout -ds -p next [path]` | 次 tier の adds のみ（済み job スキップ） |
| `scout -ds -p light\|standard\|wide\|deep` | 指定 tier まで累積 |
| `scout -ds -w id -w id` | 明示 id のみ並列 |
| `scout -d -H <hostname>` / `-ds -H <name>` | vhost 向け dir — `http://$IP/` + gobuster `-H Host:<name>`（`/etc/hosts` 不要） |
| `scout -d -A <ua>` / `-ds -A <ua>` | dir 探索の `User-Agent` を指定 |
| `scout -d -C <cookie>` / `-ds -C <cookie>` | dir 探索と wildcard probe の `Cookie` ヘッダを指定 |
| `scout -d <fqdn>` | FQDN（`.` あり）は `-H` と同義（`/app.example/` にはならない） |
| `scout -v` / `--vhosts [domain\|ip]` | vhost 列挙。Domain: ffuf **HTTPS→HTTP**；3× probe（status/size/redirect/hash/headers）→ **`-fs` または `-ac`**；HTTP redirect-only は advisory（スキップは `GB_VHOST_SKIP_HTTP_REDIRECT`）；ヒットは `hosts` 自動追記 |
| `scout -s` / `--status [ip]` | dirs ジョブの状態を **1 回**表示 |
| `scout -ws` / `--wait-dirs [sec]` | dirs 状態を自動更新。**running が 0 になったら終了**（`-s` の対） |
| `scout -n` | 実行せずコマンド計画を表示 |
| `scout --no-plan` | Phase 2.5 の auth enqueue をスキップ（フル scout 時） |
| `scout --plan [ip]` | auth enqueue のみ（phase 2.5・hydra は走らせない） |
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

service 不明のポートはスキップ（プローブ結果で service を上書きしない）。出力はコンソールと **`executions`**（`exec-list` / `exec-view`）。`task_type`: `scout-ssh`, `scout-http`, `scout-https`, `scout-ftp`。

**再実行:** 同一 `ip` + **command** で過去に **成功**（`done`, `exit_code=0`）があれば再実行せず `(cached)` と表示する。`http://IP/` と `http://IP:80/`、`https://IP/` と `https://IP:443/` は URL 正規化により同一扱い。非標準ポート（例: `:8080`）はポート付きのまま別 probe。**`scout --force` は probe には効かない**（dirs / scan / exploit のみ）。

### Phase 2.5 — task-plan（同期・enqueue のみ）

Phase 2 の後、**open ポート**の service から **auth-quick** タスクを `tasks` テーブルに登録する（**hydra は走らせない**）。実行は **`strike`**。

| service（例） | task_type | 内容 |
|---------------|-----------|------|
| `ftp`（`sftp` 除く） | `auth-ftp-anon` | `ftp-quick-userpass.txt`（anonymous / ftp / guest 等の定番組） |
| `ssh`（`sftp` 除く） | `auth-ssh-quick` | `ssh-quick-userpass.txt`（空パス → user-as-pass → 追試行） |
| `postgres` / `postgresql` | `auth-pg-quick` | seclists postgres betterdefaultpasslist |
| `mysql` / `mariadb` | `auth-my-quick` | `hydra -l root -e ns` |

dedupe: `{case}:{ip}:{port}:{task_type}`。`done` / `running` は再 enqueue しない。非標準ポートは `-s {port}` をコマンドに埋め込む。

```bash
scout                    # task-plan at end
scout --no-plan          # enqueue スキップ
scout --plan [ip]        # 手動 enqueue のみ
scout --plan -n           # dry-run
strike [ip]              # pending auth タスクを実行 → cl
strike -l                  # タスク一覧
strike -l --all-case     # ルーム内全 IP
strike --force           # 完了済み auth を再実行
strike -n                # dry-run
```

環境変数: `SCOUT_NO_PLAN=1` で task-plan オフ。

### Phase search-exploits — searchsploit（同期）

Phase 2 の後（`scout` 本番実行時）、**open ポート**の `service` / `version`（nmap `product` + `version` + `extrainfo`）から `searchsploit -j` を実行。DoS / PoC は `--exclude` で除外し、**remote / webapps** 系を優先してポートごとに最大 **5 件**を `artifacts`（`exploit_report` JSON）へ保存。

**`scout -r` の EXPLOITS は再検索不要:** 各候補に **title / 絶対パス / run コマンド / `searchsploit -m EDB`** を載せる。生 JSON は `exec-view <id>`（`executions` キャッシュ）に残る。

**試して非該当と確認した候補**は手動で reject して `scout -re` / `scout -r` から除外する（未試行の候補はそのまま表示）。

```bash
exploit-reject 50383                      # EDB-50383 を非表示（$IP 向け）
exploit-reject --port 80/tcp 50383        # ポート限定
exploit-reject 50383 --note "400 Bad Request"
exploit-rejects                           # reject 一覧
exploit-unreject 50383                    # 元に戻す
```

（alias: `erj` / `erl` / `eru`）

`scout -se` で再検索しても reject は維持される。

| 入力例 | searchsploit クエリ |
|--------|---------------------|
| `http` + `Apache httpd 2.4.49` | `Apache httpd 2.4.49` |
| `mysql` + `5.7.33` | `5.7.33` または product 行 |
| `http` のみ（product 不明） | スキップ（広すぎる） |

`task_type`: `scout-exploit`。詳細 stdout は `exec-view <id>`。サマリは **`scout -r`** の `--- EXPLOITS ---`。

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

- **既定 wordlist:** **`-w` 省略時**は catalog default。**`-w` のみ**でピッカー。
- **ログ:** `cases/<room>/logs/`（`gb-dirs` と同様の命名規則）。
- **ジョブ管理:** `recon.db` の `scout_jobs`（種別・URL・状態・ログパス）。同一 **URL + ワードリスト**で **running** または **done** のジョブがあれば再 dispatch しない（`http://IP/` と `http://IP:80/` は同一扱い。**`scout --force`** で再実行）。**`-x`（extensions）はキャッシュキーに含まれない** — 同じ wordlist を別 extension で走らせたいときも `--force` が必要（例: `-x html` 済みの `common` を `-x ticket` で再 dispatch したい場合）。
- **コンソール:** gobuster のリアルタイム出力は出さない。`scout` / `scout -d` 実行後は **自動で dirs watch**（`-ws` 相当）。単独確認は **`scout -s`** / **`scout -ws`**。

```bash
scout
scout -r
scout -s
scout -ws
scout --dirs -w dirbuster-small -t 20
scout -d /admin
scout -d /admin -x bak,old,txt
scout -d /scripts/script.txt              # ffuf + SecLists ext list (script.old …)
scout -H www.example.com -d /scripts/script.txt  # vhost + extension fuzz
scout -d /scripts/script.txt -w fuzzing-file-extensions
scout -d /assets -x php,bak -t 50 -w dirbuster-small
scout -d /admin -x ticket
scout -d /admin -x ticket -w
scout -d /admin -x ticket -w dirbuster-small
scout -d /admin -w browse
scout -d http://$IP:8080/
scout -d -H www.example.com
scout -d -A 'Mozilla/5.0'
scout -d -C 'PHPSESSID=abc123'
scout -ds -H www.example.com /admin
scout -ds -C 'PHPSESSID=abc123; role=admin' /admin
scout -ds /assets
scout -ds -p next /assets
scout -ds -p wide /uploads
scout -ds -x php /backup
scout -ds -x bak -p next /api
scout -ds -p deep -t 10
scout --force              # dirs / scan をやり直す
```

### `scout -s` / `-ws` / `-r` / `-rt` の PATHS

`-s` / `-r` / **`-rt`** は **ジョブ一覧（メタデータ）** と **PATHS（統合ツリー）** を分けて表示する（`-rt` は PATHS のみ）。

| ブロック | 内容 |
|----------|------|
| **jobs** | id・URL・wordlist 名・状態・pid・ログパス（ヒット本文は出さない） |
| **`--- PATHS ---`** | 表示対象ジョブの dirs ヒットを **サイトルート基準の階層ツリー**にマージ。**IP 直スキャン**（`http://10.x.x.x/`）と **`-H` vhost スキャン**（`http://www.example.com/` 等、scheme/port は元 URL から継承）は別ツリー |

`-s` の jobs は **完了分を古い順**（新しいものが下）、**running は常に末尾**。完了ジョブの表示上限は **`SCOUT_STATUS_SLOTS`**（既定 **4**、並列 dirs 本数に合わせて調整）。超過分はヘッダに `N older hidden`。

`-r` / `-rt` の PATHS は dirs ジョブを **origin + vhost** ごとにマージする（再実行なし・DB のみ）。同一 IP:port でも `s -d` と `s -d -H www.example.com` は混ざらない。

**PATHS の例**（ルート dirs + `-d /etc/` の結果を統合）:

```
--- PATHS ---
http://10.0.0.1/
  admin/  301
  etc/  301
    squid/  301

http://www.example.com/
  login/  200
  dashboard/  301
```

数字は gobuster の HTTP ステータス。200 / 301 / 302 / 401 のみ表示（ノイズ・拡張子 fuzz は除外）。

### 出力の見方

| 種別 | 確認方法 |
|------|----------|
| 偵察サマリ（ポート + PROBES + PATHS + HINTS + EXPLOITS） | **`scout -r`** |
| ポートのみ | **`scout -rp`** |
| PATHS ツリーのみ | **`scout -rt`** |
| exploit 一覧（DB） | **`scout -re`** |
| AI 提出資料（searchsploit + MSF） | **`scout -ep`** |
| exploit 検索（キャッシュ更新） | **`scout -se`** / **`scout -r -se`** |
| スキャン・同期プローブ | コンソール、`exec-list` / `exec-view`（probe は成功済みなら `(cached)`） |
| ディレクトリ探索（ジョブ + PATHS ツリー） | **`scout -s`** / **`scout -ws`**、ログファイル |

手動で gobuster を回す場合は **`scout -ds`**（並列）または **`scout -d`**（単一 wordlist）。

---

## ヒント / メモ（recon DB）

ページから拾った文字列・codeword・「あとで調べる」メモを **ルーム（`CASE`）単位**で DB に保存。`cases set` 済みなら IP 不要。`scout -r` の **HINTS** セクションにも出る。

| コマンド | 説明 |
|----------|------|
| `hint-add [-t tag] text...` | ヒントを保存（alias: `ha`） |
| `hint-list` | 一覧（id 付き。alias: `hl`） |
| `hint-rm <id>` | 削除（alias: `hr`） |

```bash
cases set lianyu
hint-add go!go!go!
hint-add -t codeword vigilante
hint-add -t island-page 'The Code Word is: </p><h2 style="color:white"> vigilante</style><'
hint-list
scout -r          # --- HINTS --- に表示（CASE 設定時）
hint-rm 3         # id=3 を削除
```

`-t` / `--tag` は任意ラベル。同じルーム + tag + 本文は重複保存しない。

---

## 認証情報（recon DB）

| コマンド | 説明 |
|----------|------|
| `creds-add [-c comment] [ip] <user> [pass]` | 手動登録（alias: `ca`。`-c` で用途メモ。`pass` 省略でユーザー名のみ保存。`???` 等は `noglob` 付き） |
| `creds-list [ip]` | 一覧（`user<TAB>pass<TAB>comment`）。hydra / hash-crack 等は自動コメント。**`cases set` 済みなら lineage + 現在 IP**（先頭に IP 列）。`creds-list --all-case` でルーム内全 IP（alias: `cl`） |
| `creds-rm [ip] [user]` | 削除（user 省略で IP の creds すべて。alias: `cr`。`?` 等は `noglob` 付き） |
| `hash-list [--json] [ip]` | ハッシュ一覧（`user<TAB>stored<TAB>state`）。alias: `hlist` |
| `hash-add [ip] <user hash-line>` | 手動登録（alias: `hxa`） |
| `hash-rm [ip] [user]` | 削除（user 省略で IP の hash すべて。alias: `hxr`） |
| `hydrassh [-p port] [ip] <user> [wordlist]` | hydra SSH → 成功時 DB へ（`hydrassh -h`） |
| `hydraftp [-p port] [target] [user] [wordlist]` | hydra FTP（target は IP / FQDN、既定 user: anonymous、`hydraftp -h`） |
| `mklist [passwords] <url\|html> [options]` | URL または保存済み HTML からパスワードリストを生成（`mklist -h`） |
| `probe <url> [options]` | SSRF / LFI / PHP wrapper 向けの URL パラメータ probe（`probe -h`） |
| `sql <subcommand> [options]` | `sqlmap` の短縮ラッパー（`test/dbs/tables/columns/dump/auto`） |
| `reqfuzz [options] <url> <param> <start> <end>` | GET/POST リクエスト fuzz（`--deep` で詳細、`-s` で差分のみ） |
| `ffufweb <url> <user> [-fw N ...]` | POST ログイン password spray（ffuf。`-U` で username spray） |
| `hydraweb ...` | hydra http-post-form（`:F`/`:S`。`-H` vhost 可。`hydraweb -h`） |
| `hydrabasic [-p port] [ip] <user> [path] [wordlist]` | HTTP Basic 認証（hydra http-get、`hydrabasic -h`） |

`sql` は `sqlmap` の薄いラッパーで、`sql test -r req.txt`、`sql dbs -r req.txt`、`sql tables -r req.txt -D appdb`、`sql columns -r req.txt -D appdb -T users`、`sql dump -r req.txt -D appdb -T users` のような定番操作を短く実行できる。`sql auto` は `--dbs` と `--tables` を順に走らせ、`information_schema` / `mysql` / `sys` などを除外したうえで `users` / `admins` / `accounts` / `employees` など認証情報っぽいテーブルだけを優先 dump する。危険な `--os-shell` / `--sql-shell` / `--file-write` 系は自動実行しない。ルーム内では `sqlmap` と同様に既定の保存先を `exports/sqlmap` に寄せる。

`probe` は URL 中の `FUZZ`、または空のクエリパラメータ（例: `?cv=` や `?mode=view&cv=`）へ既定ペイロードまたは `--payloads` の内容を差し込んで、`file://`、`php://filter`、`data://`、loopback HTTP などの利用可否をまとめて確認する。各試行ごとに `Status`、`Length`、タイムアウト、レスポンス先頭を表示し、`/etc/passwd`、`root:x:`、`<?php`、`DB_HOST`、`Permission denied` などが見つかった場合は強調する。対象パスが `.php` で終わる場合は、追加で `php://filter/convert.base64-encode/resource=...` を `index.php` / `config.php` / 現在の PHP ファイル名に対して試し、Base64 デコード後に PHP らしい内容が見つかれば `php://filter appears usable` と表示する。ルームディレクトリ内では `file.php?x=FUZZ` や `file.php?x=`、`/file.php?x=`、`:8080/file.php?x=` のようにホスト部分を省略でき、`CASE.thm` や `cases/<room>/.hosts`、`target-set` の IP から補完する。`--raw` で全文表示、`--save` でレスポンス保存、`--json` で JSON 出力、`-o <dir>` で保存先変更ができる。

`reqfuzz` のデフォルト出力は `VALUE / STATUS / BYTES`。`--deep` で `WORDS / LINES / HASH / NOTE` を追加する。

`mklist` は URL を渡したときは CeWL を `-d 1 -m 4` で実行し、保存済み HTML を渡したときは `raw/html.html` を保存したうえで `script` / `style` / `svg` / HTML コメントを除去し、さらに Bootstrap 系の `nav` / `button` / `toast` / `small text-secondary` / `form-label` など低優先 UI 要素を落とした `work/clean.txt` を作る。その後、値寄りの行だけを `work/value_lines.txt` に残し、`small text-secondary` → `fw-semibold` のような並びから `work/pairs.tsv` としてラベル値ペアも抽出する。さらに `keyword` / `capitalize` / `year` / `append` / `exclamation` などを含むヒント文を `work/hint_lines.txt` として拾い、その近くの短い単語群を `work/hint_keywords.txt` に集めて、`Security2024!` のようなヒント駆動候補も追加生成する。抽出語は `.mklist/raw/cewl.txt`、正規化と stopword 除外後の語は `.mklist/work/base.txt` に保存する。stopword は `dotfiles/zsh/.zsh/mklist-stopwords.txt` で管理し、UI 汎用語や CSS/JS 系の一般語、低価値ラベル語を既定で除外する。HTML 由来の複合語、4〜8 桁の意味ある数字、さらに `birthdate` / `date` / `dob` と判断できる値から `Bianchi95` / `Bianchi1402` / `Bianchi2495` のような日付派生も追加する。既定出力は `exports/passwords.txt`。`--refresh` で現在の入力元から raw を再生成、`--seed <file>` で語彙追加、`--pin 4|6` で数字 PIN を追加、`--max-lines` で最大行数を制御できる。

`ssh` の自動ログインは **anonymous を除外**（FTP 用。strike `auth-ftp-anon` 成功分は `cl` に入り `ftp` で利用）。SSH 定番は **strike `auth-ssh-quick`**。

---

## SSH

| コマンド | 説明 |
|----------|------|
| `ssh [user] [ip]` | DB の creds + `sshpass`、または保存済み passwordless user で接続 |
| `ssh -i <key> [user] [ip]` | 鍵（パスフレーズは creds から） |
| `ssh [user]`（`-i` 省略） | 同一 ip+user で前回成功した `ssh -i` の鍵を自動再利用 |
| `ssh -l` / `ssh --log` | セッションを `cases/.../logs/ssh_*` に記録 |
| `ssh-list [ip]` | creds 一覧（`creds-list` と同系） |
| `ssh-get` | `creds-list` の creds、または保存済み passwordless user で **scp ダウンロード**（`-o` 保存先、`-r` 再帰。省略時 `cases/<room>/exports/scp/`。alias: `sget`） |
| `ssh-put` | `creds-list` の creds、または保存済み passwordless user で **scp アップロード**（`-r` 再帰。alias: `sput`） |
| `dav <subcommand> ...` | `curl` ベースの WebDAV ヘルパー（`ls/get/put/cat/mkdir/rm/mv`。既定は認証なし。認証要求があれば、まず `cl` から選択し、未選択なら `wampp:xampp` / `webdav:webdav` / `jigsaw:jigsaw` を試して成功時は `cl` に保存。`-u user[:pass]`、`-n/--dry-run` は表示のみ） |

**注意:** `-l` は OpenSSH の login user ではなく **ログ保存**。ユーザー指定は `ssh holt` のように引数で。

```bash
ssh-get tryhackme.asc credential.pgp
ssh-get -o workspace/cases/tomghost ~/tryhackme.asc
ssh-get skyfuck ~/credential.pgp
ssh-put /workspace/payloads/postex/linpeas.sh /tmp/linpeas.sh
ssh-put -i id_rsa script.sh /home/user/script.sh
```

---

## FTP

| コマンド | 説明 |
|----------|------|
| `ftp [user] [ip]` | DB creds で接続 |
| `ftp -l` | セッションログ |
| `ftp -A <host>` | システム ftp の匿名モード（OpenSSH の `-A` とは別） |

---

## svcguess

| コマンド | 説明 |
|----------|------|
| `svcguess <host> <port>` | TCP バナー / HTTP / HTTPS / 証明書を確認してサービス候補を推定する |

---

## Metasploit（msfr）

| コマンド | 説明 |
|----------|------|
| `msfr list` | 登録済み preset 一覧 |
| `msfr <preset> [opts]` | MSF モジュールを case 既定で実行 |

`RHOSTS` = `$IP`、`RPORT` = scout / 環境変数 / family 既定、`LHOST` = `lhost`（exploit 時）。login preset（`pg-login` / `my-login` / `ssh-login` / `ftp-login`）は **定番の簡易チェック**。DB 系は MSF 内蔵、SSH/FTP は seclists `*-betterdefaultpasslist.txt`。フルスプレーは `hydrassh` / `hydraftp`。成功時は `cl` へ自動登録。`pg-hashdump` / `my-hashdump` は `hlist` へ。続く `pg-sql` / `my-sql` 等は `$IP` の `cl` からユーザ選択（手動 `ca` も可。`SSH`/`hydra` 等の comment は除外）。`-u USER` または `msfr pg-sql USER` で指定可。

| preset | 用途 |
|--------|------|
| `pg-login` … `pg-shell` | PostgreSQL 系 |
| `my-login` … `my-shell` | MySQL 系（`mysql-*` エイリアス可） |
| `ssh-login` | SSH 簡易ログイン（定番のみ → `cl`） |
| `ftp-login` | FTP 簡易ログイン（anonymous 等 → `cl`） |
| `tomcat-mgr` | Tomcat manager upload（`-u` / `-U`） |

```bash
msfr pg-login
msfr pg-sql -n              # dry-run（コマンドと resource のみ表示）
msfr my-login
msfr my-sql -u root
msfr ssh-login
msfr tomcat-mgr -u bob -w bubbles -p 1234
msfr -m exploit/... -u user --creds --stay
```

詳細: [docs/Metasploit.md](docs/Metasploit.md)

---

## リスナー・RCE トリガー

| コマンド | 説明 |
|----------|------|
| `listen [port]` | `nc -lvnp`（既定 443） |
| `listen -l [port]` | 接続ログを `cases/.../logs/revshell_*` に保存 |
| `listen -d [port]` | `tar` ストリームを受信して `cases/<room>/exports/listen_<ts>/` に展開（`nc -lvnp PORT | tar xf - -C ...`）。ターゲット側の送信コマンドも表示 |
| `webrsh [options] [path\|url]` | Web RCE → revshell（`?cmd=` / POST）。LHOST は `tun0` → `eth0` 自動。`-u user[:pass]` で HTTP Basic（pass 省略時は `cl`） |
| `lfish [options] [path\|url]` | LFI/php://filter include → revshell。PHP filter chain を内部生成し、既定 `LHOST=lhost`、`LPORT=443`、方式は `proc`（`-t proc|bash|nc` で切替） |

`ftp-revshell` の前に **別ターミナルで `listen`** を起動する。

---

## FTP → webshell → reverse shell

| コマンド | 説明 |
|----------|------|
| `ftp-put-shell [opts] [ip]` | ペイロードを FTP put → URL 表示 |
| `ftp-revshell` | put + `webrsh` で revshell（alias: `ftprsh`） |
| `ftp-revshell -u` | upload 省略（既に置いた shell の URL のみ） |

### よく使うオプション

| オプション | 意味 |
|------------|------|
| `-d <dir>` | FTP 上のサブディレクトリ（例: `ftp`） |
| `-w <prefix>` | HTTP パス接頭（例: `/files`） |
| `-U <url>` | shell の完全 URL（パス計算スキップ） |
| `-n <name>` | リモートファイル名（既定 `shell.php`） |
| `-p <path>` | ローカルペイロード |
| `-P <port>` | revshell ポート（既定 443） |

### ケース別設定

`cases/<room>/ftp-shell`（`cases set` で自動読込）:

```bash
REMOTE_DIR=ftp
WEB_PREFIX=/files
```

例（Startup）: `http://$IP/files/ftp/shell.php`

設定なしの既定: `ftp://$IP/shell.php` → `http://$IP/shell.php`

```bash
cases set startup
listen 443           # 別ターミナル
ftp-revshell
# または
ftp-revshell -d ftp -w /files
ftp-revshell -U http://10.49.140.156/files/ftp/shell.php -u
lfish http://$IP/secret-script.php -p file
lfish /secret-script.php -p file -t bash
lfish /secret-script.php -p page -X POST -P 5555
```

詳細: `ftp-revshell -h`

---

## steghide

| コマンド | 説明 |
|----------|------|
| `steg-extract <image> [wordlist]` | info → 空 PW → stegcracker → 展開（alias: `stegx`） |
| `imgrpt [-o path] [-B] <image>` | 画像メタデータ収集 → Markdown レポート（exiftool / GPS / fixmagic / steghide / binwalk / strings） |
| `imgmap [-q] <image>` | GPS があれば Google マップ URL を出力、なければ「位置情報なし」 |
| `imgsearch [-q] [-O] [-u url] <image>` | 画像を一時アップロード → Google Lens 逆画像検索 URL（`-O` でブラウザ起動） |

`steg-extract` 出力: `cases/<room>/exports/<name>.steg.out`（ルーム未設定時は画像横）

`imgrpt` 出力: `cases/<room>/exports/<name>_imgrpt_<ts>.md`（`-B` で binwalk 省略）

ログ: `cases/<room>/logs/steg_*`

手動コマンド → [CHEATSHEET.ja.md](CHEATSHEET.ja.md)

---

## repolog（Git 履歴の徹底洗い出し）

| コマンド | 説明 |
|----------|------|
| `repolog [-o path] [-F] [-U] [-M] <repo-url> ...` | mirror clone → 全 ref のコミットを時系列で列挙（**cases set 必須**） |
| `repolog -f <url-list>` | 複数リポを一括（`github_repos.txt` など 1 行 1 URL） |
| `repolog -u <user>` / `@user` / `repolog <user>` | GitHub API でユーザのリポ一覧取得 → 一括 scan（`--user` と同じ） |
| `repolog -M [-S] [-R] -f <url-list>` | 全リポからユニークな名前+メール一覧（`-S` 個人メール疑いのみ、`-R` でリポ名付き） |

`git clone --mirror` + `git log --all --date-order`。**デフォルトブランチだけの `gh api` より漏れが少ない**（全ブランチ・タグ）。

`--user` は `type=owner` かつ **fork 除外**。`GITHUB_TOKEN` / `GH_TOKEN` で API レート緩和可。

mirror は常に `cases/<room>/exports/repolog/<host>_<owner>_<repo>.git` に保持。再実行時は **fetch のみ**（無駄な再 clone なし）。`-F` で強制再 clone。

| オプション | 説明 |
|------------|------|
| `-u` / `--user` | GitHub ユーザ名（またはプロフィール URL） |
| `@user` / `user` | 位置引数でも可（`owner/repo` とは区別: `/` なし） |
| `--forks` | `-u` と併用: fork を含める |
| `-l` | `-u` と併用: リポ一覧保存のみ（既定: `github_repos.txt`） |
| `-F` | mirror を削除して最初から clone し直す |
| `-U` | コミット URL のみ stdout（1 行 1 URL） |
| `-M` | 名前+メールのみ stdout（`name<TAB>email`、author + committer、重複除去） |
| `-S` | `-M` と併用: noreply 以外（`check`）のみ |
| `-R` | `-M` と併用: `owner/repo<TAB>name<TAB>email` 形式 |
| `-o` | レポート path（複数リポ時はディレクトリ）／`-M` 時はメール一覧ファイル |
| `-q` | 出力 path のみ |

出力: `cases/<room>/exports/<repo>_repolog_<ts>.md`（refs 一覧・コミット表・ユニークメール）

```bash
cases set sakura
repolog -u sakurasnowangelaiko             # 一覧取得 → mirror → レポート
repolog @sakurasnowangelaiko -l            # 一覧だけ（github_repos.txt）
repolog sakurasnowangelaiko -M -S          # 同上（省略形）
repolog -u someuser --forks                # fork 含む
repolog -M -f github_repos.txt             # 保存済み一覧で再実行
```

---

## Recon CLI（DB・スキャン）

| コマンド | 説明 |
|----------|------|
| `recon-init` | `recon.db` 初期化 |
| `net-scan <cidr>` | ネットワークスキャン → DB |
| `net-view` | 登録ホスト一覧 |
| `scout [ip]` | 偵察司令塔。`scout -r` / `scout -d` / `scout -s` / `scout -ws` |

## 実行履歴・成果物

| コマンド | 説明 |
|----------|------|
| `exec-run [ip] <cmd...>` | コマンド実行を記録（alias: `x`） |
| `exec-run -s [ip] <cmd...>` | サイレント（出力抑制寄り。alias: `xs`） |
| `exec-cache [ip] <cmd...>` | キャッシュ付き（同一 ip+cmd は再利用可。alias: `xc` / `xcs` は `-s` 付き） |
| `exec-list [ip]` | 実行一覧。**`cases set` 済みなら lineage + 現在 IP**（reboot 継承）。`exec-list --all-case` でルーム内全 IP、`exec-list -l` で全ホスト（alias: `el`） |
| `exec-view <id> [--tail N]` | 出力表示（alias: `ev`） |
| `exec-form <id> [--shell]` | 実行 stdout からアップロードフォーム解析 |
| `artifact-add [ip] <kind> <value> [key]` | 成果物登録 |
| `artifact-list [ip]` | 成果物一覧（`artifact-list -l` で全ホスト。alias: `al`） |
| `artifact-del <id>` | 成果物削除 |
| `lfi-loot [-k] [--name LOGICAL=TARGET] <file\|dir\|url>...` | 保存済みレスポンス / 取得ファイル / **URL** を解析し、`cases/<room>/exploits/lfi-loot/` に保存（`-k` で TLS 検証スキップ。URL に `FUZZ` を含めると既定 14 パスを自動試行） |

例: `exec-run curl -sS http://$IP/` → `exec-view <id>` → `upload-shell <id>`

---

## Gobuster

偵察フローでは **`scout -d`**（単一） / **`scout -ds`**（並列）が dir 探索の正。DNS / vhost はこちら。

| コマンド | 説明 |
|----------|------|
| `scout -d [path]` | 単一 wordlist（catalog default / `-w` / ピッカー）— 上記「偵察（scout）」参照 |
| `scout -ds [path]` | 並列 dir（default: standard tier；`-p next` で昇格） |
| `gb-dirs [opts] [url]` | **非推奨** — `scout -ds` へ委譲 |
| `gb-dns [domain]` | DNS ブルート（実 DNS 問い合わせ） |
| `scout -v [domain\|ip]` | vhost 列挙（上記 scout 表参照） |
| `gb-vhost [domain\|ip]` | **非推奨** — `scout -v` へ委譲 |

**`-ds` 省略** = **standard** tier まで（累積）。**`-p next`** = 次 tier の adds のみ。

| tier | dirs（`-x` なし）累積 | dirs-ext（`-x`）累積 |
|------|----------------------|---------------------|
| light | common, quickhits | common |
| standard | + raft-small-directories | + dirbuster-small |
| wide | + raft-small-files | + dirbuster-medium |
| deep | + dirbuster-small, raft-small-words | + raft-small-files |

aliases: `fast→light`, `ctf→standard`。旧 dirs `-p deep`（4 jobs）は **`wide`** に変更。

DNS ワードリストの対話設定:

| コマンド | 説明 |
|----------|------|
| `gb-set-dns` | `GB_DNS_WORDLIST` を選択 |

```bash
cases set overpass
scout -d /admin -x php -w dirbuster-small
scout -ds /admin
scout -ds -p next /assets
scout -ds -x php /backup
scout -ds -p wide -n
hosts example.com         # apex のみ先に登録
scout -v example.com      # HTTPS→HTTP。ヒットは hosts に自動追記
scout -v --https example.com
scout -v              # IP 直叩き vhost
gb-dns example.com    # 実 DNS がある環境向け
```

---

## クラック（john）

| コマンド | 説明 |
|----------|------|
| `sshkey-crack [-f] [-u user] <key> [wordlist]` | ssh2john + john → 成功時 `creds-add` |
| `gpg-crack [-f] [-n] [-c cred.pgp] <key.asc> [wordlist]` | gpg2john + john → `credential.pgp` 復号 → 平文を表示 |
| `hash-crack [-f] [-a] [-b] [-u user] [<hash\|file\|url>] [wordlist]` | 1行/ファイル/URL を john。引数なし（または `-a`）で `hlist` 全件バッチ → 成功時 `cl`。`-b` で creds を `borg@$IP` に保存 |
| `zip-crack <zip> [wordlist]` | zip ハッシュ |
| `rar-crack <rar> [wordlist]` | rar ハッシュ → `john` → 成功時 `unrar x` で展開 |
| `borg-crack [-n] [-u user] [-p pass] <dir> [pass]` | フォルダ内の Borg リポジトリを検出 → 全アーカイブを `borg extract` |

```bash
msfr pg-hashdump && hlist && hash-crack      # hlist → john → cl
hash-crack -b http://$IP/etc/squid/passwd   # creds-list: borg@$IP
borg-crack <dir>                            # creds-list の borg を自動使用
borg-crack -u <user> <dir>
borg-crack -p <passphrase> <dir>
```

展開先: `exports/<repo名>/borg/`（`cases set` 必須）。`borg-crack` は `-u` 省略時 **creds-list の `borg`**（`RECON_BORG_CREDS_USER`）を優先。

---

## Web アップロード（フォーム POST）

| コマンド | 説明 |
|----------|------|
| `upload-shell [opts] [<exec_id>\|]<url>` | `shell.phtml` を multipart POST（alias: `upsh`） |
| `exec-form <exec_id>` | `exec-view` で見た HTML からフォーム項目をプレビュー |
| `shell-url` / `shell-cmd` | URL 組み立て・`?cmd=` テスト |

既定ペイロード: `/workspace/payloads/webshells/shell.phtml`

```bash
exec-run curl -sS http://$IP/panel/
upload-shell 63
```

`upload-shell -h` 参照。

---

## enc（Base64 / Base32 / Base58 / Base10）

| コマンド | 説明 |
|----------|------|
| `enc -d <str>` / `… \| enc -d` | b10 + b64 + b32 + b58 を試してデコード |
| `enc -d -C <str>` / `… \| enc -d -C` | smart decode を、変化なし / 曖昧 / no match / 最大段数まで繰り返す |
| `enc -d --online <hash>` | online md5 lookup を明示的に許可 |
| `enc -e <str>` | 全形式でエンコード |
| `enc -t b10 -d <digits>` | 10進整数 → バイト列（ASCII） |
| `enc -t b10 -e <str>` | 文字列 → 10進整数 |
| `enc -t b64 -d <str>` | Base64 のみ |
| `enc -t b32 -d <str>` | Base32 のみ |
| `enc -t b58 -d <str>` | Base58 のみ |
| `enc -t hex -d <str>` | hex のみ |
| `enc -t ascii -d <list>` | ASCII 10進列のみ |
| `enc -t morse -d <str>` | Morse のみ |
| `enc -t bcrypt -d <hash> -w <wordlist>` | bcrypt を john でクラック |

`-t` 省略時は全タイプを試す。b10 は **0–9 のみ** の入力で有効。`enc -d`（alias: `dec`）。online lookup は **既定で無効** で、`--online` 指定時のみ有効。`-w <file>` でハッシュ系クラック時の wordlist を上書きできる（既定: `RECON_PASSLIST`。bcrypt / md5 / ntlm / sha1 / sha256 など）。`-C` / `--chain` で連鎖デコード、`--max-depth N` で段数上限（既定 5）。
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
| `magic <file>` | magic byte からファイル種別を推定 |
| `magic -r TYPE [-o out] <file>` | 修復して保存（`-o` 省略時は自動で `<name>_<type>.<ext>`） |

修復不要なら `[=] ok` で終了。PNG / JPEG / GIF に対応。
`fixmagic broken.png` — 壊れていれば `broken_fixed.png`、正常なら何も書かない。`fixmagic -h`
`magic broken.png` — `PNG` / `JPEG` / `GIF` / `BMP` / `WEBP` / `ICO` / `ZIP` / `RAR` / `7Z` / `GZIP` / `PDF` / `ELF` を推定。`magic -h`
`magic -r PNG broken.bin` — `broken_png.bin` のように自動保存。`-o` で別名保存。`magic -h`

---

## エイリアス

### ラッパ

| フルコマンド | alias |
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

### その他

| コマンド | alias |
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

## ドキュメントに載せないもの

内部ヘルパ（直接は使わない）: `ftp-login`, `ssh-login`, `target-load`, `case-home`, `_revshell-lhost` など。
`python3 $RECON_APP …` は上記 zsh コマンド経由が正。

---

## ヘルプ一覧

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
hydraweb   # 引数不足時に usage 表示
hydrabasic -h
```

## 索引（ユーザー向けコマンド一覧）

フル名のみ。括弧内は alias。

`cases set`（`c set`）`cases show` `cases clear` `cases reset` `cases open` `cases sync` `cases load` ·
`target-set`（`ts`）`target-show` `target-clear` ·
`scout`（`s`）`scout -r` `scout -rp` `scout -re` `scout -ep` `scout -rt` `scout -se` `scout -d` `scout -ds` `scout -s` `scout -ws` ·
`scan` ·
`creds-add`（`ca`）`creds-list`（`cl`）`creds-rm`（`cr`）`hydrassh` `hydraftp` `hydraweb` `hydrabasic` ·
`hint-add`（`ha`）`hint-list`（`hl`）`hint-rm`（`hr`） ·
`hash-list`（`hlist`）`hash-add`（`hxa`）`hash-rm`（`hxr`） ·
`ssh` `ssh-list` `ssh-get`（`sget`）`ssh-put`（`sput`）· `ftp` · `listen` `webrsh` `lfish` · `ftp-revshell`（`ftprsh`）`ftp-put-shell` ·
`steg-extract`（`stegx`）`imgrpt` `imgmap` `imgsearch` `repolog` · `recon-init` `net-scan` `net-view` ·
`exec-run`（`x`）`exec-cache`（`xc`）`exec-list`（`el`）`exec-view`（`ev`）`exec-form` ·
`artifact-add` `artifact-list`（`al`）`artifact-del` `lfi-loot` ·
`exploit` · `exploit-reject`（`erj`）`exploit-rejects`（`erl`）`exploit-unreject`（`eru`）·
`gb-dirs` `gb-dns` `gb-vhost` `gb-set-dns` ·
`sshkey-crack` `gpg-crack` `hash-crack` `zip-crack` `rar-crack` `borg-crack` · `upload-shell`（`upsh`）`postcmd`（`pcmd`）`shell-url` `shell-cmd` ·
`pop3`（`p3`）`pop3-list`（`p3l`）`pop3-get`（`p3g`）`pop3-dump`（`p3d`）`hydrapop3` ·
`enc`（`dec`）`rot` `vig` `fixmagic` · `msfr` · `ports` `http` `ss` `msf` `t` `diga` `digmx` `digtxt` `digns`
