# workspace

コンテナ内の作業ディレクトリ。ホストの `./workspace` が `/workspace` にマウントされる。

**データの分け方**

| 種類 | 置き場所 |
|------|----------|
| 構造化ログ（コマンド履歴・ホスト・credentials 等） | `recon/recon.db` |
| ファイル出力（シェルログ・ハッシュ・メモ） | `cases/<name>/` |
| 外部 exploit | `exploits/` |
| 自作ペイロード | `payloads/` |

コマンドの使い方は [COMMAND.md](../COMMAND.md)。

### SSH 認証情報（recon DB）

| 操作 | コマンド |
|------|----------|
| hydra SSH / FTP 成功後に自動保存 | `hydrassh` / `hydraftp`（または `x` 経由） |
| 手動登録 | `creds-add [ip] <user> <pass>` |
| 一覧 | `creds-list` / `cl` / `ssh-list` |
| パスワード入力なしで接続 | `ssh` / `ftp`（DB に creds あり。`ssh` は `sshpass`） |
| 匿名 FTP | `ftpa` / `ftp -A <host>` |
| 素のクライアント | `command ssh ...` / `command ftp ...` |

### Gobuster 並列（dir）

| コマンド | 用途 |
|----------|------|
| `gb-dir` | 1 ワードリスト（`GB_WORDLIST`） |
| `gb-dirs` | 重複しにくい複数リストを並列（ログは `cases/.../logs/`） |

```bash
cs <name>
gb-dirs              # preset ctf: common + raft-small-directories + quickhits
gb-dirs -p fast      # 2 本
gb-dirs -n http://$IP   # dry-run
```

## レイアウト

| パス | 用途 |
|------|------|
| `recon/` | ReconOS の SQLite（`recon.db`） |
| `cases/<name>/` | 案件単位のファイル |
| `exploits/` | 取得した PoC・第三者 exploit |
| `payloads/` | 自作ペイロード（webshell 等） |

## recon/

ReconOS の永続化層。ここに置くのは `recon.db` のみ。

- 実行履歴・ポート・artifacts・credentials → DB
- シェルログ・john 出力・手書きメモ → `cases/`

`x` / `el` / `ev` が参照する DB パスは `/workspace/recon/recon.db`（環境変数 `RECON_DB` / `RECON_DB_PATH`）。

## cases/

1 ルーム（または 1 スコープ）= 1 ディレクトリ。ファイルを吐くツールは、先に案件を選んでから使う。

### 名前

- 先頭は英数字。続きは英数字・`.`・`_`・`-`
- `_unscoped` は予約（`CASE_LOOSE=1` かつ案件未設定時のフォールバック）

### ツリー

`cs <name>`（`case-set`）で `logs/` と `exports/` が作られる。それ以外は案件ルートに置いてよい。

```
cases/<name>/
├── logs/       # listen -l, ftpa -l, ftp -l など
├── exports/    # ハッシュ・クラック結果など
├── memo.md     # 任意
├── task.txt    # 任意
└── locks.txt   # 任意
```

### 案件未設定でファイルを書くとき

| 状態 | 出力先 |
|------|--------|
| `CASE` 設定済み | `cases/<name>/` |
| 未設定 + `CASE_LOOSE=1` | `cases/_unscoped/`（警告） |
| 未設定（既定） | エラー |

環境変数: `CASE`, `CASE_HOME`（`/workspace/cases/<name>`）, `CASE_ROOT`（`/workspace/cases`）。

## exploits/

ルーム用にダウンロードした exploit や PoC。案件とは独立した置き場。

## payloads/

アップロード・webshell 用の自作ファイル。

```
payloads/
└── webshells/
    └── shell.phtml   # upsh 等の既定パス
```
