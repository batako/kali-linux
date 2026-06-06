# Wordlist カタログ

`catalog.yaml` は scout などが参照する SecLists パスの正本です。

## 方針

- **全件網羅:** `/usr/share/seclists` 配下のファイルは、すべて `catalog.yaml` に **1 回だけ** 登録する。漏れ・余剰があると `wordlist validate` が FAIL になる。
- **UI からだけ選ぶ:** 運用時は scout（Phase 3 では `-w ?`）やカタログ id で選ぶ。`/usr/share/seclists/...` を直接 `-w` に書かない想定。
- **selectors と categories:**
  - `selectors` — scout UI に出す小さな候補セット（`dirs`, `dirs-ext` など）。
  - `categories` — ディレクトリ単位の全在庫（128 カテゴリ・6184 エントリ）。

## メンテナンス（AI）

SecLists の更新やメタデータ追加が必要なとき:

1. `catalog.yaml` を編集する（追加・移動・リネーム。可能なら id は固定）。
2. kali 内で検証する:
   ```bash
   python3 /opt/recon/recon.py wordlist validate
   ```
3. `validate: OK` になるまでエラーを直す。

**ユーザー向けの生成コマンドはない。** 一括更新はメンテナー／AI が dev 用スクリプトを一度走らせ、できた YAML をコミットする。

## エントリのフィールド

| フィールド | 必須 | 説明 |
|-----------|------|------|
| `id` | はい | 全体で一意。selector 向けは短 id（`common`, `dirbuster-small` など）。 |
| `path` | はい | `root` からの相対パス（例: `Discovery/Web-Content/common.txt`）。 |
| `lines` | いいえ | 想定行数。validate で warn / error。 |
| `speed` | いいえ | `fast` / `medium` / `slow` / `heavy` — UI 用の目安。 |
| `use` | いいえ | ピッカー用の一行説明。 |

## CLI

```bash
recon.py wordlist validate [--strict-lines]
recon.py wordlist stats
recon.py wordlist list --for dirs-ext
recon.py wordlist list --category discovery-web-content
recon.py wordlist list --all-categories
recon.py wordlist resolve dirbuster-small
```

## Selectors（scout UI）

| id | 用途 |
|----|------|
| `dirs` | `s -d`（`-x` なし） |
| `dirs-ext` | `s -d -x <ext>` の拡張子 fuzz |

passwords / dns / fuzzing など他カテゴリは在庫用。将来、別 selector を追加する。
