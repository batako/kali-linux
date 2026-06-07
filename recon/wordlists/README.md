# Wordlist カタログ

`catalog.yaml` は scout などが参照する SecLists パスの正本です。

## 方針

- **全件網羅:** `/usr/share/seclists` 配下のファイルは、すべて `catalog.yaml` に **1 回だけ** 登録する。漏れ・余剰があると `wordlist validate` が FAIL になる。
- **UI からだけ選ぶ:** 運用時は scout（`-w` でピッカー）かカタログ id で選ぶ。`/usr/share/seclists/...` を直接 `-w` に書かない想定。
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
recon.py wordlist pick --for dirs-ext
recon.py wordlist pick --browse
```

scout からは **`-w` 省略 → catalog default**、**`-w` のみ → ピッカー**（`-w browse` で全カテゴリ）。env 変数による上書きはない。

## Selectors（scout UI）

| id | 用途 | default id |
|----|------|------------|
| `dirs` | `s -d`（`-x` なし） | `common` |
| `dirs-ext` | `s -d -x <ext>` の拡張子 fuzz | `common` |

### 並列 dir（`scout -ds`）

**`-ds` 省略時**は `-d -w` ピッカーと同じ selector を **全件並列**します。

| 条件 | 並列する wordlists |
|------|-------------------|
| `-ds`（`-x` なし） | **dirs** selector 全件 |
| `-ds -x <ext>` | **dirs-ext** selector 全件 |
| `-ds -p fast\|deep\|ctf` | `dirs_multi_presets` サブセット |
| `-ds -x <ext> -p fast\|deep\|ctf` | `dirs_ext_multi_presets` サブセット |

`catalog.yaml` の `dirs_multi_presets` / `dirs_ext_multi_presets`（`-p` 用）:

| preset | dirs（`-x` なし） | dirs-ext（`-x` あり） |
|--------|-------------------|----------------------|
| `ctf` | common + raft-small-directories + quickhits | common + dirbuster-small + dirbuster-medium |
| `fast` | common + quickhits | common + dirbuster-small |
| `deep` | ctf + raft-small-files | ctf + raft-small-files |

passwords / dns / fuzzing など他カテゴリは在庫用。将来、別 selector を追加する。
