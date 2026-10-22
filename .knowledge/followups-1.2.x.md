---
title: Nexom 1.2.x への持ち越し (aisaba_platform 移行のリリースゲートで見つかったフレームワーク側の欠陥)
category: gotcha
project: nexom
tags: [nexom, 1.2.x, request-json, parallel-storage, pillow, followup]
created: 2026-10-23
sources:
  - projects/aisaba-platform/.designs/20261022-nexom-120-migration.md §12
  - scratchpad codex-aisaba-release-gate.out (Codex 2026-10-23)
  - projects/aisaba-platform/.knowledge/release-gate-20261023-claude.md
---

## Context

aisaba_platform を 1.2.0 に移行する際のリリース前ゲート (Codex + Claude) で、利用側では塞げても本来はフレームワークが持つべき欠陥が見つかった。1.2.0 はリリース済なので 1.2.x で直す。aisaba 側は wsgi 境界で暫定対応している。

## What

1. **`Request.json()` が `RequestParseError` 以外を素通しする** (`src/nexom/app/request.py` の json 分岐、Leader が venv で再現)
   - `{"size": <5000 桁の整数>}` → `builtins.ValueError` (`int` の `max_str_digits` 超過)
   - 1100 階層のネスト `[[[...]]]` → `builtins.RecursionError`
   - 通常の壊れた JSON (`{x`) は正しく `RequestParseError`
   - 雛形 wsgi の例外写像は `RequestParseError` → 400 だけなので 500 になる。認証不要の JSON ルートから到達可能
   - 直し方: `json.loads` を囲む `except (ValueError, RecursionError)` で `RequestParseError` に正規化 (`json.JSONDecodeError` は `ValueError` の子なので一緒に拾える)。`form()` / `files()` の multipart パーサ側も同様に境界を確認する
2. **`comp_img()` がデコード不能画像で Pillow の `OSError` を素通しする** (`src/nexom/app/parallel_storage.py` の RGB 変換、Codex が末尾 2 バイト欠損の 32×32 JPEG で再現)
   - `classify_file()` はマジックで `Images/.jpg` と判定するので登録は通り、後段の縮小・変換で `OSError: image file is truncated`
   - 直し方: デコード/変換の境界だけで `PIL.UnidentifiedImageError` / `OSError` を捕まえ、型付きの `Ps...Error` (例 `PsUndecodableImageError`) に変換。ディスク I/O の `OSError` まで飲まないよう範囲を限定する。アップロード時 (`register`/`commit`) にも 1 回デコードして早期に拒否するのが望ましい
3. **`client_ip()` は接続元 (REMOTE_ADDR) が信頼プロキシかを検証しない** (設計上の既知事項、`request.py:28-41`)。`trusted_proxy_count>0` は「gunicorn が loopback 以外から到達不能」が前提。ドキュメント (Request 章) にこの前提を明記する。将来は `trusted_proxies=[cidr...]` で REMOTE_ADDR を検証するオプションを検討
4. (aisaba 側で判明した運用知見) 雛形 wsgi をそのまま使うサービスが AppRouter のような独自ディスパッチを挟むと、`OPTIONS` が Nexom Router の 204 経路に乗らず 405 (`Allow` には OPTIONS が入る) になる。雛形か文書で、サブルータ利用時の OPTIONS の扱いを示す

## Why

いずれも「利用側の正しいコードでも 500 になる」種類で、aisaba では wsgi 境界の `except` で塞いだが、pip 配信先の全利用者に効かせるにはフレームワークで直す必要がある。

## How to apply

1.2.1 の設計 doc を起こす時にこの 4 項目を入力にする。aisaba 側の暫定対応 (wsgi 境界の ValueError/RecursionError → 400、デコード境界の OSError → 400/404) は 1.2.1 適用後も残して害はない。
