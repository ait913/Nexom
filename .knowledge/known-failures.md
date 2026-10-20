---
title: Nexom 既知失敗テスト台帳
category: gotcha
project: nexom
tags: [tests, baseline]
created: 2026-10-21
sources:
  - tests/test_parallel_storage.py
---

## Context

`Muraki/CLAUDE.md` 「ベースライン失敗の台帳」準拠。未分類の失敗を残したままのマージは不可。

## What

ベースライン (2026-10-21, main d3570cd + 1.1.41 同期): **32 passed, 1 xfailed**。

| テスト | 分類 | 内容 |
|---|---|---|
| `tests/test_parallel_storage.py::...comp_img` (xfail) | テスト陳腐化 (実装側の欠陥) | `comp_img` が存在しない `format_psc_contents_id` を呼ぶため xfail 指定。実装のバグをテストが追認している状態。セキュリティ強化の設計で扱いを決める |

## How to apply

新たな失敗が出たら本表に追記し、分類 (テスト陳腐化 / 環境依存 / 未分類) を付ける。未分類が残る間はマージしない。
