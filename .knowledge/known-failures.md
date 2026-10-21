---
title: Nexom 既知失敗テスト台帳
category: gotcha
project: nexom
tags: [tests, baseline]
created: 2026-10-21
sources:
  - tests/
---

## Context

`Muraki/CLAUDE.md` 「ベースライン失敗の台帳」準拠。未分類の失敗を残したままのマージは不可。

## What

ベースライン (2026-10-21, main = http-hardening + storage-deps-hardening マージ後): **全 pass、xfail 0**。

| テスト | 分類 | 内容 |
|---|---|---|
| (なし) | | 旧 xfail `test_comp_img_webp` (実装の `PsFileTypesError()` TypeError が真因) は storage-deps-hardening で実装を修正し、Reviewer が commit 経由の実画像テスト (D-1) に書き直して解消 |

## How to apply

新たな失敗が出たら本表に追記し、分類 (テスト陳腐化 / 環境依存 / 未分類) を付ける。未分類が残る間はマージしない。
