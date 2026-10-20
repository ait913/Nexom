# Nexom — プロジェクト固有メモ

親規約: [Muraki/CLAUDE.md](../../CLAUDE.md)

## プロジェクト要約

Touri 自作の軽量 Python WSGI フレームワーク。pip (`nexom`) で配信し、aisaba.net 系サービス (auth / aisaba_user / apps / aisaba_main / uploader 等) の全バックエンドがこれで動く。一般ユーザーを受け入れるサービス (Bloom 等) を控えており、**2026-10 からは「aisaba.net 系の穴を塞ぐ」一手目としてセキュリティ強化が主題**。

## 主要ドキュメント

- 設計書: `.designs/<YYYYMMDD>-<feature-slug>.md` (Architect が作成)
- プロジェクト固有ナレッジ: `.knowledge/<topic>.md`、既知失敗台帳 `.knowledge/known-failures.md`
- 公式ドキュメント: https://nexom.aisaba.net/documents/<章名> (GetStarted / Auth / Request / Response / Path / Middleware / Cookie / Database / ParallelStorage / Template / Build / Run / Error / Log / ObjectHTML)
- スタック全体像 (Appera / Nexom / aisaba_platform): `Muraki/knowledge/library/aisaba-stack.md`
- 外部診断 (2026-10-12, Codex): `Developments/cyber-security-agent/reports/aisaba-nexom-20261012.md` — AIS-01 (ObjectHTML 無エスケープ、本番実証) / NEX-02 (ParallelStorage remove の所有者チェック欠如) / NEX-03 (Static index.html 再解決後の境界未検査)

## 技術スタック

- 言語: Python >= 3.10、WSGI (gunicorn で常駐)
- 依存: `gunicorn`, `multipart`, `Pillow` (pyproject.toml)
- DB: SQLite (`nexom.app.db`、`AuthDBM`、`ParallelStorageDBM`)
- 配信: PyPI `nexom` (アカウント ait913)。GitHub `ait913/Nexom` (public, MIT)
- テスト: pytest (`tests/`)、venv は `.venv/`

## 規約・やらないこと

- ルーティングはクラスベース (`Router(Get(...), Post(...), Static(...))`)。デコレータ方式は採らない (暗黙性を避ける設計思想)
- セキュリティ修正は **既定を安全側に** (opt-in でなく opt-out)。既存アプリの互換性を壊す変更は設計 doc に移行手順を必ず書く
- 本リポジトリの main = PyPI の最新版と一致させる (2026-10-21 に 1.1.41 の未コミット差分を取り込んで同期済)

## 主要ワークフロー

### テストを回す

```
cd Muraki/projects/nexom
.venv/bin/python -m pytest -q
```
venv が無ければ `python3 -m venv .venv; .venv/bin/pip install -e . pytest`。ベースライン (2026-10-21): 32 passed, 1 xfailed (台帳参照)。

### PyPI へリリース

1. `pyproject.toml` の `version` を上げる (`src/nexom/__init__.py` の `__version__` は長年 1.1.0 のまま。揃える扱いは設計で決める)
2. `python -m build` → `twine upload dist/*` (PyPI 認証は Touri 所有。Leader は実行前に承認を取る)
3. aisaba 側は各サービスの venv で `pip install -U nexom` → `systemctl restart nexom@<service>`

### aisaba 本番への反映

`Muraki/knowledge/library/aisaba-stack.md` の「デプロイフロー」参照 (dev push → codeserv pull → `systemctl restart nexom@<service>`)。将来はコンテナ化 + Coolify 管理へ移す構想 (未着手)。

## デプロイ / 外部リソース

- PyPI: https://pypi.org/project/nexom/
- GitHub: https://github.com/ait913/Nexom
- ドキュメントサイト: https://nexom.aisaba.net/documents
- 利用側: `Developments/Projects/aisaba_platform` (GitHub `ait913/AisabaPlatform`)
