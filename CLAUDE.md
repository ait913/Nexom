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
- 本リポジトリの main = PyPI の最新版と一致させる (2026-10-21 に 1.1.41 の未コミット差分を取り込んで同期済、同日 1.2.0 をリリース)
- テンプレートの位置分類 (トークナイザ) の WHATWG 仕様差は `.designs/20261021-http-hardening.md` §21-20 の台帳に記録し、1.2.x で扱う。脅威モデル (テンプレートは開発者が書く) を超える追加実装はしない (Touri 裁定 2026-10-21)

## 主要ワークフロー

### テストを回す

```
cd Muraki/projects/nexom
.venv/bin/python -m pytest -q
```
venv が無ければ `python3 -m venv .venv; .venv/bin/pip install -e . pytest`。ベースライン (2026-10-21): 32 passed, 1 xfailed (台帳参照)。

### PyPI へリリース

1. `pyproject.toml` の `version` を上げる (`__version__` は importlib.metadata で pyproject から取るので触らない)。`CHANGELOG.md` に項を追加
2. `.venv/bin/python -m build --sdist --wheel --outdir <scratch>/dist` → `.venv/bin/python -m twine check <scratch>/dist/*`
3. `git push origin main` → `git tag v<version>` → `gh release create v<version> --notes-file <notes>`
4. `twine upload` は **Touri の PyPI トークンが必要** (ローカルに `~/.pypirc` も keyring も無い)。Touri がトークンを chat で渡し、Leader が `TWINE_USERNAME=__token__ TWINE_PASSWORD=<token> .venv/bin/python -m twine upload --non-interactive <scratch>/dist/*` を実行 (出力は `sed 's/pypi-[A-Za-z0-9_-]*/pypi-***/g'` でマスク、ファイルに保存しない)。upload 後、クリーン venv で `pip install nexom==<version>` を確認。chat に貼ったトークンは Touri が失効させる (1.2.0: 2026-10-22 実施)
5. aisaba 側は各サービスの venv で `pip install -U nexom==<version>` → アプリ修正 (移行ガイド) → `systemctl restart nexom@<service>`。順序は **アプリ (AuthClient 利用側) → auth サービス** (auth doc §10.1)

### aisaba 本番への反映

`Muraki/knowledge/library/aisaba-stack.md` の「デプロイフロー」参照 (dev push → codeserv pull → `systemctl restart nexom@<service>`)。将来はコンテナ化 + Coolify 管理へ移す構想 (未着手)。

## デプロイ / 外部リソース

- PyPI: https://pypi.org/project/nexom/
- GitHub: https://github.com/ait913/Nexom
- ドキュメントサイト: https://nexom.aisaba.net/documents
- 利用側: `Developments/Projects/aisaba_platform` (GitHub `ait913/AisabaPlatform`)
