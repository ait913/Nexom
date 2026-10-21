# Changelog

## 1.2.0 — 2026-10-21 (security hardening, breaking)

静的セキュリティ監査 (53 件) と 2 系統のリリース前レビューを経た、フレームワーク既定を安全側に倒すリリース。**互換性を壊す変更を含む。** 既存アプリの移行手順は各設計 doc の移行ガイド (`.designs/20261021-http-hardening.md` §19 / `20261021-auth-hardening.md` §10 / `20261021-storage-deps-hardening.md` §8) を参照。

### HTTP 層
- **ObjectHTML / テンプレートは既定で自動エスケープ**。信頼済み HTML は `Markup`、URL 属性は `safe_url()`、JS への値渡しは `json_script()`。`<script>`/`<style>` 本文、引用符なし属性、`on*` / `srcdoc` / `style` 属性、タグ名・属性名位置、コメント・CDATA 内のスロットはテンプレート読み込み時に `TemplateUnsafeSlotError` (OH06)。スロット位置の分類は WHATWG 準拠の 1 パス HTML トークナイザ (script 副状態、RCDATA/RAWTEXT、foreign content / integration point / breakout)
- **Cookie API を再設計**: `Cookie(name, value, *, max_age, expires, path, domain, secure=True, http_only=True, same_site="Lax")`、`Cookie.delete()`。RFC 6265 の文字検証。旧 `Max_Age=` / `MaxAge=` 等のキーワードは `TypeError`
- **Response**: `headers=` は Content-Type を消さず併合。全応答に `X-Content-Type-Options: nosniff` / `X-Frame-Options: DENY` / `Referrer-Policy` / 最小 CSP (`frame-ancestors` 等)。ヘッダ値 (content_type 含む) の文字検証
- **Redirect**: 外部 URL・プロトコル相対・先頭空白/TAB/制御文字を既定で拒否 (`allow_external=True` で外部のみ許可)
- **Request**: `files()` に Content-Length / パート / ディスク上限 (超過 413)、`Request.client_ip` と信頼プロキシ段数 (`trusted_proxy_count`)、不正 Cookie に寛容、`RequestCookies` はマッピングを受ける。JSON/フォーム不正は 400
- **Router**: パス一致・メソッド不一致は 405 + `Allow`、OPTIONS は 204 (middleware 経由)、GET を許可するパスは HEAD も許可。`raise_if_not_exist=False` なら従来どおり `None`
- **Static**: index.html 再解決後の root 再検査、ドットファイル拒否
- **CORS**: `allowed_origins=["*"]` と `credentials=True` の併用は起動時 `ValueError`
- 雛形 (`nexom start-project` 等): bind 既定 `127.0.0.1`、`--trusted-proxy-count` (`--gateway` 指定時は 1)、wsgi は 405/413/400 を正しく返しログに制御文字を書かない。CLI 名の typo `naxom` → `nexom`

### 認証 (AuthService / AuthClient / AuthPages)
- 固定の `master_password` を廃止。master 操作は master 自身のログインパスワード再入力 (`compare_digest`)。`master/users/activate` 追加、自己 deactivate は拒否、起動時に master 行を自己修復。`AuthService(..., master_password=...)` は `TypeError`
- **総当たり対策**: アカウント軸 5 回失敗/15 分の固定ロック、IP 軸 30 回失敗/15 分、signup 10 回/時/IP、PBKDF2 の時間ベース予算 (worker の 50%)。予約方式で並行超過なし。再認証経路も同じロックを事前検査。429 `A11`
- 列挙対策: 未知ユーザーでもダミーハッシュ、`is_active` 判定は一致後、`resolve/pid` 廃止 (404)
- 入力ポリシー (signup / 変更時): `user_id` 正規表現 + 大文字小文字非区別の一意性、`public_name` 制御文字除去、`password` 8〜256 バイト。400 `A12` (`field` 付き)。login / reauth は DoS 上限 (1024) のみ
- PBKDF2 600,000 回 + `pbkdf2_sha256$iter$salt$dk` 形式、ログイン時に透過再ハッシュ (旧値条件付き UPDATE、セッション発行は同一トランザクションで再検証)。schema v2 へ起動時に冪等移行
- `allowed_clients` (既定 loopback) 外からの要求は 403 `A13`。`AuthClient.login/signup/...` に `client_ip` 必須、必須キー欠落は `AuthServiceUnavailableError`、リダイレクト非追従
- AuthPages: Cookie は `Max-Age` 相対秒 + `SameSite=Lax`、応答 body から token 除去、logout は POST のみ (form POST は常に 302 `/` + 削除 Cookie)、`page_path` は `<body data-page-path>` 属性へ
- 監査ログ (`AuthLogger`) を実配線 (LOGIN_OK/NG、LOCKOUT、SIGNUP、LOGOUT、MASTER_*)

### ストレージ (ParallelStorage / MultiPartUploader)
- **所有者 fail-closed**: 変更系は `pid` 必須、不一致は `PsPermissionError` (SQL 側も `AND pid = ?`)。参照系は `pid: str | None` を明示 (None = capability モデル)。`permission_id` を API から削除、`update_status` 削除
- 保存拡張子はコンテンツ由来 (`classify_file`、Pillow は JPEG/PNG/GIF/WEBP のみ開く)、SVG/HTML/ポリグロットは `Images` にしない。`original_suffix` 列追加、schema v2 冪等移行
- 上限: pixel 50M、寸法/品質はプリセット丸め + 拡大なし + キャッシュ再利用、チャンクは等分 + 端数 (`PsChunkSizeMismatchError`)、`min_chunk_size` 256 KiB、`max_active_uploads_per_pid` 8 (`BEGIN IMMEDIATE` で原子化、ERROR は数えない)、`gc()`
- チャンク sha 不一致は `PsChunkHashMismatchError` (PS17) で status 不変 (再送で回復)。commit 失敗時は作業ディレクトリ即削除
- DB ファイルは新規作成時のみ 0600、作業ディレクトリ 0700。`DatabaseManager.immediate_transaction()` (ネスト可、SAVEPOINT)。初期化失敗時に接続を close

### ログ・依存・パッケージング
- `nexom.core.log.sanitize_log_field()` (制御文字・改行を潰す)、`RotatingFileHandler`、`AuthLogger.event()`、`utcnow` 廃止
- 依存下限: `gunicorn>=22.0.0` (CVE-2024-1135 / CVE-2024-6827)、`multipart>=1.3.1,<3` (CVE-2026-28356)、`Pillow>=12.3.0` (libwebp / decode 系 CVE 群。Python 3.10 対応の最終系列)
- `__version__` は `importlib.metadata` で pyproject を単一ソースに

### 既知の残存リスク
- テンプレート作者が病的なマークアップ (`encoding="text&#x2f;html"`、`</p>` による foreign content の breakout、integration point 直下の CDATA 等) を書いた場合の位置分類の仕様差。遠隔到達性はない。台帳: `.designs/20261021-http-hardening.md` §21-20
- 旧版で `.svg` / `.html` 名のまま保存済みのファイルは FS 上に残る (運用で棚卸し、storage doc §8-5)

### 監査・レビューの記録
`.knowledge/security-audit-20261021/` (Researcher 3 本、Codex 外部診断との突合、Codex リリースゲート 5 パス)。
