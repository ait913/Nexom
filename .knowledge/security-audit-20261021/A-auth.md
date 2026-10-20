# Nexom 静的セキュリティ監査 — A: 認証・セッション・Cookie・ユーザー層

- 対象: `/Users/touri/Documents/Creatives/Developments/Muraki/projects/nexom` @ d3570cd (1.1.40)。読み取りのみ、リポジトリ無変更
- 読んだファイル (全行): `src/nexom/app/auth.py`, `app/cookie.py`, `app/user.py`, `templates/auth.py`, `assets/auth/{config,wsgi,gunicorn.conf}.py`, `assets/auth_page/{login,signup}.html`, `assets/app/{config,router,wsgi}.py`, `assets/app/pages/default.py`, `tests/test_auth_and_db.py`。参照のみ: `app/request.py`, `app/response.py`, `app/path.py`, `app/db.py`, `core/log.py`, `core/error.py`, `core/object_html_render.py`, `buildTools/build.py`, `__main__.py`, `tests/test_templates_and_buildtools.py`
- 先行知見: Codex 診断 2026-10-12 (`cyber-security-agent/reports/aisaba-nexom-20261012.md`)。「既定の管理操作用補助パスワード」の実体を AUTH-01 で特定
- 動的確認: 一時 DB 上で `AuthService.handler` を直接呼び出す probe (scratchpad 内、本番・リポジトリに影響なし) で主要主張を実測。該当箇所に [実測] と記す
- 基準値: OWASP Password Storage Cheat Sheet — PBKDF2-HMAC-SHA256 は 600,000 回 (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

到達条件の記法: **[雛形]** = `nexom start-project` 既定で生成されるアプリ (`/user/login/`, `/user/signup/`, `/user/logout/` が公開、AuthService は 127.0.0.1:7070) / **[aisaba]** = AuthService は localhost、各アプリは AuthClient 経由 / **[ローカル]** = AuthService に TCP 到達できる同一ホスト上プロセスが必要

---

## 所見

### AUTH-01 既定の「補助パスワード」= `MASTER_PASSWORD "NexomWebFramework"` がコードと雛形にハードコード (Codex 指摘の実体)
- 深刻度: Low
- 箇所: `src/nexom/app/auth.py:185` (`master_password: str = "NexomWebFramework"`), `auth.py:606-620` (`master_users_deactivate`), `src/nexom/assets/auth/config.py:19` (`MASTER_PASSWORD: str = "NexomWebFramework"`), `assets/auth/wsgi.py:40`, `tests/test_templates_and_buildtools.py:43` (この定数が雛形に入ることをテストが固定している)
- 内容: `master/users/deactivate` は「master の有効セッション token」+「`master_password` が設定値と一致」の二段。後者は公開リポジトリと pip 配布物に平文で入っている定数で、build.py はこれを置換しない (`_replace_many` の辞書に `MASTER_PASSWORD` のキーなし、build.py:252-262 / 319-331 / 405-416)。比較も `if master_password != self.master_password` (auth.py:619) の素の `!=`。つまり第二要素としての価値はゼロで、master セッション token が漏れれば任意ユーザーを無効化できる。他の master 操作 (`master/users/list`) はこの定数すら要求しない (auth.py:586-598)
- 到達条件: [雛形][aisaba] いずれも master の login password (`secrets.token_urlsafe(14)`、`__main__.py:135`) で得た有効 token が別途必要。Codex の「それだけでログイン不可」は正しい。単独では攻撃不能
- 修正案: (a) 雛形生成時に `secrets.token_urlsafe(32)` で生成して config に書く (`_replace_many` に `__master_password__` を追加、テスト `:43` を更新)、かつ `AuthService.__init__` の既定値を削除して必須引数化 (API 互換: 既定値に依存する呼び出しが壊れる — 雛形以外は test のみ)。(b) 比較を `hmac.compare_digest` に。(c) 設計としては「定数の二重パスワード」をやめ、master 操作は専用の短命 token か再認証 (login password の再入力) にする方が筋がよい

### AUTH-02 `_nxt` Cookie の `MaxAge` 属性が無効な属性名で出力され、有効期限制御と logout の cookie 削除が機能していない
- 深刻度: Low (機能不全。ただし素直に直すと 55 年 cookie になる罠あり)
- 箇所: `src/nexom/templates/auth.py:83` (`Cookie(KEY_NAME, sess.token, Path="/", MaxAge=sess.expires_at)`), `:140` (`Cookie(KEY_NAME, "", Path="/", MaxAge=0)`), `src/nexom/app/cookie.py:38` (`k = k.replace("_", "-")`)
- 内容: [実測] 出力ヘッダは `_nxt=TOKEN; Path=/; MaxAge=1761000000; HttpOnly; Secure;`。`MaxAge` は RFC 6265 の属性名 (`Max-Age`) ではないためブラウザは無視し、cookie はセッション cookie (ブラウザ終了まで) になる。logout 側も `MaxAge=0` が無視され、値が空文字の cookie が残る (サーバ側では token は revoke 済なので実害は小)。さらに渡している値 `sess.expires_at` は絶対 epoch 秒 (auth.py:960 `exp = _now() + ttl_sec`) なので、属性名を `Max-Age` に直すだけだと約 55 年有効の cookie を発行することになる
- 到達条件: [雛形] 全ログインで発生。[aisaba] AuthPages を使っていれば同じ
- 修正案: `Cookie(KEY_NAME, token, Path="/", Max_Age=sess.expires_at - int(time.time()), Same_Site="Lax")` (`Max_Age` は `_`→`-` 変換で正しく `Max-Age` になる [実測])。logout は `Max_Age=0` + 同じ `Path`。`Cookie` クラス側で `MaxAge` のような誤記を拒否するか、`max_age` / `same_site` を明示キーワード引数にする (API 互換: 追加のみなら非破壊)

### AUTH-03 `_nxt` Cookie に `SameSite` が無く、cookie 認証の state-changing リクエストが既定で CSRF 可能
- 深刻度: Medium
- 箇所: `src/nexom/app/cookie.py:14-31` (既定属性は `HttpOnly`, `Secure` のみ), `src/nexom/templates/auth.py:83`
- 内容: フレームワークは `_nxt` を cookie で運び、アプリは `request.cookie.get(KEY_NAME)` → `verify_token` で認証する (`assets/app/pages/default.py:16-18`)。`SameSite` 未指定の cookie を Lax 扱いにするのは Chrome 系のみで、Firefox / Safari は None 相当のまま送る。Login / Signup 自体は `application/json` の fetch のみ受理する (`request.py` `json()` が `content_type == "application/json"` を要求) ので login-CSRF は不可だが、アプリ側が form POST で状態変更するエンドポイントを作れば cookie が付いて飛ぶ。フレームワークに CSRF トークン機構もない
- 到達条件: [雛形][aisaba] cookie 認証 + form/非 JSON POST を持つアプリ全般。被害者がログイン済で攻撃ページを開く必要あり
- 修正案: `Cookie` の既定に `SameSite=Lax` を追加 (`__init__` に `same_site: str | None = "Lax"`)。加えてアプリ向けに「JSON 以外の state-changing POST は Origin/Referer 検証か CSRF token」を middleware として提供。API 互換: 既定値変更はクロスサイト埋め込み (iframe 内アプリ) を壊し得るので `None` を明示指定できる逃げ道を残す

### AUTH-04 login / signup にレート制限・ロックアウト・監査ログがなく、PBKDF2 コストが CPU 増幅になる
- 深刻度: High
- 箇所: `src/nexom/app/auth.py:261-291` (login), `:244-259` (signup), `:938-973` (`AuthDBM.login`), `:222` (`AuthLogger` を生成するが以後一度も呼ばれない — `grep logger auth.py` で 222 行のみ), `src/nexom/templates/auth.py:72-89` (`/user/login/` が無制限に proxy)
- 内容: 失敗回数・IP・ユーザー単位のいかなる制御もない。[実測] 存在するユーザーへの誤パスワード 1 回 = PBKDF2 200k 回 ≈ 0.04-0.05 s CPU (この Mac)。既定 gunicorn は sync worker 4 (`__main__.py:57`, `--auth-workers` 既定 4) なので毎秒 100 req 弱で AuthService が飽和する。AuthService は全ページの `verify_token` が依存する単一点 (`AuthClient` timeout 3.0 s、auth.py:636) なので、login 洪水 → verify がタイムアウト → `AuthServiceUnavailableError` → 雛形 `default.py` は捕捉しないため全ページ 500。加えてパスワード総当たり・credential stuffing が無制限、signup も無制限 (アカウント大量作成 → sessions/users 行が無限増加、AUTH-17)
- 到達条件: [雛形] 認証なし・インターネットから `/user/login/`, `/user/signup/` に POST するだけ。[aisaba] アプリが AuthPages か自前 login を公開していれば同様
- 修正案: AuthService 側に (1) user_id 単位の失敗カウンタ + 指数バックオフ/一時ロック (sessions と同じ SQLite に `login_attempts` テーブル)、(2) IP 単位のトークンバケット (X-Forwarded-For は信用せず、アプリ側で `REMOTE_ADDR` を渡す専用フィールドを追加)、(3) `AuthLogger.login_failed/login_success/signup/token_invalid` を実際に呼ぶ。API 互換: レスポンスに `A11 TooManyAttempts` (429) を追加、`_raise_from_error_code` と HTML の `error_code_for_message` も更新

### AUTH-05 signup / update が user_id・public_name・password に一切の制約を置かない
- 深刻度: Medium
- 箇所: `src/nexom/app/auth.py:253-258`, `:909-936` (`AuthDBM.signup` は空チェックのみ), `:343-356` (`update_public_name`), `:438-454` (`update_password` は空チェックのみ), `src/nexom/assets/auth_page/signup.html` (JS も `required` と一致確認だけ)
- 内容: [実測] `password="1"` で 201、`user_id="<img src=x onerror=alert(1)>"`, `public_name="<script>1</script>"` で 201。長さ上限なし (10 MB body まで)。`user_id` に空白・制御文字・Unicode 混同文字・大文字小文字違い (`Admin`/`admin` は別ユーザー) が通るため表示名なりすましが容易。`public_name` は雛形 `default.py:22` が `f"Hello <i>{session.public_name}@{session.user_id}</i>"` で HTML に埋め、`object_html_render.py:_apply_slots_*` はエスケープしない (Codex AIS-01 と同根) ので、雛形では self-XSS、Bloom のように他人に表示するアプリでは stored XSS の供給源になる
- 到達条件: [雛形] 公開 `/user/signup/`。[aisaba] signup 経路を持つアプリ全部
- 修正案: AuthService で正規化と検証を集中管理 — `user_id`: NFKC 正規化 + `^[a-z0-9_][a-z0-9_.-]{2,31}$` 相当 + case-insensitive UNIQUE (`COLLATE NOCASE` か小文字化保存)、`public_name`: 制御文字除去 + 長さ 1-64、`password`: 最低 8 文字 (NIST SP 800-63B 準拠)、最大 256 バイト、`A12 InvalidField` (400) を新設。表示側のエスケープは別監査 (テンプレート層) の修正に依存するが、auth 層で制御文字と長さを切るのは独立に有効。API 互換: 既存アカウントの user_id が新規約に合わない可能性 → 既存行は免除し新規のみ適用

### AUTH-06 ユーザー列挙オラクルが複数 (無認証 `resolve/pid`、signup A02、login の A04 先行、タイミング差)
- 深刻度: Medium
- 箇所: `src/nexom/app/auth.py:384-401` (`resolve_pid` — docstring 通り "without token"), `:933-934` (signup → `A02` 409), `:949-957` (`AuthDBM.login`: 行なし→即 A03、`is_active` 判定→A04、その後に PBKDF2), `:379-381`, `:424-426`
- 内容: [実測] `POST /resolve/pid {"user_id":"a"}` は token なしで `{"ok":true,"pid":"L2rD..."}`、未知 user_id は 401 A03 — 存在確認と内部 ID (pid = sessions FK の uid、permission の鍵、`UserDatabaseManager` のファイル名) をそのまま返す。login は未知ユーザー 0.0001 s / 既知ユーザー誤パスワード 0.05 s [実測] で 500 倍のタイミング差。無効化済ユーザーはパスワード不問で A04 (403) が返り「存在かつ停止中」が漏れる。signup の A02 は UI 要件上避けにくいが、レート制限 (AUTH-04) が無い状態では無料の列挙 API になる
- 到達条件: `resolve/pid` と login タイミングは [ローカル] (AuthService 直) または アプリが `AuthClient.resolve_pid` / login を公開している場合。signup A02 は [雛形] 公開
- 修正案: (1) `resolve/pid` を削除するか token 必須にして `convert/pid` に統合 (API 互換: `AuthClient.resolve_pid` 利用箇所の確認が必要 — nexom 内では tests のみ)。(2) login は行なしでもダミー salt で PBKDF2 を 1 回回し、`is_active` 判定をパスワード検証の後に移す。(3) A02 はレート制限とセットで許容
- 補足: pid 自体は login/verify 応答でクライアントに返る公開識別子なので、pid の露出だけでは権限は得られない (fail-closed、AUTH-08 参照)

### AUTH-07 AuthService に呼び出し元認証がなく、bind アドレスだけが境界。`create-auth` / `create-config --auth` の既定は 0.0.0.0
- 深刻度: Medium (既定 `start-project` は 127.0.0.1 なので雛形単体では Low、`create-auth` 経路で High 相当)
- 箇所: `src/nexom/__main__.py:66` (`create-auth --address` 既定 `"0.0.0.0"`), `:97` (`create-config --address` 既定 `"0.0.0.0"`), `:56` (`start-project --auth-address` 既定 `"127.0.0.1"` だが help 文は "default: 0.0.0.0" と矛盾), `src/nexom/buildTools/build.py:14-19` (`AppBuildOptions.address = "0.0.0.0"`), `src/nexom/assets/auth/gunicorn.conf.py:5` (`bind = f"{ADDRESS}:{PORT}"`), `src/nexom/app/auth.py:224-240` (handler に REMOTE_ADDR 検査や共有秘密なし), `:657-668` (AuthClient は平文 HTTP、認証ヘッダなし)
- 内容: AuthService のどのエンドポイントも、到達できれば誰でも叩ける (signup/login/verify/resolve-pid は無認証、permissions は任意ユーザーの token で可)。コード上の保証はゼロで、`gunicorn` の bind に全依存。`create-auth` と `create-config --auth` の既定は全インターフェースなので、Docker/VPS でそのまま起動すると認証 API がインターネットに出る。アプリ側 `AUTH_SERVER` は `http://` 固定の config 文字列 (`assets/app/config.py:19`) で TLS なし — loopback なら問題ないが 0.0.0.0 運用では平文でパスワードが流れる。また同一ホストの別プロセス (別テナントのアプリ、侵害されたアプリ) は AuthService の全機能に到達できる (aisaba の「1 ホスト複数アプリ」構成では設計通りの信頼境界だが、文書化されていない)
- 到達条件: [雛形 start-project] localhost のみ、問題なし。[create-auth / create-config] 既定でネットワーク露出。[aisaba] localhost 前提なら [ローカル] のみ
- 修正案: (1) 全 CLI の auth 側既定を `127.0.0.1` に統一し、help 文を直す (`__main__.py:56,66,97`)。(2) AuthService に `REMOTE_ADDR` が loopback でなければ 403 を返すガード (環境変数で opt-out) を入れる。(3) 長期的には app→auth 間に共有秘密 (`X-Nexom-Auth-Key` ヘッダ、`secrets.token_urlsafe(32)` を雛形生成時に両 config に書く) を導入。API 互換: (3) は AuthClient に `api_key` 引数追加 — 未指定なら従来動作、で段階導入可

### AUTH-08 permission group の名前空間がグローバル先取りで、任意ユーザーが他人の level を照会できる
- 深刻度: Low
- 箇所: `src/nexom/app/auth.py:456-477` (`permissions_group_create` — 認証済なら誰でも任意 `group_id` を作成し level 100 になる、`:1091-1102`), `:550-571` (`permissions_group_auth` — 任意 token で任意 group/pid の level を返す), `:1199-1203` (`delete` は level 100 なら可 = owner 以外でも owner が 100 を付与した人は削除可)
- 内容: アプリが「`group_id="admin"` の level で管理者判定」のように固定 ID を期待する設計だと、アプリ側がその group を作る前に一般ユーザーが同 ID を作れば level 100 を得る (squatting)。判定は `auth_permission_level_by_uid` が行なし→0 で fail-closed なので、squatting されても「本物の admin group」を後から作る側が A10 で失敗して気づく、という形でしか顕在化しない。`permissions/group/auth` はメンバー外のユーザーにも level を返すため、組織構造の情報漏えい (軽微)
- 到達条件: group 作成/照会 API をアプリが一般ユーザーに公開しているか [ローカル]
- 修正案: group 作成を master または所定ユーザーに限定するオプション、group_id に owner 名前空間 (`owner_uid/`) を強制、`group/auth` は「自分の pid」または「その group のメンバー」からのみ応答。API 互換: 既存 group_id は移行が要るので opt-in フラグで

### AUTH-09 `level` の型検査が `bool` を通す
- 深刻度: Info
- 箇所: `src/nexom/app/auth.py:515-518` (`isinstance(level_raw, int)` — Python では `bool` は `int` の派生)
- 内容: [実測] `"level": true` で level 1 が保存される。権限昇格にはならない (1 は最小限) が、入力検証の意図 (整数のみ) とズレる
- 修正案: `if isinstance(level_raw, bool) or not isinstance(level_raw, int)` で弾く

### AUTH-10 master が自分自身を無効化できる → 回復不能なロックアウト
- 深刻度: Low
- 箇所: `src/nexom/app/auth.py:600-622` (`target_user_id != self.master_user` の検査なし), `:1009-1013` (`ensure_master_user` は行が存在すれば `is_active` を見ずに return), 再有効化エンドポイントなし
- 内容: [実測] master token + `NexomWebFramework` で `target_user_id="master_user"` → 200、以後 master login は 403 A04。起動時 bootstrap も既存行があるため何もしない。復旧は SQLite を直接 UPDATE するしかない。master token を盗んだ攻撃者が運用側を締め出す手段にもなる
- 修正案: `target_user_id == self.master_user` を拒否、`ensure_master_user` で master 行の `is_active=1` を保証 (起動時自己修復)。API 互換なし

### AUTH-11 認証イベントの監査ログが実質ゼロ。例外は握りつぶされログに出ない
- 深刻度: Low
- 箇所: `src/nexom/app/auth.py:222` (`self.logger = AuthLogger(log_path)` のみ、以後未使用), `:239-240` (`except Exception as e: return JsonResponse(... "InternalError", 500)` — `e` を捨てる), `core/log.py:88-124` (`AuthLogger` の API は揃っている)
- 内容: login 失敗・signup・token 不正・master 操作のどれも記録されない。AUTH-04 の攻撃を事後にも検知できない。秘密のログ出力については確認済で問題なし — アクセスログ (`assets/auth/wsgi.py:74`, `assets/app/wsgi.py:57`) は IP/method/path/status/UA のみ、body・token・password は書かない。`AuthLogger.token_invalid` は token を先頭 8 文字に切る設計 (`log.py:106`)
- 修正案: handler の各分岐で `AuthLogger` を呼ぶ (success/failed/signup/token_invalid/master_action)、`except Exception` では `traceback` を error ログに。API 互換なし

### AUTH-12 雛形 `auth/wsgi.py` の例外経路が壊れている (NameError / `start_response` 未呼出)。`Request()` 生成が try の外
- 深刻度: Low
- 箇所: `src/nexom/assets/auth/wsgi.py:60-65` (`except NexomError as e: ... return JsonResponse(...)`, `except Exception: logger.error(e)` — `e` 未定義、かつ両分岐が `start_response` を呼ばずに Response を返す), `src/nexom/app/auth.py:230-231` (`req = Request(environ)` が `try:` の前)
- 内容: [実測] `Cookie: a<b=1` のような不正キーの Cookie ヘッダで `http.cookies.SimpleCookie.load` が `CookieError("Illegal key")` を送出し、`Request.__init__` → `AuthService.handler` の try 外 → `auth/wsgi.py` の `except Exception` に落ちて `NameError`。gunicorn が 500 を返すだけなので脆弱性ではないが、auth サービス側の例外経路は一度も実行されていないことを示す。アプリ側 `assets/app/wsgi.py:38-50` は正しく try 内で処理しているので、同じ Cookie を送ると全ページが整った 500 になる (Cookie に不正値を持つ訪問者は、該当 cookie を消すまでサイト全体が見えない — `request.py` 側の寛容化が本筋、別監査領域)
- 修正案: `auth/wsgi.py` を `app/wsgi.py` と同じ構造に (try 内で `Request`、`except Exception as e`、最後に必ず `start_response`)。`AuthService.handler` の `Request(environ)` を try 内へ。`Request._parse_cookies` は `CookieError` を捕捉して空 dict に

### AUTH-13 login 応答 JSON に token を同梱 (HttpOnly cookie の意味が薄れる)
- 深刻度: Low
- 箇所: `src/nexom/templates/auth.py:84` (`JsonResponse({"ok": True, "user_id": ..., "token": sess.token, ...}, cookie=...)`), `assets/auth_page/login.html` (JS は `r.data.token` を使わず `location.href = "/"`)
- 内容: cookie は HttpOnly で JS から読めないが、同じ token を body で返しているので、ログインページ上の XSS・ブラウザ拡張・HAR/プロキシログから token が取れる。クライアント側で使っていないので純粋な過剰露出
- 修正案: body から `token` を外す (API 互換: 自前 SPA が body の token を使っている場合は影響 — aisaba 内で確認要)

### AUTH-14 logout が GET で、Referer ベースのリダイレクト
- 深刻度: Low
- 箇所: `src/nexom/templates/auth.py:122-141`
- 内容: `<img src="/user/logout/">` で第三者が被害者をログアウトさせられる (CSRF logout、嫌がらせ級)。リダイレクト先は `referer.startswith("/")` を要求するが、ブラウザの Referer は絶対 URL なので実運用では常に `/` に落ちる (open redirect にはならない — `//evil` は Referer として送れない。確認済)。`SameSite=Lax` (AUTH-03) を入れると GET top-level navigation では cookie が付くので、logout CSRF 自体は残る
- 修正案: logout を POST (JSON) 化、または GET 時は確認ページ。リダイレクトは固定 `/` か許可リスト

### AUTH-15 `Cookie` の CRLF 検査が value のみで、属性値・名前は未検査
- 深刻度: Low
- 箇所: `src/nexom/app/cookie.py:23-31` (`"\r" in value or "\n" in value` のみ), `:33-44` (`__repr__` が属性を文字列連結)
- 内容: [実測] `Cookie("x","y", Path="/\r\nSet-Cookie: evil=1")` は例外なく `Set-Cookie` 行を 2 本分出力する。`Response.__init__` (`response.py:52`) もヘッダ値を検査しない。現状のフレームワーク内呼び出しは全て定数属性 (`Path="/"`) なので到達不能だが、アプリが `Domain`/`Path` にユーザー入力を渡せばヘッダインジェクション。gunicorn は Set-Cookie ヘッダ値の CR/LF を拒否する (InvalidHeader) ので最終防衛線はあるが、他 WSGI サーバでは保証なし。値のエンコードも無し — `token_urlsafe` の文字集合は cookie-octet 内なので `_nxt` は安全
- 修正案: name・各属性値にも `\r\n;` 検査。`Response.append_header` / `__init__` でも CR/LF を拒否

### AUTH-16 PBKDF2 反復回数 200,000 は OWASP 推奨 600,000 の 1/3
- 深刻度: Low
- 箇所: `src/nexom/app/auth.py:59-62`
- 内容: アルゴリズム PBKDF2-HMAC-SHA256、salt は `secrets.token_hex(16)` (128 bit、`:55-56`) をユーザー毎に生成、比較は `hmac.compare_digest` (`:956`, `:1055`)、パスワード変更時に salt 再生成 (`:1058`)。設計は正しい。回数のみ OWASP 2023+ 推奨 (600,000) 未満。[実測] 200k=0.041 s、600k=0.130 s。ただし反復を上げると AUTH-04 の CPU 増幅が比例して悪化するので、レート制限とセットで
- 修正案: 600,000 に上げ、`password_hash` にスキーム/反復回数を埋め込む (`pbkdf2_sha256$600000$<salt>$<hash>`) か列を追加し、login 成功時に旧回数ハッシュを再計算して移行。API 互換: DB 列形式が変わるため既存 DB は移行コード必須 (現状は `password_hash`/`password_salt` 分離の素 hex)

### AUTH-17 セッション行が無期限に蓄積、ユーザー当たりセッション数上限なし
- 深刻度: Info
- 箇所: `src/nexom/app/auth.py:963-971` (login ごとに INSERT)、期限切れ/revoked 行の DELETE は全コードに存在しない
- 内容: AUTH-04 と合わせ、匿名からの login/signup 連打で SQLite が無限に成長する。`verify` は `token_hash UNIQUE` インデックス経由なので検索性能は保つが、ディスク DoS と list_users の肥大
- 修正案: login 時に同 uid の期限切れ行を削除、または定期掃除。1 ユーザー N セッション上限

### AUTH-18 `UserDatabaseManager` が pid を無検証でファイル名に使う
- 深刻度: Low
- 箇所: `src/nexom/app/user.py:33-35` (`db_file = str(plb.Path(users_dir) / f"{pid}.db")`)
- 内容: 正規の pid は `token_urlsafe(24)` (`[A-Za-z0-9_-]`) なので安全だが、アプリが `request.json()["pid"]` のような未検証値を渡すと `../../x` で任意パスに SQLite を作成/オープンする。`verify_token` が返した `Session.pid` のみを渡す、という前提がコードに現れていない
- 修正案: `re.fullmatch(r"[A-Za-z0-9_-]{16,64}", pid)` を要求、`users_dir` 配下に resolve されることを確認

### AUTH-19 master 判定が user_id 文字列比較、`is_master` 列は未使用。`created_at` が NULL で保存される
- 深刻度: Info
- 箇所: `src/nexom/app/auth.py:596`, `:617` (`lsess.user_id != self.master_user`), `:865`/`:1027` (`is_master` 列は書くだけ), `:923-932`/`:1018-1028` (位置指定 INSERT で `created_at` に `None` → DEFAULT が効かず NULL)
- 内容: 現状は user_id UNIQUE かつ bootstrap が先行するので乗っ取り経路はない。ただし config の `MASTER_USER` を変えると「別名の master」が存在しないため起動時に `AuthServiceUnavailableError` で落ちる (fail-closed、良い)。`created_at` NULL は監査性の欠落
- 修正案: master 判定を `is_master=1` に寄せる、INSERT を列名指定にして `created_at` を DEFAULT に任せる

### AUTH-20 `_ip()` が `X-Forwarded-For` の先頭を無条件に信用
- 深刻度: Info
- 箇所: `src/nexom/assets/auth/wsgi.py:44-48`, `src/nexom/assets/app/wsgi.py:26-30`
- 内容: 現状はアクセスログ用途のみなので偽装されてもログが汚れるだけ。AUTH-04 で IP レート制限を導入する際にこの関数を流用すると、ヘッダ 1 本で回避可能になる
- 修正案: 信頼プロキシ数 (nginx 1 段なら右から 1 つ目) を config 化、直結時は `REMOTE_ADDR` のみ

### AUTH-21 AuthClient のレスポンス処理 (参考)
- 深刻度: Info
- 箇所: `src/nexom/app/auth.py:657-688`, `:706`, `:713`
- 内容: fail-closed は確認済 — `verify_token` は `d.get("active") is True` のみで Session を返す (`:712`)、`Permissions.auth` は `ok` 以外で raise (`:121-123`)、不明コードは A09 (`:838`)、timeout 3.0 s あり。弱点: (a) `Session(str(d["pid"]), ...)` は必須キー欠落で `KeyError` (NexomError でないのでアプリの `except NexomError` を抜ける)、(b) `urlopen` はリダイレクトを追従する、(c) `str(d["user_agent"])` は `None` を `"None"` に変える。(d) 通信は config の `http://127.0.0.1:7070` 平文 — loopback 前提なら許容、AUTH-07 参照
- 修正案: 必須キー欠落を `AuthServiceUnavailableError` に正規化、`HTTPRedirectHandler` を外した opener を使う

---

## チェックリスト結果表

| # | 観点 | 結果 | 根拠 / 所見 |
|---|---|---|---|
| 1 | パスワードハッシュ | 該当あり (Low) | PBKDF2-HMAC-SHA256、salt 128 bit `secrets`、`hmac.compare_digest`、変更時 salt 再生成 — いずれも確認済・良。反復 200k のみ OWASP 600k 未満 → AUTH-16 |
| 2 | トークン/セッション | 確認済・一部該当 | 乱数源は `secrets.token_urlsafe(24)` (192 bit、auth.py:51-52) → 良。HMAC 署名トークンではなく DB 保持の不透明トークン (SHA-256 ハッシュで保存、auth.py:65-66, 967) なので **HMAC 鍵の既定値・ハードコードは該当なし** (`hmac` は compare_digest のみ)。TTL 検証 `int(exp) <= _now()` (1004)、logout で `revoked_at` (980-984)、パスワード変更で全セッション失効 (1067-1071) → 良。セッション固定: token はサーバ生成のみでクライアント値を採用しない → 該当なし。蓄積の掃除なし → AUTH-17 |
| 3 | Cookie | 該当あり | 既定 `HttpOnly`/`Secure` → 良。`SameSite` 無し → AUTH-03。`Path="/"` 明示、`Domain` 未設定 (host-only、良)。`MaxAge` 属性名誤り + 絶対 epoch → AUTH-02。CRLF は value のみ検査、属性未検査 → AUTH-15。値エンコード無し (token は cookie-octet 安全)。パース (`SimpleCookie`) の不正キーで例外 → AUTH-12 |
| 4 | AuthService HTTP API | 該当あり | 入力検証: 空チェックのみ → AUTH-05。列挙: `resolve/pid` 無認証、A02、A04 先行、タイミング 500 倍 → AUTH-06。レート制限/ロックアウト: 無し → AUTH-04。CSRF: login/signup は JSON 限定で不可、logout GET は可 → AUTH-14、アプリ一般は AUTH-03。verify の呼び出し元制限: コード上ゼロ、bind のみ → AUTH-07。method は各 handler で POST を手動検査 → 良 |
| 5 | AuthClient | 確認済・Info | 平文 HTTP (loopback 前提)、認証ヘッダ無し → AUTH-07。レスポンスは fail-closed、timeout 3.0 s → 良。KeyError/redirect 追従 → AUTH-21 |
| 6 | AuthDBM | 確認済・一部該当 | SQL は全て `?` プレースホルダ (f-string/format による組み立ては auth.py 内に無し — 全 `execute` 呼び出しを確認)。権限昇格: owner 検査 (`assert_permission_group_owner` 1104-1113)、level 0-100 検査 3 箇所 → 良。グローバル名前空間 squatting → AUTH-08。ハードコード補助パスワード → AUTH-01。初期化既定アカウント: `master_user` は scaffold 時に `token_urlsafe(14)` で bootstrap、`login_password=""` なら起動拒否 (1014-1015) → 良。自己無効化 → AUTH-10 |
| 7 | Permissions | 確認済・Info | 行なし→0、pid 不明→0 で fail-closed (1181-1197)。境界 `< 0 or > 100` 3 箇所一貫。None は `isinstance(int)` で 400。bool 通過 → AUTH-09。delete は `== 100` 厳密 |
| 8 | ログに秘密 | 確認済・問題なし | アクセスログは IP/method/path/status/UA のみ、body 不記録 (assets/*/wsgi.py)。`AuthLogger.token_invalid` は 8 文字切り詰め設計。ただし AuthLogger 自体が未使用 → AUTH-11 |
| 9 | 生成雛形 (assets/auth) | 該当あり | master login password は `secrets.token_urlsafe(14)` を stdout に 1 回表示・config には書かない → 良。`MASTER_PASSWORD` は定数 → AUTH-01。デバッグ: `RELOAD` は `--auth-reload` 明示時のみ True → 良。待受: `start-project` は 127.0.0.1、`create-auth`/`create-config` は 0.0.0.0、help 文矛盾 → AUTH-07。gateway テンプレは main app のみ proxy (auth は非公開) → 良。例外経路の NameError → AUTH-12 |

## 設計への含意 (優先順)

1. ★ **AUTH-04 + AUTH-05 + AUTH-11 を 1 つの設計単位で**: 「レート制限 (user_id/IP) + 失敗ロックアウト + パスワード/ID 正規化と最小ポリシー + AuthLogger の実配線 + 新エラーコード A11/A12」。一般ユーザー受け入れ前の必須。IP は AUTH-20 の信頼プロキシ設定を同時に決める
2. ★ **AUTH-07**: CLI の auth bind 既定を 127.0.0.1 に統一 + AuthService に loopback ガード。app→auth 共有秘密は段階導入 (AuthClient に optional `api_key`)
3. **AUTH-03 + AUTH-02 + AUTH-14 + AUTH-15 を Cookie 層の 1 改修で**: `SameSite=Lax` 既定、`max_age`/`same_site` を明示引数化、相対秒へ変換、属性 CRLF 検査、logout POST 化
4. **AUTH-06**: `resolve/pid` の廃止 or token 必須化、login のダミー PBKDF2 と `is_active` 判定順の入替
5. **AUTH-01 + AUTH-10 + AUTH-19**: master 操作の再設計 (定数パスワード廃止 → 雛形で乱数生成、`is_master` 列ベース判定、自己無効化禁止、起動時 `is_active` 自己修復)
6. **AUTH-16 + AUTH-17**: ハッシュ形式のバージョン化 (反復 600k へ移行可能に) とセッション掃除 — 1 と同時に DB マイグレーションとして
7. **AUTH-12 / AUTH-13 / AUTH-18 / AUTH-21**: 小粒の堅牢化。雛形 `auth/wsgi.py` は `app/wsgi.py` と同構造に揃える

既存テスト (`tests/test_auth_and_db.py`) が守っているのは「正常系 + level 境界 + 重複 group + master deactivate」のみ。上記のどれも回帰テストが無いので、改修時は Reviewer が AUTH-ID ごとにテストを足す前提で設計 doc に挙動仕様を書くこと (特に `MASTER_PASSWORD` の定数をテストが固定している `test_templates_and_buildtools.py:43` は改修で書き換え必須)。
