# Nexom 静的セキュリティ監査 — B: HTTP 層

- 対象: `/Users/touri/Documents/Creatives/Developments/Muraki/projects/nexom` (git HEAD d3570cd = 1.1.40、pyproject 1.1.41)
- 読了ファイル: `src/nexom/app/{request,response,path,middleware,template,cookie,__init__}.py`, `src/nexom/core/{object_html_render,error,log}.py`, `src/nexom/__init__.py`, `src/nexom/assets/app/{wsgi,config,router,gunicorn.conf}.py`, `src/nexom/assets/app/pages/{default,_templates}.py`, `src/nexom/assets/auth/{wsgi,config}.py`, `src/nexom/assets/error_page/error.html`, `src/nexom/assets/auth_page/*.html` (slot 部分), `src/nexom/assets/gateway/*.conf`, `src/nexom/templates/auth.py`, `src/nexom/buildTools/{build,run}.py`, `tests/{conftest,test_request_response,test_router_static_middleware,test_core}.py`
- 検証方法: 全行 Read + `.venv/bin/python -I` で挙動プローブ (スクリプト: `/private/tmp/claude-501/-Users-touri-Documents-Creatives-Developments-Muraki/e718362d-0c6d-4987-a368-071b41717d1e/scratchpad/probe/p1.py`)。リポジトリは無変更
- 実行環境の前提: `.venv` の gunicorn 26.2.0 / multipart 2.0.1 (defnull 版。`python-multipart` ではない)。pyproject は `gunicorn>=21.2`, `multipart>=1.3.0`
- 先行知見 (Codex 2026-10-12 `aisaba-nexom-20261012.md`): AIS-01 → HTTP-01 で**確認 (該当あり)**、NEX-03 → HTTP-04 で**確認 (該当あり、プローブで実証)**

---

## 所見

### HTTP-01 ObjectHTML / ObjectHTMLTemplates のスロット展開に自動エスケープが無い (AIS-01 確認)
- 深刻度: **High** (ユーザ入力をスロットに渡した瞬間に反射型/格納型 XSS。aisaba 本番で HTML 注入実証済)
- 箇所: `src/nexom/core/object_html_render.py:190-216` (`_apply_slots_non_strict` / `_apply_slots_strict`)、`src/nexom/app/template.py:72-79`、`src/nexom/assets/app/pages/default.py:21`
- 内容: 両スロット関数とも
  ```python
  raw = str(values[key])            # L196, L210
  ...
  return raw
  ```
  で値を文字列化してそのまま埋める。`html.escape` 相当の処理はリポジトリ全体に存在しない (`grep -rn "escape(" src/nexom` → 0 件)。コンテキスト区別 (テキスト / 属性 / `<script>` 内 / URL 属性) も無い。プローブ結果:
  ```
  render("t", v='</h2><script>alert(1)</script>', u='javascript:alert(1)')
  → <h2></h2><script>alert(1)</script></h2><a href="javascript:alert(1)"><script>var x="</h2><script>alert(1)</script>"</script>
  ```
  雛形自身も `default.py:21` で `f"Hello <i>{session.public_name}@{session.user_id}</i> San!!"` を `user_message` スロットへ無エスケープで渡している (public_name はサインアップ時にユーザが決める値 → 本人にだけ表示されるので self-XSS 止まりだが、「スロットに生値を渡す」のが公式作法になっている)。
  付随: `src/nexom/templates/auth.py:74,99` は `page_path=req.path` を `login.html:150` / `signup.html:220` の `const PAGE_PATH = "/{{ page_path }}"` (JS 文字列コンテキスト) に埋める。ただし LoginPage の経路は静的セグメント完全一致 (`path.py:92-107`) なので `req.path` は `user/login` の前後スラッシュ違いしか取れず、**この箇所は現状は非悪用**。一方、将来 `{arg}` 付き経路で同じ書き方をすると即 XSS になる。
- 到達条件: 雛形で到達可能 (上記 default.py)。一般的には「ユーザ由来の文字列を `templates.render(..., x=value)` に渡す」だけ。aisaba は `/works/tag/<入力>` で実証済
- 修正案:
  1. `_apply_slots_*` で既定 `html.escape(raw, quote=True)`。信頼済 HTML 断片は `Markup`/`SafeHTML` 型 (str サブクラス) で opt-out、`Insert` 由来の値 (`_apply_extends` L117、テンプレート作者が書いたもの) は safe 扱い
  2. 互換性: 既存テンプレートで「意図して HTML 断片をスロットに流している」箇所 (雛形の `user_message` に `<i>` を入れる書き方、`{{ main }}` に部品を合成する用途) が壊れる → `Markup` でラップする移行が必要。マイナー版で `ObjectHTML(autoescape=True)` を導入し、次メジャーで既定 True が無難
  3. 属性コンテキストで `javascript:` URL は escape では防げない。「URL 属性にユーザ値を入れる時は `https?://` or 相対パスのみ許可」を doc 化、可能なら `url=` ヘルパ提供
  4. 追加防御として既定 CSP (HTTP-06)

### HTTP-02 Request.files() (multipart) に一切のサイズ/件数上限が無く、DoS (ディスク/メモリ枯渇) 可能
- 深刻度: **High** (multipart を受けるエンドポイントを 1 つでも公開すると未認証でディスク枯渇)
- 箇所: `src/nexom/app/request.py:206-287` (特に L241-242)、`DEFAULT_MAX_BODY_SIZE` は L42
- 内容: `read_body()` には 10MB 上限 (L137-145) があるが、`files()` はそれを通らず
  ```python
  stream = self.environ["wsgi.input"]
  parser = MultipartParser(stream, boundary.encode("utf-8"))   # L241-242
  ```
  と limit 引数を一切渡さない。installed multipart 2.0.1 の既定は `partsize_limit=inf`, `disk_limit=inf` (`multipart.py:936-940`、docstring に "Both are unlimited by default" と明記)。プローブ: Content-Length 10MB の `max_body_size` を持つ Request に 30MB の 1 パートを流すと `accepted bytes: 31457280`、`BufferedRandom` (一時ファイル) に全量スプール。`part_limit=128` と `memory_limit=8MB` のみ既定で効く。Content-Length 自体の検査も `files()` には無い (L133-138 は `read_body` のみ)。chunked 転送なら Content-Length すら無い
- 到達条件: 雛形の routes には multipart を受ける handler は無い (`grep "\.files()" src/nexom` → 呼び出し元ゼロ)。Bloom 等アプリ側で `req.files()` を使う全エンドポイントが対象
- 修正案: `files()` の冒頭で `_content_length()` を取り `max_body_size` 超なら拒否、`MultipartParser(..., content_length=length, partsize_limit=self.max_body_size, disk_limit=self.max_body_size, part_limit=<設定値>)` を渡す。上限超過は専用例外 (→ 413) にする。互換性: 10MB を超える正当なアップロードがあるアプリは `Request(environ, max_body_size=...)` の引き上げが必要 (wsgi.py 雛形は `Request(environ)` 固定 L40 なので設定の通し方も要設計)

### HTTP-03 Response に `headers=` を渡すと Content-Type が消える (JsonResponse/HtmlResponse も同様) → MIME スニッフィング経由の XSS
- 深刻度: **Medium**
- 箇所: `src/nexom/app/response.py:51`
- 内容:
  ```python
  self.headers: list[Header] = list(headers) if headers else [("Content-Type", ct)]
  ```
  「置換」であり「併合」でない。プローブ:
  ```
  JsonResponse({"a": "<b>"}, headers=[("X-A","1")]).headers → [('X-A','1'), ('Content-Length','12')]
  HtmlResponse("<p>", headers=[("X-A","1")]).headers         → [('X-A','1'), ('Content-Length','3')]
  ```
  Content-Type 無しの JSON 応答にユーザ入力 (HTML 片) が含まれると、ブラウザのスニッフィングで text/html 扱いになり得る (HTTP-06 の `X-Content-Type-Options: nosniff` 不在と複合)。API 名から「追加ヘッダ」と読める引数なので誤用しやすい
- 到達条件: アプリが `JsonResponse(..., headers=[...])` を使った時。雛形内では `Static._access` (`path.py:236-240`) が自前で Content-Type を含めて渡しているため影響なし。`Redirect` も headers を渡すが body 空なので実害なし
- 修正案: 既定ヘッダ (Content-Type) を先に置き、`headers` に同名 (case-insensitive) があれば上書き、無ければ併合。互換性: 「Content-Type を消すためにわざと headers を渡した」コードは想定しづらく、実質無影響

### HTTP-04 Static: index.html 再解決後に root 境界を再検査しない (NEX-03 確認、プローブで実証)
- 深刻度: **Low** (root 直下に外部を指す `index.html` シンボリックリンクが置かれている必要あり)
- 箇所: `src/nexom/app/path.py:220-233`
- 内容:
  ```python
  target = (self._root / rel).resolve()                                     # L220
  if not str(target).startswith(str(self._root) + os.sep) and target != self._root:   # L224
      raise PathNotFoundError(request.path)
  if target.is_dir():
      target = (target / "index.html").resolve()                            # L228  ← 以後再検査なし
  ...
  data = target.read_bytes()                                                # L233
  ```
  プローブ: `static/sub/index.html → <tmp>/outside.txt` の symlink で `/static/sub/` も `/static/sub` も `200 OUTSIDE`。対照群: 通常ファイルの symlink (`/static/link.txt`) と symlink ディレクトリ経由 (`/static/etcdir/hosts`) は L220 の resolve で実パスになり **L224 で正しく 404**。つまり穴は index.html 分岐だけ
- 到達条件: 攻撃者が static root 配下にシンボリックリンクを作れること (別の書き込み脆弱性 or 運用ミス)。雛形の static は固定 3 ファイルで該当なし
- 修正案: 境界チェックを関数化し L228 の後にも適用 (2 行)。互換性影響なし

### HTTP-05 CORSMiddleware: `allowed_origins` 既定 `["*"]` と `credentials=True` の併用で任意 Origin を反射 (認証付き応答の越境読み取り)
- 深刻度: **Medium** (設定ミス誘発型。コード自身が「必ず echo」と設計している)
- 箇所: `src/nexom/app/middleware.py:70, 76-77, 110-115`
- 内容:
  ```python
  self.allowed_origins = allowed_origins or ["*"]                 # L70
  ...
  if "*" in self.allowed_origins and not self.allow_credentials:  # L110
      res.append_header("Access-Control-Allow-Origin", "*")
  else:
      # credentials=True なら必ず echo（*は禁止）
      res.append_header("Access-Control-Allow-Origin", origin)    # L114
  ```
  `CORSMiddleware(access_control_allow_credentials=True)` (origin 未指定) だけで、プローブ結果: `Origin: https://evil.example` → `Access-Control-Allow-Origin: https://evil.example` + `Access-Control-Allow-Credentials: true`。ブラウザの `*`+credentials 禁止を「Origin 反射」で迂回してしまう最悪形。他は健全: Origin 比較は完全一致 (`https://app.example.evil` と `null` は許可されない — プローブで確認)、`allowed_headers=["*"]` の要求ヘッダ反射 (L129-135) は credentials 無しなら一般的挙動
- 到達条件: アプリが credentials=True を指定しつつ origin リストを書かない (または `"*"` を含める) 時。雛形は CORSMiddleware を使っていない
- 修正案: `__init__` で `"*" in allowed_origins and allow_credentials` なら `ValueError` を投げる (fail closed)。互換性: その設定で動いていたアプリは起動時に落ちるが、それは直すべき設定

### HTTP-06 セキュリティヘッダをフレームワークが一切付けない (nosniff / frame / referrer / CSP / HSTS)
- 深刻度: **Medium** (単独では脆弱性でないが、HTTP-01/03/08 の緩和層が皆無)
- 箇所: `src/nexom/app/response.py` 全体、`src/nexom/assets/app/wsgi.py:64`
- 内容: `grep -rni "x-content-type\|x-frame\|content-security\|referrer-policy\|strict-transport" src/` → 0 件。Response が付けるのは Content-Type / Content-Length / Set-Cookie のみ。gateway 雛形 (`nginx_app.conf` / `apache_app.conf`) も `add_header` 無し、かつ `listen 80` のみで TLS 設定無し
- 到達条件: 全応答
- 修正案: wsgi 雛形 (or Router 層) の既定ミドルウェアとして `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or `frame-ancestors`), `Referrer-Policy: strict-origin-when-cross-origin` を**無条件**付与。CSP は HTML 応答のみ、雛形は Google Fonts を読む (`error.html`, `login.html`) ので `default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com` 程度の既定 + アプリ側上書き口。互換性: nosniff で「拡張子なし静的ファイルを HTML として配っていた」ケースが壊れる可能性のみ

### HTTP-07 生成 WSGI / 雛形の既定: `0.0.0.0` バインド (auth サーバ含む)、X-Forwarded-For を無条件信頼
- 深刻度: **Medium** (auth サービスの直接露出)、XFF は **Low** (現状ログ用途のみ)
- 箇所: `src/nexom/buildTools/build.py:16-19` (`AppBuildOptions.address = "0.0.0.0"`, port 8080 / auth 7070)、`src/nexom/assets/app/gunicorn.conf.py:5`、`src/nexom/assets/app/config.py:19` (`AUTH_SERVER = "http://127.0.0.1:7070"`)、`src/nexom/assets/app/wsgi.py:26-30` と `src/nexom/assets/auth/wsgi.py:44-48` (`_ip`)
- 内容: アプリは `AUTH_SERVER` を 127.0.0.1 で呼ぶ (= 内部サービスとして設計) のに、auth 側 gunicorn も `0.0.0.0:7070` で listen する。ファイアウォールが無い VPS / Docker `-p` で auth API (login/signup/verify、master 操作) が外部到達。`_ip()` は
  ```python
  xff = environ.get("HTTP_X_FORWARDED_FOR")
  if isinstance(xff, str) and xff.strip():
      return xff.split(",")[0].strip()      # 先頭要素 = クライアントが自由に書ける
  ```
  nginx 雛形は `$proxy_add_x_forwarded_for` (追記) なので先頭はクライアント値のまま。access.log / AuthLogger の ip が偽装可能 (監査証跡の汚染)。IP ベースのレート制限や許可リストを後で載せると即バイパスになる
  付随 (Info): `assets/auth/wsgi.py:63-65` の `except Exception:` 節は `logger.error(e)` の `e` が未束縛 (NameError)、かつ両 except で `start_response` を呼ばずに `JsonResponse` を return → gunicorn 側の素の 500 に落ちる。情報漏えいは無いがエラー経路が機能していない
- 到達条件: `nexom start-project` 既定値そのまま
- 修正案: 既定 `address="127.0.0.1"` (auth は特に)。公開したい時だけ明示 `--address 0.0.0.0`。XFF は「信頼プロキシ数 N を設定し右から N 個目を取る」か `X-Real-IP` のみ採用 (nginx 雛形は `X-Real-IP $remote_addr` を既に送っている)。gateway 雛形に TLS/HSTS or 「TLS 終端は前段」の注記。互換性: 既存プロジェクトの config.py は生成済なので無影響

### HTTP-08 ErrorResponse の `message` 無エスケープ + 雛形 auth ページが例外文字列を埋める
- 深刻度: **Low**
- 箇所: `src/nexom/app/response.py:152-173` (L172 `ohtml.render("error_page", status=status_str, message=message)`)、`src/nexom/assets/error_page/error.html:11`、`src/nexom/templates/auth.py:136-138`
- 内容: HTTP-01 と同根。`ErrorResponse(404, "<img src=x onerror=alert(1)>")` → body にそのまま 1 回出現 (プローブ)。`wsgi.py:48,52` は定数 ("Not Found" / "Internal Server Error") なので雛形の 404/500 は安全。`templates/auth.py:138` は `ErrorResponse(500, str(e))` で `AuthClient.logout` の例外文字列 (urllib 由来、auth サーバ応答を含み得る) を HTML に埋める。また L155 で `content_type="text/html"` だが `include_charset` 既定 False なので charset 無し (status/message が ASCII の間は無害)
- 到達条件: アプリが `ErrorResponse(status, <ユーザ由来>)` を書いた時 / auth サーバ側のエラー文に依存
- 修正案: HTTP-01 の既定エスケープで同時に解決。`ErrorResponse` は `include_charset=True` に。`templates/auth.py:138` は `e.code` 相当の定数へ

### HTTP-09 HTTP メソッド処理: `Post` が OPTIONS を handler に素通し、未対応メソッドは 405 でなく 404、HEAD は Get 経路に乗らない
- 深刻度: **Low**
- 箇所: `src/nexom/app/path.py:194-197` (`methods={"POST", "OPTIONS"}`)、`path.py:266-297` (`Router.get`)
- 内容: プローブで `Post("submit/")` に OPTIONS を送ると handler が `req.method == "OPTIONS"` のまま実行される (`handler saw: ['OPTIONS']`、既存テスト `test_router_get_post_and_options` もこれを 200 として固定化している)。CORSMiddleware 無しでは、`if req.method == "GET": ... else: <POST処理>` と書いた handler は OPTIONS でも POST 処理を走らせる (雛形 `LoginPage._handler` L72-89 がこの形。body 空なので今は無害)。HEAD/PUT/DELETE/TRACE は `PathNotFoundError` → 404 で `Allow` ヘッダ無し。HEAD は `Get` に含まれず 404 (gunicorn 26 は HEAD の body を自動で落とす `wsgi.py:363-369` ので、Get に HEAD を含めるだけで正しく動く)
- 到達条件: 全アプリ
- 修正案: Router でパスは一致するがメソッド不一致 → 405 + `Allow`。`Get` は `{"GET","HEAD"}`。preflight は Router の前段 (wsgi 雛形 or Router.handle 冒頭) で CORSMiddleware が処理し、`Post` から OPTIONS を外す。互換性: 「OPTIONS を handler で自前処理していた」アプリと、405 を 404 として期待するテストが変わる

### HTTP-10 ヘッダインジェクション: フレームワーク自身は CR/LF を検証せず WSGI サーバ任せ (gunicorn なら拒否される)
- 深刻度: **Low** (gunicorn >= 19.5 配下では到達不能。他 WSGI サーバ/テストハーネスでは生のまま出る)
- 箇所: `src/nexom/app/response.py:51-54, 67-69, 125-144`、`src/nexom/app/cookie.py:25-26`
- 内容: `Redirect("/x\r\nSet-Cookie: a=b").headers → [('Location', '/x\r\nSet-Cookie: a=b'), ...]` (プローブ)。`append_header` も無検証。`Cookie` は値の CR/LF のみ拒否 (L25-26) で、名前と属性値は未検証、`;` も通る: `Cookie("k", "v; Path=/evil", Path="/")` → `k=v; Path=/evil; Path=/; HttpOnly; Secure;` (属性注入)。gunicorn 側: `http/wsgi.py:22` `HEADER_VALUE_RE = re.compile(r'[ \t\x21-\x7e\x80-\xff]*')`、`process_headers` L389-390 で `fullmatch` 失敗 → `InvalidHeader` → `workers/base.py:203-212` で 400。CR/LF 検証は CVE-2018-1000164 の修正 (19.5.0) 以降 (NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-1000164)。pyproject は `gunicorn>=21.2` なので運用上は守られる
  付随: Cookie 属性名は `k.replace("_", "-")` (cookie.py:38) のみなので `MaxAge=` は `Max-Age=` に変換されず、`templates/auth.py:83,140` の `MaxAge=sess.expires_at` / `MaxAge=0` はブラウザに未知属性として無視される (= セッション cookie になり、logout の削除指示も効かない。値は空文字で上書きされるので実質ログアウトは成立)。`SameSite` も既定で付かない → 認証担当へ引き継ぎ
- 到達条件: gunicorn 以外のサーバ、または値に `;` を含む cookie をアプリが作った時
- 修正案: `Response.__init__`/`append_header` で名前は token、値は `[\t\x20-\x7e\x80-\xff]*` を強制 (gunicorn と同じ正規表現) し `ValueError`。Cookie は名前/値/属性に `;`, `,`, 空白, CTL を拒否、属性名は `MaxAge→Max-Age` の明示マップ、`SameSite="Lax"` 既定。互換性: 既存の `MaxAge=` 呼び出しが**初めて効き始める** (expires_at が epoch 秒なら Max-Age が数十年になる) 点は認証担当と要確認

### HTTP-11 オープンリダイレクト: `Redirect` 自体は無検証、雛形 Logout の Referer チェックは `//host` を通す
- 深刻度: **Low**
- 箇所: `src/nexom/app/response.py:125-144`、`src/nexom/templates/auth.py:128-130, 141`
- 内容: `Redirect("//evil.example")` はそのまま Location に乗る (プローブ)。雛形 Logout は
  ```python
  redirect_url = req.headers.get("referer") or "/"
  if not redirect_url.startswith("/"):
      redirect_url = "/"
  ```
  で `//evil.example/` (プロトコル相対) を通す。ただし Referer はブラウザが絶対 URL (`https://...`) で送るためブラウザ経由でこの値は作れず、**現実的な悪用経路は無い**。設計上の誘導 (「Referer をそのまま Location へ」) として記録。別件: Logout が GET で副作用 (cookie 無効化 + auth サーバ logout) → `<img src="/user/logout/">` で他サイトから強制ログアウト可能 (Login CSRF 系、Low)
- 到達条件: アプリが `Redirect(req.query["next"][0])` の類を書いた時
- 修正案: `Redirect(location, *, allow_external=False)` 既定で `//`・スキーム付きを拒否 (`urllib.parse.urlsplit(location).netloc` 非空なら ValueError)。Logout は POST 化 or 同じ検査。互換性: 外部へ飛ばす既存コードは `allow_external=True` が必要

### HTTP-12 Static: ドットファイル配信、全量メモリ読み、MIME をそのまま返す (text/html / svg)
- 深刻度: **Low** (雛形の static は固定ファイル。ユーザアップロード物を Static 配下に置く設計を取った瞬間に格納型 XSS)
- 箇所: `src/nexom/app/path.py:230-240`
- 内容: プローブ: `/static/.env` → `200 SECRET=1` (application/octet-stream)、`/static/up.html` → `text/html`、`/static/up.svg` → `image/svg+xml` (script 実行可能)。`read_bytes()` で全量をメモリに載せ Range/ETag/Cache-Control 無し。`guess_type` は拡張子依存なので `Content-Disposition` も無い。健全な点: `..`, 復号後 `..`, NUL, バックスラッシュ, 11 セグメント超, ファイル symlink, ディレクトリ symlink は全て 404 (プローブ 1-3,5,9,10,12)。gunicorn は PATH_INFO を `unquote_to_wsgi_str` (`http/wsgi.py:279`) で復号するので `%2e%2e` は `..` として L220 の resolve に入り L224 で止まる (Codex 報告の本番 404 と整合)
- 到達条件: static root にドットファイル/アップロード物がある時
- 修正案: 先頭 `.` セグメント拒否、`X-Content-Type-Options: nosniff` 付与、`text/html` と `image/svg+xml` 以外は許可リスト化 or `Content-Disposition: attachment` を選べる引数、大ファイルはイテレータ応答 (Response が `__iter__` で `yield self.body` しているので bytes 固定を解く設計変更が要る)。アップロード物は ParallelStorage 側で別配信にする方針を doc 化

### HTTP-13 リクエスト解析: JSON/フォームの不正は 500、Content-Length 不正値の扱い、cookie 解析の黙殺
- 深刻度: **Info**
- 箇所: `src/nexom/app/request.py:102-110, 160-204, 83-91`
- 内容: `json()` の `JSONDecodeError` / `UnicodeDecodeError`、`read_body()` の `ValueError` (サイズ超過) は wsgi 雛形で `except Exception` → 500 (本来 400 / 413)。スタックトレースは `logger.error(e)` (`log.py:46-52`) でファイルのみ、応答は定数 → 情報漏えいなし。`_content_length`: `-5`/`abc`/`1e3` → None → Content-Length 無し扱いで最大 10MB+1 まで読む (gunicorn は不正 CL 自体を 400 で落とすので実質到達せず)。ネスト 5000 段の JSON は `json.loads` で問題なし (C パーサ)。`parse_qs` は `max_num_fields` 未指定だが QUERY_STRING は gunicorn `limit_request_line=4094` で頭打ち、body は 10MB 上限。`SimpleCookie.load` は不正な名前を含む cookie 以降を黙って捨てる (`a=b; bad\x7fname=1; c=d` → `{'a': 'b'}`) — 認証 cookie が消えてログイン状態が外れるだけで安全側
- 修正案: `RequestBodyTooLarge` / `RequestParseError` を `NexomError` 派生で定義し、wsgi 雛形で 413 / 400 にマップ

### HTTP-14 ログインジェクション: 復号後の PATH_INFO / User-Agent をそのまま行ログへ
- 深刻度: **Low**
- 箇所: `src/nexom/core/error.py:40-44` (`PathNotFoundError` に生パス)、`src/nexom/assets/app/wsgi.py:47, 54-60`、`src/nexom/core/log.py:67-75`
- 内容: `%0a` を含むパスは gunicorn 復号後 `\n` になり `PathNotFoundError` 文字列に乗る (プローブ: `"P01 -> This path is not found. 'x\nFAKE LOG LINE'"`) → `logger.warn(str(e))` で warning.log に偽行を挿入可能。access.log も `ua`/`path` を無加工 (UA の CR/LF は gunicorn が弾くが、パスは復号後なので弾かれない)
- 修正案: `_write` で `msg` の `\r\n` を `\\r\\n` にエスケープ (1 行 1 レコード保証)

### HTTP-15 ObjectHTML: テンプレート名がインスタンス属性として `setattr` され、メソッド名と衝突し得る
- 深刻度: **Info**
- 箇所: `src/nexom/core/object_html_render.py:82-88`
- 内容: `setattr(self, doc.name, _call)`。`render.html` / `lib.html` という名のテンプレートを置くと `self.render` が `_call` に差し替わり無限再帰。開発者がファイル名を決めるので攻撃面ではないが、`ObjectHTMLTemplates.__getattr__` (template.py:67-70) と二重の動的属性で予測しづらい
- 修正案: 予約名チェック or 動的属性を `_TemplateAccessor` 側に一本化

### HTTP-16 dict 自動 JSON 化 / JsonResponse のエスケープ
- 深刻度: **Info**
- 箇所: `src/nexom/app/path.py:169-170`、`src/nexom/app/response.py:113`
- 内容: handler が dict を返すと `JsonResponse(res)` に自動変換。「DB 行の dict をそのまま return」でハッシュ等が漏れる誘導はあるがフレームワークで防げる性質ではない。`json.dumps(body, ensure_ascii=False)` は `</script>` を無変換 → JSON を `{{ }}` で HTML に inline する用途では HTTP-01 と同じ XSS。`application/json; charset=utf-8` は正しく付く (HTTP-03 の `headers=` 併用時を除く)
- 修正案: HTML 内に JSON を埋めるヘルパを作るなら `json.dumps(...).replace("<", "\\u003c")` 系を提供。既定の nosniff (HTTP-06)

---

## チェックリスト結果表

| # | 観点 | 結果 | 根拠 / 所見 |
|---|---|---|---|
| 1 | XSS (スロット/属性/script/URL、HtmlResponse/ErrorResponse) | **該当あり** | HTTP-01 (High), HTTP-08 (Low)。`object_html_render.py:196,210` に escape 無し、全コンテキスト未区別 |
| 2 | パストラバーサル (`..`/`%2e%2e`/絶対/symlink/index.html/Windows/`{"*"}`) | **該当あり (限定)** | `..`・復号後 `..`・NUL・バックスラッシュ・symlink ファイル/ディレクトリ・11 セグメント超は全て 404 (プローブ)。index.html symlink のみ通る → HTTP-04 (Low)。ドットファイルは配信 → HTTP-12 |
| 3 | ヘッダインジェクション (CR/LF、Set-Cookie、Location) | **該当あり (Low)** | フレームワーク無検証、gunicorn >= 19.5 が 400 で遮断 (`http/wsgi.py:22,389`)。Cookie は `;` 注入可、`MaxAge` 属性名バグ → HTTP-10 |
| 4 | オープンリダイレクト | **該当あり (Low)** | `Redirect` 無検証、雛形 Logout の `startswith("/")` は `//host` 通過 (ブラウザ経由では非悪用) → HTTP-11 |
| 5 | リクエスト解析 DoS (CL 上限/全量読込/multipart/JSON 深さ/CL 偽装/chunked) | **該当あり** | body/json/form は 10MB 上限 (`request.py:42,137-145`)。**multipart は無制限** → HTTP-02 (High)。不正 CL は None 扱い、JSON 深さは C パーサで問題なし → HTTP-13 |
| 6 | CORS (完全一致/`*`+credentials/null/preflight/allow-headers 反射) | **該当あり** | 比較は完全一致で健全 (prefix/null 攻撃はプローブで不通)。`*`+credentials で Origin 反射 → HTTP-05 (Medium)。Get 経路への preflight は 404 → HTTP-09 |
| 7 | エラー処理 (トレース漏れ/デバッグ既定/500 ログ) | **確認済・問題なし** | 雛形は 404/500 とも定数メッセージ (`wsgi.py:46-52`)、トレースは `log.py:49` でファイルのみ。デバッグモードという概念自体が無い。`RELOAD` 既定 False (`build.py:19`)。auth 雛形の except 節は機能不全 (HTTP-07 付随、漏えいは無し) |
| 8 | セキュリティヘッダ既定 | **該当あり** | 0 件 → HTTP-06 (Medium) |
| 9 | Content-Type / charset / 静的 MIME | **該当あり** | HtmlResponse は `text/html; charset=utf-8` (`response.py:81,48-49`) で正常。ErrorResponse は charset 無し。`headers=` で Content-Type 消失 → HTTP-03。Static は `guess_type` 無加工で `.html`/`.svg` を実行可能 MIME で返す → HTTP-12 |
| 10 | dict 自動 JSON 化 / JSON エスケープ | **確認済・Info** | HTTP-16。`</script>` 無変換は HTML inline 時のみ問題 |
| 11 | HTTP メソッド (HEAD/OPTIONS/未定義/405+Allow) | **該当あり (Low)** | Post が OPTIONS を handler へ素通し、HEAD/PUT/等は 404、Allow 無し → HTTP-09 |
| 12 | 生成 WSGI 既定 (デバッグ/ホスト・ポート/XFF) | **該当あり** | `0.0.0.0` 既定 (auth 7070 含む)、XFF 先頭要素を無条件採用 → HTTP-07 (Medium/Low) |

## 既存テストが守っているもの (参考)
- `test_request_response.py`: JSON/form/multipart の正常系、Content-Length 自動付与、Redirect Location、ErrorResponse に message が含まれる (= 無エスケープを間接的に固定している。HTTP-01 修正時にこのテストは `b"missing"` のままなら通るが、HTML を含む message のテストは追加が要る)
- `test_router_static_middleware.py`: Static 正常系のみ (境界・symlink・dotfile のテスト無し)、CORS は `*` 既定の preflight のみ (credentials 併用の負のケース無し)、**OPTIONS が Post handler に届いて 200 になることを正として固定** (HTTP-09 修正で要更新)
- `test_core.py`: 例外文字列と status code 表のみ
- セキュリティ観点の負のテスト (traversal / escape / CRLF / サイズ超過) はゼロ

## 設計への含意 (優先順)

1. ★ **ObjectHTML の既定エスケープ化** (HTTP-01/08/16): `autoescape` フラグ + `Markup` 型で段階導入、属性/URL/JS コンテキストは doc で禁止事項を明記 (escape では `javascript:` を防げない)。aisaba 本番の実証済 XSS を塞ぐ唯一の根本策。既存テンプレート (`{{ main }}` 合成・`user_message` の `<i>`) の `Markup` 移行が互換コスト
2. ★ **`Request.files()` に上限** (HTTP-02): `max_body_size` を multipart にも適用し `partsize_limit/disk_limit/part_limit` を渡す。Bloom のアップロード経路があるなら本番前必須。413/400 の例外型と wsgi 雛形のマップも同時に (HTTP-13)
3. **Response ヘッダ併合 + 既定セキュリティヘッダ + ヘッダ値検証** (HTTP-03/06/10): `Response.__init__` 一箇所の変更で 3 件が片付く。nosniff は HTTP-03/12 の緩和にもなる
4. **CORS fail-closed** (HTTP-05): `*`+credentials を起動時 ValueError に
5. **Static の仕上げ** (HTTP-04/12): index.html 再検査 (2 行)、ドットファイル拒否、nosniff。アップロード物の配信は Static に乗せない方針を明文化
6. **メソッド処理の正規化** (HTTP-09): 405+Allow、HEAD→Get、preflight を Router 前段へ。既存テスト 1 件の期待値変更を伴う
7. **デプロイ既定** (HTTP-07): bind 127.0.0.1、XFF は信頼プロキシ数方式、auth 雛形の except 節修正、gateway 雛形に TLS 注記
8. **Cookie 属性** (HTTP-10 付随、認証担当と共有): `Max-Age` 名の修正は挙動が変わる (未知属性→有効) ので `expires_at` の単位確認が先。`SameSite=Lax` 既定、値の `;` 拒否
9. Low 群 (HTTP-11/14/15): Redirect の外部拒否既定、ログの改行エスケープ、予約テンプレート名

## 不確定事項
- gunicorn 26.2.0 が `.venv` に入っていること自体は `pip show` で確認したが、本番 (aisaba/Bloom) で稼働している gunicorn 版は未確認。ヘッダ CR/LF 遮断の前提は「>= 19.5.0」(NVD CVE-2018-1000164) なので pyproject の `>=21.2` が守られていれば成立
- aisaba 本番が HEAD d3570cd と同一コードかは未確認 (Codex 報告も同じ留保)。本監査はリポジトリ版に対する静的所見
- `multipart` の限界値は installed 2.0.1 の実ソース (`multipart.py:926-960`) で確認。pyproject 下限 `>=1.3.0` での既定が同じかは未確認 (docstring 上は「両方 unlimited」で一貫している模様だが 1.3 系ソースは未読)
