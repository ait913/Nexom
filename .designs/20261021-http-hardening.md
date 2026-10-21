# Nexom 1.2.0 — HTTP 層ハードニング (http-hardening)

- 対象リポジトリ: `Muraki/projects/nexom` (main 6b63cd5 = PyPI 1.1.41 と同期済)
- 根拠: `.knowledge/security-audit-20261021/B-http.md` (HTTP-01〜16)、同 A-auth.md (AUTH-02/03/12/15/20)、同 C-data.md (DATA-10/11、HTTP-02 申し送り)、`cyber-security-agent/reports/aisaba-nexom-20261012.md` (AIS-01 / NEX-03)
- 並列 doc: `20261021-auth-hardening.md` (auth 層)、`20261021-storage-deps-hardening.md` (storage / deps / log / pyproject)。3 本まとめて **1.2.0 (破壊的変更)** として出す。版番号・pyproject は storage doc が持つ
- Researcher の実測スクリプト: scratchpad `probe/p1.py` (本 doc の「現状」欄はこれの出力)。本 doc の規則値 (エスケープ出力・Redirect 判定・Cookie 文字集合・XFF 抽出) は scratchpad `arch/rules.py` で実走して確定した値のみを書いている

## 0. スコープ境界 (並列 3 doc)

| 本 doc が触る | 触らない (他 doc 所有) |
|---|---|
| `src/nexom/app/request.py`, `app/response.py`, `app/path.py`, `app/middleware.py`, `app/cookie.py`, `app/template.py`, `app/__init__.py` | `app/auth.py`, `app/user.py`, `templates/auth.py`, `assets/auth/**`, `assets/auth_page/**` (auth doc) |
| `src/nexom/core/object_html_render.py`, `core/error.py` (HTTP 系エラー型の追加のみ。既存クラスは不変) | `app/parallel_storage.py`, `app/db.py`, `core/log.py`, `pyproject.toml`, `src/nexom/__init__.py` の `__version__` (storage doc) |
| `src/nexom/assets/app/**` (config.py / wsgi.py / gunicorn.conf.py / router.py / pages/* / templates/*)、`assets/error_page/error.html` (変更なし、挙動のみ変わる) | `assets/gateway/**` (変更なし。TLS 注記は storage doc の README 範囲) |
| `src/nexom/buildTools/build.py` の `AppBuildOptions` (address 既定値 + `trusted_proxy_count` 追加)、`_replace_many` 辞書への `__g_trusted_proxies__` 追加、`src/nexom/__main__.py` の `--address` / `--auth-address` 既定値と help 文、`--trusted-proxy-count` 系フラグの配線 (Leader 裁定で所有拡大) | build.py / __main__.py のそれ以外 (`MASTER_PASSWORD` 生成等は auth doc) |
| `tests/test_request_response.py`, `tests/test_router_static_middleware.py`, `tests/test_core.py` (変更) + 新規 `tests/test_http_hardening.py` | `tests/test_auth_and_db.py`, `tests/test_parallel_storage.py`, `tests/test_templates_and_buildtools.py` (※ §18 に「変えない根拠」を書く) |

他 doc から参照される節: **§4 自動エスケープの契約**、**§5 Cookie API 契約**、**§9 プロキシ信頼の契約**、**§13 ログ・エラー経路 (storage doc の `sanitize_log_field` を呼ぶ側)**。

## 1. 目的

一般ユーザーを受け入れる前に、Nexom の HTTP 層の既定を「何もしなくても安全側」に倒す。aisaba 本番で実証済の XSS (AIS-01 = HTTP-01)、未認証で踏める multipart DoS (HTTP-02)、設定ミス 1 行で認証付き応答が越境する CORS (HTTP-05) を根本から塞ぎ、Cookie / ヘッダ / リダイレクト / 静的配信 / メソッド処理 / bind 既定を RFC と業界既定に揃える。

## 2. 現状 (実測、回帰テストの「before」)

| # | 現状 (1.1.41) | 出典 |
|---|---|---|
| HTTP-01 | `ObjectHTML.render("t", v='</h2><script>alert(1)</script>')` → そのまま出力。`grep "escape(" src/nexom` = 0 件 | B-http、p1.py |
| HTTP-02 | `Request(max_body_size=10MiB).files()` に 30 MB の 1 パートを流すと `accepted bytes: 31457280` (全量を一時ファイルへ) | B-http |
| HTTP-03 | `JsonResponse({"a":"<b>"}, headers=[("X-A","1")]).headers` → `[('X-A','1'), ('Content-Length','12')]` (Content-Type 消失) | p1.py |
| HTTP-04 | `static/sub/index.html` → root 外への symlink で `/static/sub/` が `200 OUTSIDE` | p1.py |
| HTTP-05 | `CORSMiddleware(access_control_allow_credentials=True)` + `Origin: https://evil.example` → `Access-Control-Allow-Origin: https://evil.example` + `Allow-Credentials: true` | p1.py |
| HTTP-06 | セキュリティヘッダ 0 件 | B-http |
| HTTP-07 | `AppBuildOptions.address="0.0.0.0"`、`--auth-address` help が「default: 0.0.0.0」(実値 127.0.0.1) | build.py:16、__main__.py:59 |
| HTTP-08 | `ErrorResponse(404, "<img src=x onerror=alert(1)>")` → body にタグがそのまま 1 回出現、charset 無し | p1.py |
| HTTP-09 | `Post("submit/")` に OPTIONS → handler が `req.method == "OPTIONS"` で実行 (`test_router_get_post_and_options` が 200 を正として固定)。HEAD/PUT/DELETE は 404、`Allow` 無し | p1.py、tests |
| HTTP-10 | `Redirect("/x\r\nSet-Cookie: a=b").headers` → CR/LF がそのまま乗る (gunicorn が 400 で遮断するだけ)。`Cookie("k","v; Path=/evil", Path="/")` → `k=v; Path=/evil; Path=/; HttpOnly; Secure;`。`Cookie(..., MaxAge=0)` → `MaxAge=0;` (無効属性名) | p1.py、A-auth AUTH-02 |
| HTTP-11 | `Redirect("//evil.example")` → `Location: //evil.example` | p1.py |
| HTTP-12 | `/static/.env` → `200 SECRET=1` | p1.py |
| HTTP-13 | 不正 JSON → `json.JSONDecodeError` → 雛形で 500。CL 超過 → `ValueError` → 500。`Content-Length: abc` → None 扱い | p1.py |
| HTTP-14 | `PathNotFoundError` の `str(e)` に復号後パスの `\n` が乗り、`logger.warn` で偽行 | p1.py |
| AUTH-12 | `Cookie: a<b=1` で `SimpleCookie.load` が `CookieError`、`a=b; bad\x7fname=1; c=d` → `{'a':'b'}` (`c` を黙って捨てる) | A-auth、B-http |

## 3. 横断方針 (Leader 確定、逸脱なし)

1. 安全既定 (opt-out)。1.2.0 で互換を切る。壊れる範囲と移行は §19
2. 変更は Python 3.10 / 標準ライブラリのみで実装する (新規依存なし。`markupsafe` は不採用、§21)
3. 検証は「起動時 / 構築時に `ValueError` or `NexomError`」で fail-closed。リクエスト時のエラーは `NexomError` 派生 + `http_status` 属性で wsgi 雛形が 400/404/405/413 にマップ
4. 設定の置き場は雛形 `config.py` (`MAX_BODY_SIZE`, `TRUSTED_PROXY_COUNT`) に限定し、環境変数は増やさない

---

## 4. § 自動エスケープの契約 (HTTP-01 / 08 / 16 / 15)

対象: `src/nexom/core/object_html_render.py`, `src/nexom/app/template.py`, `src/nexom/app/response.py (ErrorResponse)`

### 4.1 型とヘルパ (`core/object_html_render.py` に追加。`nexom.app` と `nexom.app.template` から再 export)

```python
class Markup(str):
    """信頼済み HTML 断片。スロットに渡すとエスケープされずそのまま埋まる。"""
    __slots__ = ()
    def __html__(self) -> str: ...            # str(self)
    def __add__(self, other: object) -> "Markup": ...   # Markup(str(self) + escape(other))
    def __radd__(self, other: object) -> "Markup": ...  # Markup(escape(other) + str(self))
    def join(self, iterable: Iterable[object]) -> "Markup": ...  # 各要素を escape() してから str.join
    def format(self, *args: object, **kwargs: object) -> "Markup": ...  # 各引数を escape() してから str.format
    def __repr__(self) -> str: ...            # "Markup('...')"

class _AttrSafe(Markup):
    """非公開。escape 済 (引用符も符号化済) で属性値位置にも置ける HTML 断片。
    生成するのは safe_url() だけ (規約。__all__ に載せない。アプリコードが直接作ってはならない)。"""
    __slots__ = ()

def escape(value: object) -> Markup:
    """Markup / __html__ を持つ値はそのまま。それ以外は str(value) を html.escape(quote=True)。"""

def safe_url(value: object, *, allowed_schemes: tuple[str, ...] = ("http", "https", "mailto")) -> Markup:
    """URL 属性 (href/src/action/formaction) 用。Markup を渡しても信用しない:
    str(value) → html.unescape で文字参照を復号 → スキーム検査 → 常に escape して _AttrSafe で返す
    (公開型注釈は Markup)。allowlist 外なら _AttrSafe("")。"""

def json_script(value: object, element_id: str | None = None) -> Markup:
    """JSON を HTML に inline する用。<, >, & を \\u003c \\u003e \\u0026 に置換。
    element_id を渡すと <script id="…" type="application/json">…</script> で包む。
    守るのは HTML パーサ経由の脱出だけ。出力を JS で innerHTML に代入する用途は守らない。"""
```

- `escape()` の規則: `isinstance(value, Markup)` → そのまま。`callable(getattr(value, "__html__", None))` → `Markup(value.__html__())` (markupsafe 等との相互運用)。それ以外 → `Markup(html.escape(str(value), quote=True))`。`None` は `"None"` になる (現行 `str(values[key])` と同じ。黙って空にはしない)
- `html.escape(quote=True)` の置換: `&`→`&amp;` `<`→`&lt;` `>`→`&gt;` `"`→`&quot;` `'`→`&#x27;`
- `Markup` で **Markup を返すメソッドは `+` / `join` / `format` の 3 つだけ**。`strip()` / `replace()` / f-string / `%` は素の `str` を返す (その結果をスロットに渡すとエスケープされる)。信頼済みと分かっている結果は呼び出し側が `Markup(...)` で包み直す
- `_AttrSafe(Markup)`: 非公開の `Markup` サブクラス。「出力は常に escape 済 (`"` `'` も符号化済) なので属性値位置に置いても境界を壊さない」ことを型で表す。**規約: 生成するのは `safe_url()` だけ**。`nexom.app` / `nexom.app.template` の `__all__` に載せず、ドキュメントにも「アプリは `safe_url()` を呼ぶ」とだけ書く (Codex 第 2 パス RG07: 直接コンストラクタを呼べば属性注入になるが、通常文字列・render 結果・`+`/`join`/`format` から自動で昇格する経路は無いことを同パスで確認済)。本文位置では Markup と同じく素通し、属性値位置 (E-R12) でも素通し
- `safe_url()` の手順 (Markup 入力も**同じ経路**。素通し分岐は無い): (a) `raw = html.unescape(str(value))` — `jav&#x61;script:` のような文字参照を属性値として復号された形に戻す。(b) `probe = re.sub(r"[\x00-\x20]", "", raw).lower()`、`m = re.match(r"^([a-z][a-z0-9+.\-]*):", probe)`。`m` 無し (相対 URL、`//host/...`、`?q`、`#top`) → 許可。`m` あり → `m.group(1) in allowed_schemes` のときだけ許可。(c) 許可なら `_AttrSafe(html.escape(raw, quote=True))` を返し、拒否なら `_AttrSafe("")`。`\x00-\x20` を除去してから判定するのは `java\tscript:` / ` JAVASCRIPT:` のようなブラウザが無視する文字の迂回を潰すため。(a) を入れるのは `Markup("jav&#x61;script:alert(1)")` が (b) を素通りして属性で `javascript:` に復号される穴を塞ぐため (Codex 指摘)。戻り値を `_AttrSafe` にするのは、E-R12 (属性値位置では Markup も escape) と組んだとき `href="{{ u }}"` が二重エスケープ (`&amp;amp;`) になったため (リリース前ゲート第 1 パス RG07)
- **スロット位置の分類 — HTML トークナイザ** (E-R6 の読み込み時検査と E-R12 の属性値判定の両方がこれ 1 つを使う。正規表現検出と「直近の `<` からの状態機械」は Codex 第 2 パスで `<div title="a < {{x}}">` / `title="a <!-- {{x}}"` (引用符内の `<` でリセット、RG02) と `<p/onclick="{{x}}">` / `<iframe/srcdoc=` (`/` 区切り、RG03) に迂回されたので廃止)。`_classify_slots(html: str) -> list[SlotInfo]` (`SlotInfo = (start: int, state: str, attr: str | None, tag: str | None)`) が**テンプレート全体を先頭から 1 パス**で走査し、各 `{{ slot }}` の開始位置にいた状態を記録する:

  | 状態 | 入る条件 | 出る条件 |
  |---|---|---|
  | `DATA` | 初期状態 | `<!--` → COMMENT。`<` の直後が英字 / `/` / `!` / `?` **または `{{` (スロット)** → TAG_OPEN (それ以外の `<` は文字のまま) |
  | `COMMENT` | `<!--` | `-->` → DATA。中の `<` `>` `"` は無視 |
  | `TAG_OPEN` | `<` の直後 | タグ名文字 (英数 `-` `:` `!` `?`、先頭だけ `/`) を読み、それ以外で IN_TAG |
  | `IN_TAG` | タグ名の後 | **空白と `/` が属性の区切り** (`<p/onclick=` を属性として読む)。属性名文字を溜め、`=` を見たら後続の空白を飛ばして `"` → ATTR_VALUE_DQ、`'` → ATTR_VALUE_SQ、それ以外 → ATTR_VALUE_UNQUOTED。`=` の前の空白で属性名は捨てない (`onmouseover = "…"` の属性名は `onmouseover`)。`>` → タグ名が `script` / `style` (大文字小文字無視、開始タグ、自己終了 `/>` でない) なら RAWTEXT、それ以外 DATA |
  | `ATTR_VALUE_DQ` / `_SQ` | `="` / `='` | 開き引用符と**同種**の引用符 → IN_TAG。**中の `<` `<!--` `>` `/` と異種の引用符は状態を変えない** |
  | `ATTR_VALUE_UNQUOTED` | `=` の後が引用符以外 | 空白 → IN_TAG、`>` → IN_TAG に戻してから `>` を処理 |
  | `RAWTEXT` | `<script…>` / `<style…>` の直後 | `</script\s*>` / `</style\s*>` (大文字小文字無視) → DATA。中の `<` `{{` `"` は状態を変えない |

  各スロットに記録する `attr` は IN_TAG で最後に溜めた属性名の小文字、`tag` は直近のタグ名の小文字。
- 読み込み時検査 (E-R6 / E-R8): `ObjectHTML.__init__` が登録する全 `HTMLDoc` について `_classify_slots(doc.html)` を取り、次のいずれかのスロットがあれば `TemplateUnsafeSlotError(doc.name, reason)` (OH06) を送出する。(a) `state in {ATTR_VALUE_DQ, ATTR_VALUE_SQ}` かつ `attr` が `^(on\w+|srcdoc|style)$` に一致 (reason = 属性名)。(b) `state == ATTR_VALUE_UNQUOTED` (reason `"unquoted attribute"`)。(c) `state == RAWTEXT` (reason `"script/style body"` — **script / style 本文内のスロットは読み込み時に拒否**。第 2 パスで「非対応かつ安全でない」から「拒否」に強めた)。(d) `state in {IN_TAG, TAG_OPEN}` (reason `"tag/attribute name position"`)。(e) `state == COMMENT` (reason `"comment"`)。許されるのは `DATA` と、(a) に当たらない `ATTR_VALUE_DQ/SQ` だけ。`autoescape` の値に関係なく実行する (テンプレート作者の誤りで、設定で緩める対象ではない)。`ObjectHTMLTemplates` と `ErrorResponse` はどちらも `ObjectHTML(...)` を通るので同じ検査を受ける。偽陽性: 属性名の完全一致なので `data-onx="{{ v }}"` / `title="on{{ v }}"` は通る。`<script src="{{ s }}">` は `src` 属性 (ATTR_VALUE_DQ) なので通る (RAWTEXT に入るのは `>` の後)
- 属性値位置の判定 (E-R12): `_apply_slots_strict` は同じ `_classify_slots` の結果 (`ObjectHTML.__init__` で doc ごとに 1 回計算してキャッシュ。ただし `_render_structure` が Extends / Import で合成した HTML に対しては置換直前に 1 回計算する) を参照し、**スロットの `state` が `ATTR_VALUE_DQ` / `ATTR_VALUE_SQ` なら属性値位置**として **Markup でも `html.escape(str(value), quote=True)`** する (`_AttrSafe` だけは素通し)。`DATA` なら本文位置で Markup 素通し。他の状態はここに来る前に OH06 で落ちている。Insert 由来 (`_apply_slots_non_strict`) はこの判定を行わない (E-R2)。トークナイザは HTML 仕様の簡約版なので誤分類は「本文を属性値と見る」側 (= 過剰エスケープ) にしか倒れない — 引用符内で状態が変わらないこと、RAWTEXT が終了タグまで続くことが、その保証の核
- `json_script()` の `element_id` は `^[A-Za-z0-9_-]+$` に一致しなければ `ValueError`。JSON 化は `json.dumps(value, ensure_ascii=False)` → 3 文字置換 → `Markup`

### 4.2 エンジンのシグネチャ

```python
class ObjectHTML:
    def __init__(self, *docs: HTMLDoc, lib: HTMLDocLib | None = None, autoescape: bool = True) -> None
    def render(self, name: str, **kwargs: object) -> Markup

class ObjectHTMLTemplates:
    def __init__(self, base_dir: str, reload: bool = False, autoescape: bool = True) -> None
    def render(self, name: str, **kwargs: object) -> Markup      # _TemplateAccessor.__call__ も Markup
```

### 4.3 契約 (他 doc / 利用側が従う規則)

| # | 規則 |
|---|---|
| E-R1 | `render(name, **kwargs)` の **kwargs 値は既定でエスケープされる** (`_apply_slots_strict`)。`Markup` (または `__html__` を持つ値) だけが素通し |
| E-R2 | `<Insert key>…</Insert>` の中身 (テンプレート作者が書いたもの、`_apply_slots_non_strict`) と `<Import x />` の展開結果はエスケープしない (従来どおり) |
| E-R3 | `render()` の戻り値は `Markup`。**ネストした render の結果を別の render のスロットに渡すと素通し**。`"\n".join(list_of_markup)` は `str` に落ちるので `Markup("\n").join(...)` を使う |
| E-R4 | `HtmlResponse(body)` / `Response(body)` は body を一切加工しない (Markup でも str でも bytes にするだけ)。「レンダ済み出力は Raw」= 応答 body に escape は掛からない、の意味。エスケープは常にスロット埋め込み時の 1 回だけ |
| E-R5 | スロット値は**再展開されない** (置換後の文字列に `{{ x }}` が含まれていても 2 回目の置換は起きない。`re.sub` 1 パス) |
| E-R6 | E-R1 で安全なのは **テキストコンテキスト** (`<p>{{ x }}</p>`) と、**引用符付きの通常テキスト属性** (`alt` / `title` / `value` / `placeholder` / `content` / `aria-*` / `data-*` 等、値が文字列としてだけ扱われる属性) の 2 つ。安全でない属性: (a) URL 属性 `href` / `src` / `action` / `formaction` / `poster` 等 → `javascript:` を escape では止められないので **`safe_url()` 必須** (E-R7)。(b) **`on*` (イベントハンドラ) / `srcdoc` / `style` は禁止** — 値が JS / HTML 文書 / CSS として解釈され、エスケープでは守れない。`ObjectHTML` はテンプレート読み込み時に §4.1 のトークナイザで属性名を特定し `TemplateUnsafeSlotError` (OH06) を投げる (`<p/onclick=` の `/` 区切り、`ONCLICK` の大文字も検出)。(c) **引用符なし属性 (`<a title={{ x }}>`)、タグ名 / 属性名位置 (`<{{ t }}>`、`<p {{ a }}>`)、コメント内は読み込み時に拒否** (OH06)。属性スロットは必ず `"…"` で囲む |
| E-R7 | URL 属性にユーザ由来値を入れるときは `safe_url(value)` を通す。`safe_url` は Markup 入力も信用せず、文字参照を復号してからスキーム検査し、常に escape して非公開型 **`_AttrSafe`** で返す (§4.1)。`_AttrSafe` は属性値位置でも素通しなので `href="{{ u }}"` に渡しても二重エスケープにならない。**`_AttrSafe` を生成するのは `safe_url()` だけ** (規約。アプリコードが `_AttrSafe(...)` を直接呼ぶのは契約違反で、属性注入になる) |
| E-R8 | **`<script>` / `<style>` 本文内のスロットは読み込み時に拒否** (OH06、§4.1 トークナイザの RAWTEXT)。理由: `<script>let x={{ x }}</script>` に `alert(1)` を渡すとエスケープ対象文字が無いためそのまま `let x=alert(1)` になり実行される (E29)。`<script src="{{ s }}">` のような属性は RAWTEXT ではなく属性値位置なので通る (URL なので `safe_url()`)。JS に値を渡すときは `json_script(data, element_id="boot")` で `<script type="application/json">` を出し、JS 側で `JSON.parse(document.getElementById("boot").textContent)` する。`json_script` の出力を `innerHTML` に代入する用途は守らない |
| E-R9 | `ObjectHTML(autoescape=False)` / `ObjectHTMLTemplates(autoescape=False)` で従来挙動 (全スロット素通し) に戻せる。移行猶予用。雛形は使わない。E-R6 (b) の読み込み時検査は `autoescape=False` でも走る |
| E-R10 | `ErrorResponse(status, message)` は `_render` で `escape(str(message))` を呼ぶ — `str()` で Markup 性を剥がしてから `escape()` に渡すので、`Markup` を渡しても常にエスケープされる (`escape()` 自体の「Markup は素通し」規則とは矛盾しない) |
| E-R12 | **Markup の素通しは要素本文位置 (`DATA`) のみ**。スロットが引用符付き属性値位置 (§4.1 トークナイザの `ATTR_VALUE_DQ` / `_SQ`) にあるときは Markup でも escape する。**ただし `_AttrSafe` (= `safe_url()` の戻り値。アプリは直接生成しない) は属性値位置でも素通し** (出力が既に引用符まで符号化済だから)。ネストした `render()` 出力には生の `"` が含まれ得るので、属性値に Markup を入れると境界を壊すため。誤判定は escape 側に倒れる |
| E-R11 | HTTP-15: テンプレート名が `ObjectHTML` のクラス属性名 (`render`, `lib`, `_set_doc` 等) と衝突するか `_` で始まる場合、動的属性 (`engine.<name>()`) は**作らない**。`render("<name>")` は従来どおり動く。例外は投げない |

### 4.4 雛形への適用

- `assets/app/pages/default.py:21` → `msg = Markup("Hello <i>{}@{}</i> San!!").format(session.public_name, session.user_id)`、`from nexom.app import Markup` を追加。`else` 側 `"Not Logined."` は str のままでよい (エスケープされても同じ)
- `assets/app/templates/*.html`: スロットは `{{ title }}` (text / `<title>`)、`{{ main }}` (Insert 由来)、`{{ user_message }}` (text) のみ。変更なし
- `assets/error_page/error.html`: 変更なし。`{{ message }}` が E-R10 でエスケープされる

---

## 5. § Cookie API 契約 (AUTH-02 / 03 / 15、HTTP-10)

対象: `src/nexom/app/cookie.py`。**Leader 指定の署名をそのまま採用** (変更なし)。auth doc はこの節を前提に `templates/auth.py` を書き換える。

### 5.1 シグネチャ

```python
from datetime import datetime
from typing import Literal

class Cookie:
    def __init__(
        self,
        name: str,
        value: str,
        *,
        max_age: int | None = None,          # 秒・相対。負値は 0 に正規化
        expires: datetime | None = None,     # naive は UTC とみなす。aware は UTC に変換
        path: str = "/",
        domain: str | None = None,
        secure: bool = True,
        http_only: bool = True,
        same_site: Literal["Strict", "Lax", "None"] = "Lax",
    ) -> None: ...

    @classmethod
    def delete(
        cls,
        name: str,
        *,
        path: str = "/",
        domain: str | None = None,
        secure: bool = True,
        http_only: bool = True,
        same_site: Literal["Strict", "Lax", "None"] = "Lax",
    ) -> "Cookie":
        """value="" / max_age=0 / expires=1970-01-01T00:00:00Z の削除用 Cookie。
        path/domain は発行時と同じ値を渡さないとブラウザは別 cookie と見る。"""

    def to_header(self) -> str: ...      # Set-Cookie の値
    def __str__(self) -> str: ...        # == to_header()
    def response(self, body: str | bytes = "OK") -> Response: ...   # Response(body, cookie=self)
```

削除されるもの: `**kwargs` (任意属性)、`set(key, value)`、`attributes` 辞書。`Cookie.name / value / max_age / expires / path / domain / secure / http_only / same_site` を読み取り専用属性として持つ。

```python
class RequestCookies(dict[str, str | None]):
    def __init__(self, cookies: Mapping[str, str] | None = None) -> None   # 旧: **kwargs。マッピングを受ける
    default: str | None                                                     # 不変
    def get(self, key: str, default: str | None = None) -> str | None       # 不変
```

`RequestCookies` の公開挙動 (`.get` / dict 等価 / `in` / 反復 / `len`) は不変。変わるのはコンストラクタの受け方だけで、`Request._parse_cookies` 以外に nexom 内の呼び出しは無い (grep)。`RequestCookies(a="b")` のキーワード呼び出しは `TypeError` になる。

### 5.2 検証規則 (違反は `CookieInvalidValueError` (C01: name / value) または `CookieInvalidAttributeError` (C02: 属性))

| 項目 | 規則 (fullmatch) | 根拠 |
|---|---|---|
| `name` | `[!#$%&'*+\-.^_`|~0-9A-Za-z]+` (RFC 6265 token)。空は不可 | 現行は空のみ検査 |
| `value` | `[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*` (RFC 6265 cookie-octet。空は可 = 削除用)。= CTL / 空白 / `"` / `,` / `;` / `\` / 非 ASCII を拒否 | `token_urlsafe` の文字集合 `[A-Za-z0-9_-]` は全て通る (実走確認) |
| `path` | `/` で始まり、`[\x21-\x3A\x3C-\x7E]*` (CTL / 空白 / `;` を含まない) | `Path="/\r\nSet-Cookie: evil=1"` を拒否 (AUTH-15) |
| `domain` | `None` または `[A-Za-z0-9.-]+` | |
| `max_age` | `int` (bool は不可)。負値は 0 に正規化して出力 | 期限切れ算出が負になった場合を削除として扱う |
| `expires` | `datetime`。tzinfo 無し → `replace(tzinfo=timezone.utc)`、有り → `astimezone(timezone.utc)` | |
| `same_site` | `"Strict"` / `"Lax"` / `"None"` の完全一致 (大文字小文字も)。`"None"` のとき `secure=False` なら C02 | ブラウザは `SameSite=None; Secure` 以外の None を拒否する |

### 5.3 出力形式 (`to_header()`)

`name=value` の後に、存在する属性だけを **この順** で `; ` 区切り、末尾に `;` を付けない:

`Max-Age=<int>` → `Expires=<IMF-fixdate>` → `Path=<path>` → `Domain=<domain>` → `Secure` → `HttpOnly` → `SameSite=<v>`

`Expires` は `email.utils.format_datetime(dt_utc, usegmt=True)` の出力 (例 `Wed, 21 Oct 2026 12:00:00 GMT`)。

例:
- `Cookie("_nxt", "abc", max_age=3600)` → `_nxt=abc; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax`
- `Cookie.delete("_nxt")` → `_nxt=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax`
- `Cookie("sid", "v", secure=False, http_only=False, same_site="Strict", domain="example.com")` → `sid=v; Path=/; Domain=example.com; SameSite=Strict`

### 5.4 Response 側の受け口

`Response(..., cookie: "str | Cookie | None" = None)`。`Cookie` を渡すと `str(cookie)`。`str` を渡した場合も §6.2 のヘッダ値検証 (CR/LF 拒否) を通る。複数 Set-Cookie は `res.append_header("Set-Cookie", str(c2))` で足す (従来どおり)。

### 5.5 現行呼び出し (nexom 内、grep 全件) と移行先

| 箇所 | 現行 | 1.2.0 | 所有 |
|---|---|---|---|
| `templates/auth.py:83` | `Cookie(KEY_NAME, sess.token, Path="/", MaxAge=sess.expires_at)` | `Cookie(KEY_NAME, sess.token, max_age=max(0, sess.expires_at - int(time.time())))` (`expires_at` は絶対 epoch 秒 — A-auth AUTH-02) | auth doc |
| `templates/auth.py:140` | `Cookie(KEY_NAME, "", Path="/", MaxAge=0)` | `Cookie.delete(KEY_NAME)` | auth doc |
| aisaba (§19) | `Cookie(..., Domain=, SameSite=, Path="/", Max_Age=expires_at)` | §19 #1 | 利用側 |

---

## 6. Response ヘッダ (HTTP-03 / 06 / 10)

対象: `src/nexom/app/response.py`

### 6.1 シグネチャ

```python
Header = tuple[str, str]

class Response:
    security_headers: ClassVar[dict[str, str]] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
    }

    def __init__(
        self,
        body: str | bytes = b"",
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: "str | Cookie | None" = None,
        content_type: str = "text/plain",
        charset: str = "utf-8",
        include_charset: bool = False,
        *,
        security_headers: bool = True,
    ) -> None: ...
    def append_header(self, key: str, value: str) -> None: ...   # 検証あり。重複排除なし (従来どおり)

class HtmlResponse(Response):   # 既存引数 + security_headers: bool = True (kw-only)
class JsonResponse(Response):   # 同上
class ErrorResponse(Response):
    def __init__(self, status: int, message: str, headers: Iterable[Header] | None = None) -> None
```

### 6.2 ヘッダ組み立て規則 (`__init__`)

1. `base = [("Content-Type", ct)]` (`ct` は従来どおり `include_charset` で `; charset=` を付加)
2. `sec = list(Response.security_headers.items())` (`security_headers=False` なら `[]`)
3. `caller = list(headers or [])` を 1 件ずつ検証 (6.3)。違反は `ResponseHeaderInvalidError` (RS01)
4. `override = {k.lower() for k, _ in caller}`。`self.headers = [h for h in base + sec if h[0].lower() not in override] + caller`
   → **名前が一致する既定 (Content-Type / セキュリティヘッダ) は caller 側が置き換える。一致しなければ併合**。caller 内の重複 (Set-Cookie ×2 等) はそのまま残す
5. `cookie` があれば `("Set-Cookie", str(cookie))` を検証して append
6. `Content-Length` が無ければ `str(len(body))` を append (従来どおり)

結果例: `JsonResponse({"a":"<b>"}, headers=[("X-A","1")]).headers` → `[("Content-Type","application/json; charset=utf-8"), ("X-Content-Type-Options","nosniff"), ("X-Frame-Options","DENY"), ("Referrer-Policy","strict-origin-when-cross-origin"), ("Content-Security-Policy","frame-ancestors 'none'; base-uri 'self'; object-src 'none'"), ("X-A","1"), ("Content-Length","12")]`

### 6.3 ヘッダ検証 (`__init__` の `content_type` (charset 連結後の `ct`) / caller / cookie、`append_header`、`Redirect` の Location)

`content_type` 引数も `("Content-Type", ct)` として同じ値検証を通す (RG05: `Response(b"x", content_type="text/plain\r\nX: y")` が無検査で通っていた)。`charset` も `ct` に連結された形で検証される。

- 名前: `[!#$%&'*+\-.^_`|~0-9A-Za-z]+` に fullmatch
- 値: `[\t\x20-\x7e\x80-\xff]*` に fullmatch (gunicorn `HEADER_VALUE_RE` と同じ集合。CR / LF / その他 CTL を拒否、`\t` は許可、非 ASCII は Latin-1 範囲のみ)
- 違反 → `ResponseHeaderInvalidError(name)` (RS01)。値はメッセージに含めない (ログ注入を避ける)

### 6.4 セキュリティヘッダの方針

- `X-Content-Type-Options: nosniff` / `X-Frame-Options: DENY` / `Referrer-Policy: strict-origin-when-cross-origin` を**全応答**に付ける (JSON / 静的 / リダイレクト / 204 含む。`Response.__init__` が唯一の付与点なので wsgi 雛形の `except` 経路や Static も漏れない)
- CSP は **`frame-ancestors 'none'; base-uri 'self'; object-src 'none'` のみ**。`script-src` / `style-src` は付けない (理由: §21-5)。スクリプト制限を掛けるアプリは `Response.security_headers["Content-Security-Policy"] = "default-src 'self'; ..."` を wsgi.py の import 時に 1 回設定する
- HSTS は付けない (TLS 終端が nginx / Cloudflare)。必要なら同じ辞書に `"Strict-Transport-Security": "max-age=31536000; includeSubDomains"` を足す (opt-in)
- 上書き口は 2 つ: (a) プロセス全体 = `Response.security_headers` 辞書を書き換える / キーを `pop` する、(b) 応答単位 = `headers=[("X-Frame-Options", "SAMEORIGIN")]` で名前一致置換、または `security_headers=False` で全部外す
- `Response.security_headers` は **クラス属性を直接参照**する (インスタンス生成時に `type(self).security_headers` を読む)。サブクラスで上書きすればそのサブクラスだけ変わる

---

## 7. Redirect (HTTP-11 / 10)

```python
class Redirect(Response):
    def __init__(
        self,
        location: str,
        headers: Iterable[Header] | None = None,
        cookie: "str | Cookie | None" = None,
        *,
        status: int = 302,                 # 301 / 302 / 303 / 307 / 308 以外は ValueError
        allow_external: bool = False,
    ) -> None
```

検査順と例外種別 (`allow_external` に**関わらず**両方とも拒否):
1. **ヘッダ値検証を先に通す** (`_validate_header("Location", loc)`、§6.3 と同じ正規表現 `[\t\x20-\x7e\x80-\xff]*`)。CR / LF / `0x00`〜`0x08` / `0x0A`〜`0x1F` / `0x7F` / Latin-1 外の文字を含めば **RS01** (`ResponseHeaderInvalidError`)
2. 次に Location 固有の拒否: `loc` が空、**先頭が空白 (`0x20`)**、または **TAB (`0x09`、ヘッダ値としては合法だが WHATWG URL パーサが位置に関係なく除去する) を含む** なら **RS02** (`ResponseRedirectExternalError`)。`/\t\evil.example` が `https://evil.example/` に解決される (Codex 第 2 パス RG04 で実機確認)。先頭空白も除去されるので ` /\evil` が外部になる。先頭以外の空白 (`/a b`) は通る
3. 最後に `_is_local_location` (下記) で外部判定 → `allow_external=False` なら RS02

整理: 「ヘッダとして不正な文字」は RS01、「ヘッダとしては合法だが URL として外部化・曖昧化する形」は RS02。

ローカル判定 `_is_local_location(loc)` (全部 True で「ローカル」):
1. `loc` が空でない、かつ先頭が `\` でない
2. `urllib.parse.urlsplit(loc)` の `scheme` と `netloc` が両方空
3. `loc` が `/` で始まるなら 2 文字目が `/` でも `\` でもない

`allow_external=False` でローカルでなければ `ResponseRedirectExternalError(location)` (RS02)。実走結果: `/next` `/` `next` `?a=1` `/x?u=https://ok` → ローカル。`//evil.example` `/\evil.example` `\\evil.example` `///evil` `https://x` `http:evil` `javascript:alert(1)` → 外部。Location 値は §6.3 の検証も通る (`\r\n` → RS01)。

---

## 8. Request (HTTP-02 / 13、AUTH-12)

対象: `src/nexom/app/request.py`

### 8.1 シグネチャ

```python
class Request:
    DEFAULT_MAX_BODY_SIZE: int = 10 * 1024 * 1024          # 不変
    DEFAULT_MAX_MULTIPART_PARTS: int = 64

    def __init__(
        self,
        environ: WSGIEnviron,
        *,
        max_body_size: int | None = None,          # None → DEFAULT_MAX_BODY_SIZE。上限を外す口は無い
        max_multipart_parts: int | None = None,    # None → DEFAULT_MAX_MULTIPART_PARTS
        trusted_proxy_count: int = 0,              # §9。雛形は config.TRUSTED_PROXY_COUNT を渡す
    ) -> None

    @property
    def remote_addr(self) -> str                   # environ["REMOTE_ADDR"] or "" (生の接続元。プロキシ構成では nginx の IP)
    @property
    def client_ip(self) -> str                     # client_ip(self.environ, trusted_proxy_count=self.trusted_proxy_count)
                                                   # = §9 で解決した末端クライアント IP。auth doc のレート制限 IP 軸はこれを使う
                                                   # (auth-hardening doc 要求 (a))。REMOTE_ADDR も無ければ "-"
    def read_body(self) -> bytes
    def json(self) -> Any | None
    def form(self) -> dict[str, list[str]] | None
    def files(self) -> dict[str, str | File] | None

@dataclass(frozen=True)
class File:
    filename: str
    content_type: str | None
    size: int | None          # 1.2.0 から multipart の part.size を入れる (現行は常に None)
    file: Any

def client_ip(environ: Mapping[str, Any], *, trusted_proxy_count: int = 0) -> str   # §9
```

### 8.2 規則

| # | 規則 |
|---|---|
| Q-R1 | `_content_length()`: `CONTENT_LENGTH` が無い / 空 → `None`。`int()` に失敗、または負 → `RequestParseError("invalid Content-Length")` (RQ02)。**`Request.__init__` が 1 回評価して `self._length` に保持する**ので、不正値は構築時点で RQ02 になる (現行: None 扱いで最大 10 MiB + 1 まで読む) |
| Q-R2 | `read_body()`: CL があり `> max_body_size` → ストリームを読まずに `RequestEntityTooLargeError` (RQ01)。CL が無い → `max_body_size + 1` まで読み超えたら RQ01 (現行の `ValueError` を置換) |
| Q-R3 | `json()`: `UnicodeDecodeError` / `json.JSONDecodeError` → `RequestParseError("invalid JSON body")` (RQ02)。メッセージに body を含めない。Content-Type 不一致 / 空 body → `None` (不変) |
| Q-R4 | `form()`: `UnicodeDecodeError` → RQ02。`parse_qs` は `max_num_fields=1000` を渡す (超過 `ValueError` → RQ02) |
| Q-R5 | `files()`: (a) `_content_length()` を取り、`> max_body_size` なら読む前に RQ01。(b) boundary 無し → RQ02 (現行 `ValueError`)。(c) `wsgi.input` を `_LimitedStream(stream, limit=max_body_size)` で包む — `read(n)` の累積が `limit` を超えた瞬間に RQ01。(d) `MultipartParser(limited, boundary, content_length=cl if cl is not None else -1, part_limit=max_multipart_parts, partsize_limit=max_body_size, disk_limit=max_body_size, memory_limit=min(8 * 1024 * 1024, max_body_size), spool_limit=64 * 1024)`。(e) 反復中の `multipart.ParserLimitReached` → RQ01、その他 `multipart.MultipartError` → RQ02。(f) `File.size = part.size`。(g) `File.content_type = part.content_type` (**現行の `isinstance(part.headers, dict)` 判定は multipart 1.3.1 / 2.0.1 とも `Headers` 型なので常に False で `None` になっていた** — storage doc §9 指摘。`part.content_type` はヘッダ無しのファイルパートに `application/octet-stream` を返す。`File` の型注釈 `str \| None` は据え置く) |
| Q-R6 | `files()` を `read_body()` の後に呼んだ場合の `ValueError("Body was already read…")` は**そのまま** (プログラミングエラー → 500 でよい) |
| Q-R7 | `multipart` 未インストール時のメッセージを `"multipart is required … Install with: pip install multipart"` に修正 (python-multipart は別物。C-data DATA-08 付随) |
| Q-R8 | Cookie 解析 (`_parse_cookies`): `SimpleCookie` を使わず自前で寛容に解析。`HTTP_COOKIE` が無い / 空 → `None`。それ以外 → `;` で分割 → 各片を `strip()` → 最初の `=` で `name, value` に分割 → `name` が §5.2 の token に fullmatch しなければ**その片だけ**捨てる → `value` が `"` で始まり `"` で終わるなら両端を剥がす → 同名は**最初**を採る → `RequestCookies(dict)` (マッピングを渡す。`**` 展開はしない — ユーザー制御のヘッダ名を Python の呼び出し機構に流さない。現行の `RequestCookies(**cookies)` は `self` という名の cookie で `TypeError` になり `except Exception` で素の dict に落ちていた)。例外は投げない。例: `a=b; bad\x7fname=1; c=d` → `{"a":"b","c":"d"}`、`a<b=1` → `RequestCookies()` (空、None ではない)、`self=1; a=b` → `{"self":"1","a":"b"}` で型は `RequestCookies` |
| Q-R9 | `_LimitedStream` は `read(size: int = -1) -> bytes` だけを持つ。`size < 0` または `size > 残り + 1` のときは `残り + 1` に丸めて読む。`multipart` 2.0.1 は `stream.read(buffer_size)` のみ使う (ソース確認済) |

---

## 9. § プロキシ信頼の契約 (HTTP-07 / DATA-10 / AUTH-20)

対象: `src/nexom/app/request.py` の `client_ip()`、雛形 `config.py` / `wsgi.py`。auth doc は `assets/auth/wsgi.py` で**同じ関数を同じ config 値で**呼ぶ。

```python
def client_ip(environ: Mapping[str, Any], *, trusted_proxy_count: int = 0) -> str:
    """
    trusted_proxy_count <= 0            → REMOTE_ADDR (無ければ "-")
    trusted_proxy_count = N (>0)        → X-Forwarded-For を "," で分割し strip、空要素を除いた列 hops の
                                          右から N 個目 hops[-N] を候補にする。
                                          XFF が無い / hops が N 個未満 / 候補が ipaddress.ip_address() で
                                          解釈できない → REMOTE_ADDR にフォールバック
    """
```

実走例 (`REMOTE_ADDR=127.0.0.1`, `XFF="1.1.1.1, 203.0.113.9"`): N=0 → `127.0.0.1`、N=1 → `203.0.113.9`、N=2 → `1.1.1.1`、N=3 → `127.0.0.1`。`XFF="FAKE LOG\nLINE"`, N=1 → `127.0.0.1`。IPv6 `2001:db8::1` は通る。

**`Request.client_ip` プロパティ** は同じ関数を `Request(environ, trusted_proxy_count=N)` の N で呼ぶだけ (計算は毎回。キャッシュしない)。利用側 (アクセスログ、auth のレート制限 IP 軸、将来の IP 許可リスト) は `environ` を直接読まずこのプロパティを使う。XFF 偽装時の値: N=0 なら XFF は**完全に無視**され `REMOTE_ADDR`、N≥1 なら攻撃者が左側に何個足しても右から N 個目 (= 信頼プロキシが見た接続元) が返り、クライアントが自分で付けた値は左側に押し出されて採られない。

- 雛形 `config.py` に `TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__` を追加し、build が埋める (生成規則は §14.5: `--gateway` 無し → 0、あり → 1、`--trusted-proxy-count N` で明示上書き)。コメント: 「gunicorn の前に置くリバースプロキシの段数。直結なら 0、この雛形の gateway 1 段なら 1、Cloudflare → nginx なら 2」
- nginx 雛形は `$proxy_add_x_forwarded_for` (追記) なので右端 = nginx が見た接続元。`X-Real-IP` は使わない (XFF 1 本に統一。Cloudflare 2 段構成でも同じ規則で済む)
- 前提: gunicorn が `127.0.0.1` に bind されていること (§14)。0.0.0.0 で公開する運用では `TRUSTED_PROXY_COUNT=0` にしないと XFF 偽装が通る (doc 注記)

---

## 10. Static (HTTP-04 / 12)

対象: `src/nexom/app/path.py` の `Static`

```python
class Static(Path):
    def __init__(
        self,
        path: str,
        static_directory: str,
        name: str,
        *,
        index_file: str | None = "index.html",   # None でディレクトリ要求を常に 404
        allow_dotfiles: bool = False,
    ) -> None   # methods={"GET", "HEAD"} で super().__init__
```

`_access` の手順 (番号順。各 "404" は `PathNotFoundError(request.path)`):
1. `rel` を `subpath` から組む (従来)。`target = (root / rel).resolve()`、例外 → 404
2. `target == root or target.is_relative_to(root)` でなければ 404 (`str.startswith(root + os.sep)` から `Path.is_relative_to` に置換。意味は同じ)
3. `target.is_dir()` なら: `index_file is None` → 404。それ以外 `target = (target / index_file).resolve()` して **手順 2 を再適用** (NEX-03 / HTTP-04)
4. `target.is_file()` でなければ 404
5. `allow_dotfiles=False` で `target.relative_to(root).parts` のいずれかが `.` で始まる → 404 (resolve 後に判定するので `link -> .env` の symlink も塞ぐ)
6. `mime = guess_type(str(target))[0] or "application/octet-stream"`。`mime.startswith("text/")` なら `"; charset=utf-8"` を付ける
7. `Response(data, headers=[("Content-Type", mime), ("Content-Length", str(len(data)))])` → §6 でセキュリティヘッダ (nosniff 含む) が自動付与

MIME 方針: 拡張子 → `mimetypes.guess_type` を維持。`.html` → `text/html; charset=utf-8`、`.svg` → `image/svg+xml` のまま配る (Static の root は開発者が管理する資産、という前提)。**ユーザアップロード物を Static の root 配下に置かない** — 配信は ParallelStorage 側 (storage doc) の `Content-Disposition: attachment` + 拡張子正規化の経路で行う。本注記を `Static` の docstring と README (storage doc の責務範囲なら申し送り) に書く。

---

## 11. CORS (HTTP-05)

対象: `src/nexom/app/middleware.py`

- `__init__` 末尾: `if self.allow_credentials and ("*" in self.allowed_origins or "null" in self.allowed_origins): raise ValueError("CORSMiddleware: allow_credentials=True requires an explicit allowed_origins list (no '*' / 'null').")`。**import 時 (Router 構築時) に落ちる**
- `allowed_origins=None` → `["*"]` (credentials=False の公開 API 用途。不変)
- Origin 比較は完全一致 (不変)。`Origin: null` は `"null"` が明示列挙されているときだけ echo。`*` 許可 (credentials 無し) では常に `*` を返す (echo しない)。いずれも現行コードの挙動で、テストで固定する
- preflight 処理は §12 の Router 側で OPTIONS が middleware まで届くようになるので、`CORSMiddleware.__call__` 自身の判定 (`method == "OPTIONS" and Access-Control-Request-Method あり → 204`) は不変

---

## 12. メソッド処理 (HTTP-09)

対象: `src/nexom/app/path.py` の `Get` / `Post` / `Router`

### 12.1 変更

- `Post.methods = {"POST"}` (OPTIONS を外す)。`Get.methods = {"GET"}` 不変
- **HEAD 規則 (Router)**: Path が `GET` を許可していれば `HEAD` も許可とみなす (`Get` も、`Path(..., methods={"GET"})` も、aisaba の独自サブクラスも同じ扱い)。gunicorn 26 は HEAD の body を自動で落とす (B-http) ので handler は GET と同じ処理でよい
- `methods=None` (任意メソッド) の Path は従来どおり全メソッドを handler に渡す (OPTIONS / HEAD 含む)

### 12.2 `Router.get(request_path, *, method=None) -> Path | None`

1. `candidates = [(p, score) for p in self if p.match(request_path) ok]`。空 → `raise_if_not_exist` なら `PathNotFoundError`、でなければ `None`
2. `method is None` → `candidates` の最高 score を返す (`AuthPages._handler` が使う経路。不変)
3. `m = method.upper()`。`allows(p) = p.methods is None or m in p.methods or (m == "HEAD" and "GET" in p.methods)`
4. `specific = [p for p in candidates if p.methods is not None and allows(p)]`、`agnostic = [p for p in candidates if p.methods is None]`。`specific` → 最高 score、無ければ `agnostic` → 最高 score
5. どちらも空 → `PathMethodNotAllowedError(request_path, allowed=_allowed_methods(candidates))`。**`raise_if_not_exist=False` のときは 404 と同じく `None` を返す** (旧契約「見つからなければ None」を維持。Leader 裁定 2026-10-21)

実装上は、常に raise する内部関数 `_resolve(request_path, method) -> Path` (手順 1〜5、404 / 405 とも例外) を持ち、公開 `get()` は `raise_if_not_exist` が False なら `PathNotFoundError` / `PathMethodNotAllowedError` の両方を捕まえて `None` を返すラッパにする。`Router.handle` は `_resolve` を呼ぶので、フラグの値に関係なく 405 / OPTIONS 204 の挙動 (§12.3) になる

`_allowed_methods(candidates)`: `methods is not None` の Path の `methods` の和集合。`"GET"` を含めば `"HEAD"` を追加。常に `"OPTIONS"` を追加。`PathMethodNotAllowedError.allowed: frozenset[str]`、`.allow_header: str = ", ".join(sorted(allowed))` (例 `"GET, HEAD, OPTIONS"`)。

### 12.3 `Router.handle(request) -> Response`

```
try:
    path = self._resolve(request.path, request.method)     # raise_if_not_exist を見ない
except PathMethodNotAllowedError as e:
    if request.method == "OPTIONS":
        return self._options_response(request, e)
    raise
return path.call_handler(request, tuple(self.middlewares))
```

`_options_response(request, e)`: `p = self._resolve(request.path, None)` (method 無し = 最高 score の Path) で `args = p._read_args(request.path)`、終端 handler を `lambda req, a: Response(b"", status=204, headers=[("Allow", e.allow_header)])` とし、`self.middlewares` があれば `MiddlewareChain(...).wrap(終端)` を通して返す。→ **CORS preflight は CORSMiddleware が 204 に Access-Control-* を足す。CORS 無しでも 204 + Allow が返る。handler には届かない**。

405 (OPTIONS 以外) は middleware を通らず例外として wsgi 雛形に上がる (ErrorResponse 405 + `Allow`)。

---

## 13. ErrorResponse とログ経路 (HTTP-08 / 13 / 14)

- `ErrorResponse(status, message, headers=None)`: `_render` が `escape(message)` を明示的に通す (E-R10)、`include_charset=True` (`text/html; charset=utf-8`)。`headers` は 405 の `Allow` 用
- wsgi 雛形 (§14.2) が `PathNotFoundError` → 404、`PathMethodNotAllowedError` → 405 + `Allow`、`RequestEntityTooLargeError` → 413、`RequestParseError` → 400、その他 `Exception` → 500 にマップ。応答 message は `http_status_codes[status]` の定数 (ユーザ由来文字列は入れない)
- ログ: **storage doc が `nexom.core.log` に `sanitize_log_field(s: str) -> str` を提供する** (契約: `\r` → `\\r`、`\n` → `\\n`、その他 C0 制御文字と `\x7f` → `\\xNN`、戻り値は 1 行に収まる str)。本 doc の wsgi 雛形は access 行の `method` / `path` / `ua` にこれを通す。`_write` 側でも二重に潰すかは storage doc の判断 (二重でも害なし)
- **404 は warning.log に書かない** (storage doc §9 要求 (3)、DATA-12): 現行雛形の `logger.warn(str(e))` を削除し、404 は access 行の status `404` としてだけ残す。`PathNotFoundError` のメッセージ (パスを含む) はどこにも書かれなくなるので HTTP-14 の偽行注入経路も同時に消える
- 依存関係: **storage doc の `sanitize_log_field` が同じリリースに入ること**が wsgi 雛形の前提 (同 1.2.0。先に本 doc だけマージする場合は Developer が `core/log.py` にこの関数だけ先行追加してよい。storage doc 側と署名が同じなら衝突しない)

---

## 14. 雛形 (`assets/app/**`) と CLI 既定 (HTTP-07)

### 14.1 `assets/app/config.py` (追加 2 項目)

```python
# ======== request ========
MAX_BODY_SIZE: int = 10 * 1024 * 1024   # bytes. body / json / form / files (multipart) に共通で効く

# ======== proxy ========
# gunicorn の前に置くリバースプロキシの段数。0 = 直結 (REMOTE_ADDR のみ信頼)。
# この雛形の nginx / apache gateway を 1 段置くなら 1。Cloudflare -> nginx なら 2。
TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__
```

(`__g_trusted_proxies__` は `__g_port__` と同じ build 時プレースホルダ。§14.5 の規則で `0` / `1` / 明示値に置換される。)

### 14.2 `assets/app/wsgi.py` (全文置換)

```python
"""WSGI entrypoint template for generated app."""

from __future__ import annotations

from typing import Callable, Iterable
import time

from nexom.app.request import Request, client_ip
from nexom.app.response import Response, ErrorResponse
from nexom.app.http_status_codes import http_status_codes
from nexom.core.error import (
    PathNotFoundError,
    PathMethodNotAllowedError,
    RequestEntityTooLargeError,
    RequestParseError,
)
from nexom.core.log import AppLogger, sanitize_log_field

from __app_name__.config import INFO_LOG, WARN_LOG, ERR_LOG, ACES_LOG, MAX_BODY_SIZE, TRUSTED_PROXY_COUNT
from .router import routing


logger = AppLogger(info=INFO_LOG, warn=WARN_LOG, error=ERR_LOG, access=ACES_LOG)


def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    t0 = time.time()
    req: Request | None = None
    res: Response

    try:
        req = Request(environ, max_body_size=MAX_BODY_SIZE, trusted_proxy_count=TRUSTED_PROXY_COUNT)
        res = routing.handle(req)
    except PathNotFoundError:
        # 匿名スキャンで warning.log が無限に伸びるので 404 は access.log だけに残す (DATA-12)
        res = ErrorResponse(404, http_status_codes[404])
    except PathMethodNotAllowedError as e:
        res = ErrorResponse(405, http_status_codes[405], headers=[("Allow", e.allow_header)])
    except RequestEntityTooLargeError:
        res = ErrorResponse(413, http_status_codes[413])
    except RequestParseError:
        res = ErrorResponse(400, http_status_codes[400])
    except Exception as e:
        logger.error(e)
        res = ErrorResponse(500, http_status_codes[500])

    try:
        dt_ms = int((time.time() - t0) * 1000)
        method = req.method if req else str(environ.get("REQUEST_METHOD") or "-")
        path = (req.path if req else str(environ.get("PATH_INFO") or "")).lstrip("/")
        ip = req.client_ip if req else client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)
        ua = str(environ.get("HTTP_USER_AGENT") or "-")
        logger.access(
            f'{ip} "{sanitize_log_field(method)} /{sanitize_log_field(path)}" '
            f'{res.status_code} {dt_ms}ms "{sanitize_log_field(ua)}"'
        )
    except Exception:
        pass

    start_response(res.status_text, res.headers)
    return [res.body]
```

(`AuthLogger` の未使用 import を削除。`http_status_codes[404]` = `"Not Found"`、`[500]` = `"Internal Server Error"` なので文言は現行と同じ。)

**処理順の契約** (auth 雛形も同じ順。RG08: auth 雛形で `Request()` が try の外にあり `CONTENT_LENGTH=abc` が 500 になった):
1. (auth 雛形のみ) `allowed_clients` ガード — `environ["REMOTE_ADDR"]` だけを見る。`Request` を作る前に判定するので、不正な Content-Length / Cookie を送っても拒否判定は変わらない
2. `Request(environ, ...)` の構築を **`try` の内側**で行う。構築時に出る入力起因の例外は `RequestParseError` (Q-R1 の不正 Content-Length) だけで、これは `except RequestParseError` → 400 に落ちる。Cookie ヘッダは例外を投げない (Q-R8)。`Request()` が `ValueError` を上げる入力経路は無い (`max_body_size` 等の引数は設定値で、ユーザ入力ではない)
3. `routing.handle(req)` (handler)
4. access ログは `req` が None (構築失敗) でも環境変数から書く (既存の `req if req else ...` フォールバック)

### 14.3 `assets/app/pages/default.py` — §4.4 のとおり `Markup(...).format(...)`

### 14.4 `assets/app/gunicorn.conf.py` / `router.py` / `templates/*` / `static/*` — 変更なし

### 14.5 CLI / build 既定 (B-R1〜R3)

| 箇所 | 現行 | 1.2.0 |
|---|---|---|
| `buildTools/build.py:16` `AppBuildOptions.address` | `"0.0.0.0"` | `"127.0.0.1"` |
| `__main__.py:53` `start-project --address` | default `0.0.0.0`、help「(default: 0.0.0.0)」 | default `127.0.0.1`、help「Bind address for main app (default: 127.0.0.1; pass 0.0.0.0 to listen on all interfaces)」 |
| `__main__.py:59` `start-project --auth-address` | default `127.0.0.1`、help「(default: 0.0.0.0)」(誤記) | default 不変、help「Bind address for auth app (default: 127.0.0.1; keep it loopback unless you know why)」 |
| `__main__.py:67` `create-auth --address` | `0.0.0.0` | `127.0.0.1` + 同趣旨 help |
| `__main__.py:76` `create-app --address` | `0.0.0.0` | `127.0.0.1` + 同趣旨 help |
| `__main__.py:93` `create-config --address` | `0.0.0.0`、help「Bind address」 | `127.0.0.1`、help「Bind address (default: 127.0.0.1)」 |
| `__main__.py:22` `ArgumentParser(prog="naxom")` | typo | `prog="nexom"` (storage doc §9 要求 (4)。`buildTools/run.py` の文言 "naxom run" は storage doc 側で扱う) |

既存の生成済み `config.py` は影響なし (新規生成のみ)。`AUTH_SERVER = "http://127.0.0.1:7070"` は不変。

### 14.6 `TRUSTED_PROXY_COUNT` の生成規則 (Leader 裁定 2026-10-21 で採用)

```python
@dataclass(frozen=True)
class AppBuildOptions:
    address: str = "127.0.0.1"
    port: int = 8080
    workers: int = 4
    reload: bool = False
    trusted_proxy_count: int | None = None   # None = gateway の有無から導出。int なら明示値 (0 以上)
```

| 入口 | 導出 (`options.trusted_proxy_count is None` のとき) | 明示値 |
|---|---|---|
| `start_project(gateway=...)` の main app | `gateway != "none"` → `1`、`"none"` → `0`。`start_project` が `dataclasses.replace(main_opt, trusted_proxy_count=導出値)` してから `create_app(...)` を呼ぶ (現行 `create_app(root, main_name, options=main_opt, gateway_config=None)` の構造は変えない。gateway ファイルは従来どおり start_project が書く) | `--trusted-proxy-count N` |
| `start_project` の auth app | 常に `0` (loopback 直結) | `--auth-trusted-proxy-count N` |
| `create_app(gateway_config=...)` | `gateway_config` が truthy → `1`、None → `0` | `--trusted-proxy-count N` |
| `create_auth(...)` | `0` | `--trusted-proxy-count N` |
| `create_config(auth=...)` | `0` (gateway を知らない) | `--trusted-proxy-count N` |

- `build.py` の 4 つの `_replace_many` 辞書 (create_app / create_auth / create_config / start_project の auth 側) に `"__g_trusted_proxies__": str(effective)` を追加する。`_replace_many` は「辞書のキーが置換後にも残っていれば例外」なので、テンプレートにプレースホルダが無い場合 (auth の config 雛形がまだ持たない場合) は何も起きない — auth doc 側は `assets/auth/config.py` に `TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__` を足せば自動で埋まる
- `trusted_proxy_count` に負の int を渡したら `create_*` が `ValueError("trusted_proxy_count must be >= 0")`
- CLI (`__main__.py`): `start-project --trusted-proxy-count` / `--auth-trusted-proxy-count`、`create-app --trusted-proxy-count`、`create-auth --trusted-proxy-count`、`create-config --trusted-proxy-count` を `type=int, default=None` で追加。help は「Number of trusted reverse proxies in front of gunicorn (default: 1 if --gateway is set, else 0)」(create-app は「1 if --gateway-config is set, else 0」、auth 系と create-config は「default: 0」)。値はそのまま `AppBuildOptions(trusted_proxy_count=args.trusted_proxy_count)` へ

---

## 15. エラー型 (`core/error.py` に追加。既存クラス・コードは不変)

```python
class NexomError(Exception):
    http_status: ClassVar[int] = 500      # 追加 (既存クラスは全て 500 のまま)

# Path
class PathMethodNotAllowedError(NexomError):          # "P05", http_status = 405
    def __init__(self, path: str, allowed: Iterable[str]) -> None
    allowed: frozenset[str]
    allow_header: str                                   # ", ".join(sorted(allowed))
    # message: f"Method is not allowed for this path. '{path}'"
class PathNotFoundError(NexomError):                   # 既存。http_status = 404 を追加

# Request
class RequestEntityTooLargeError(NexomError):          # "RQ01", http_status = 413, message "Request entity is too large."
class RequestParseError(NexomError):                   # "RQ02", http_status = 400
    def __init__(self, detail: str) -> None             # message f"Request could not be parsed. ({detail})" detail は定数文字列のみ

# Response
class ResponseHeaderInvalidError(NexomError):          # "RS01"  def __init__(self, name: str)  message f"Invalid response header. '{name}'"
class ResponseRedirectExternalError(NexomError):       # "RS02"  def __init__(self, location: str)

# Cookie
class CookieInvalidValueError(NexomError):             # 既存 "C01" (name / value)
class CookieInvalidAttributeError(NexomError):         # "C02"  def __init__(self, name: str, detail: str)

# ObjectHTML
class TemplateUnsafeSlotError(NexomError):             # "OH06"  def __init__(self, doc_name: str, reason: str)
    # reason は属性名 ("onclick" / "srcdoc" / "style" …) または位置種別 ("unquoted attribute" / "script/style body" / "tag/attribute name position" / "comment")
    # message f"Unsafe slot position ({reason}) in template '{doc_name}'. Use json_script()/safe_url() or move the slot to element body / quoted text attribute."
```

## 16. 公開 API (`app/__init__.py`)

追加 export: `Markup`, `escape`, `safe_url`, `json_script` (from `.template` 経由で `core.object_html_render` を再 export)、`CORSMiddleware`、`client_ip`、`File`。`__all__` にも追加。削除なし。**`_AttrSafe` は非公開** — `nexom.app` / `nexom.app.template` から import させず `__all__` にも載せない (`core.object_html_render` 内の名前としてだけ存在。E27c で確認)。

---

## 17. 挙動仕様 (Reviewer はここからテストを生成する)

記法: 「入力 → 期待」。`make_environ` は `tests/conftest.py` の既存ヘルパ。「現状」は §2 の実測。

### 17.1 自動エスケープ (E)

| # | 入力 | 期待 |
|---|---|---|
| E1 | `ObjectHTML(HTMLDoc("t", "<h2>{{ v }}</h2>")).render("t", v='</h2><script>alert(1)</script>')` | `<h2>&lt;/h2&gt;&lt;script&gt;alert(1)&lt;/script&gt;</h2>` (現状: 生) |
| E2 | 同テンプレ `<a title="{{ v }}">` に `v='" onmouseover="alert(1)'` | `<a title="&quot; onmouseover=&quot;alert(1)">` |
| E3 | `v="' onmouseover='x"` を `title='{{ v }}'` に | `title='&#x27; onmouseover=&#x27;x'` |
| E4 | `render("t", v=Markup("<b>ok</b>"))` | `<h2><b>ok</b></h2>` |
| E5 | `render("t", v=None)` | `<h2>None</h2>` |
| E6 | `render("t", v=5)` | `<h2>5</h2>` |
| E7 | `class H: def __html__(self): return "<i>h</i>"`; `render("t", v=H())` | `<h2><i>h</i></h2>` |
| E8 | 戻り値型: `isinstance(engine.render("t", v="x"), Markup)` | True |
| E9 | ネスト: inner = `engine.render("t", v="<x>")`; `ObjectHTML(HTMLDoc("o", "<div>{{ c }}</div>")).render("o", c=inner)` | `<div><h2>&lt;x&gt;</h2></div>` (inner は 1 回だけエスケープされ、外側で素通し) |
| E10 | `Markup("\n").join([Markup("<a>"), "<b>"])` | `Markup("<a>\n&lt;b&gt;")` |
| E11 | `Markup("<i>{}</i>").format("<x>")` | `Markup("<i>&lt;x&gt;</i>")`; `Markup("<i>{}</i>").format(Markup("<x>"))` → `<i><x></i>` |
| E12 | `Markup("<a>") + "<b>"` → `Markup("<a>&lt;b&gt;")`; `"<b>" + Markup("<a>")` → `Markup("&lt;b&gt;<a>")`; `Markup("<a>") + Markup("<b>")` → `Markup("<a><b>")` | |
| E13 | `Markup("<a>").strip()` の型 | `str` (Markup ではない) |
| E14 | Insert 由来は素通し: `base="<div>{{slot}}</div>"`, `child="<Extends base />\n<Insert slot><b>hello</b></Insert>"` → `render("child")` | `<div><b>hello</b></div>` (既存 `test_object_html_render_simple` の `hello` 版も不変) |
| E15 | 再展開なし: `render("t", v="{{ v }}")` | `<h2>{{ v }}</h2>` |
| E16 | `ObjectHTML(doc, autoescape=False).render("t", v="<b>")` | `<h2><b></h2>` |
| E17 | `ObjectHTMLTemplates(tmp_dir).render("page", x="<s>")` (tmp に `page.html` = `<p>{{ x }}</p>`) | `<p>&lt;s&gt;</p>`、戻り値 Markup。`templates.page(x="<s>")` も同じ |
| E18 | `safe_url("https://a.example/x")` → `Markup("https://a.example/x")`; `safe_url("/rel")` / `"?q=1"` / `"#top"` / `"//other.example/x"` → そのまま; `safe_url("mailto:a@b")` → そのまま | |
| E19 | `safe_url("javascript:alert(1)")`, `"java\tscript:alert(1)"`, `" JAVASCRIPT:x"`, `"data:text/html,x"`, `"x:y"` | いずれも `Markup("")` |
| E20 | `safe_url('https://a/?q="<x>')` | `Markup("https://a/?q=&quot;&lt;x&gt;")` (許可されたらエスケープして返す) |
| E21 | `json_script({"a": "</script><b>&"})` | `Markup('{"a": "\\u003c/script\\u003e\\u003cb\\u003e\\u0026"}')` |
| E22 | `json_script({"a": 1}, element_id="boot")` | `Markup('<script id="boot" type="application/json">{"a": 1}</script>')`; `element_id="x y"` → `ValueError` |
| E23 | `ErrorResponse(404, "<img src=x onerror=alert(1)>")` | body に `&lt;img src=x onerror=alert(1)&gt;` を含み、`<img` を含まない。`("Content-Type", "text/html; charset=utf-8") in headers`。`ErrorResponse(404, "missing")` の body に `b"missing"` (既存テスト不変) |
| E24 | `ErrorResponse(500, Markup("<b>x</b>"))` | body に `&lt;b&gt;x&lt;/b&gt;` (Markup でも常にエスケープ) |
| E25 | `ObjectHTML(HTMLDoc("render", "<p>{{ a }}</p>"))` | 例外なし。`engine.render("render", a="1")` → `<p>1</p>`。`engine.render` は bound method のまま (`callable` で `_call` に置換されていないこと = `engine.render.__name__ == "render"`) |
| E26 | `ObjectHTML(HTMLDoc("t", '<a title="{{ v }}">x</a>')).render("t", v=Markup('y" onmouseover="alert(1)'))` | `<a title="y&quot; onmouseover=&quot;alert(1)">x</a>` (属性値位置では Markup でも escape、E-R12)。同じ Markup を `<p>{{ v }}</p>` に渡すと `<p>y" onmouseover="alert(1)</p>` (本文位置は素通し、E4 と同じ) |
| E27 | `'<a title = \'{{ v }}\'>'` (`=` の前後に空白、単引用符) に `v=Markup('<b>')` | `title = '&lt;b&gt;'` (空白を挟んでも属性値位置と判定)。`'<p data-x="a" {{ v }}>'` (引用符は閉じている = 属性名位置) に `Markup("<b>")` → 素通し (本文扱い。属性名位置へのスロットは E-R6 (c) で非対応) |
| E27b | `'<div title="prefix {{ x }}">'` に `x=Markup('y" onmouseover="alert(1)')` | `<div title="prefix y&quot; onmouseover=&quot;alert(1)">` (スロットの直前が `="` でなくても、タグ内で引用符が開いていれば属性値位置。RG02 の再発防止)。`'<a title="a>b {{ v }}">'` に `Markup("<b>")` → `title="a>b &lt;b&gt;"` (引用符内の `>` ではタグを閉じない)。`'<a href="x">{{ v }}</a>'` に `Markup("<b>")` → `<a href="x"><b></a>` (タグが `>` で閉じた後は本文位置) |
| E27c | `'<a href="{{ u }}">'` に `u=safe_url("/?a=1&b=2")` | `<a href="/?a=1&amp;b=2">` (`&amp;` は **1 回だけ**。`_AttrSafe` は属性値位置でも素通し。RG07 の再発防止)。同じテンプレに `u=Markup("/?a=1&b=2")` (safe_url を通さない Markup) → `href="/?a=1&amp;b=2"` (Markup は属性値位置で escape されるので結果は同じだが、`u=Markup('x" onclick="a')` なら `&quot;` に符号化される)。`isinstance(safe_url("/x"), Markup)` → True、`type(safe_url("/x")).__name__ == "_AttrSafe"`、`"_AttrSafe" not in nexom.app.__all__` かつ `not hasattr(nexom.app, "AttrSafe")` |
| E28 | `ObjectHTML(HTMLDoc("t", '<div onclick="{{ h }}">'))`、`'<div style="color:{{ c }}">'`、`"<iframe srcdoc='{{ d }}'>"`、`'<div  onmouseover = "x{{ h }}">'`、**`'<div ONCLICK="{{ x }}">'`** (大文字)、**`'<div onclick="if (\'x\') {{ x }}">'`** (値の中に異種引用符) | いずれも構築時に `TemplateUnsafeSlotError` (OH06、`.code == "OH06"`、メッセージに属性名を含む)。`ObjectHTMLTemplates(dir)` でも同じ (ディレクトリに該当 html を置く)。`autoescape=False` でも投げる。一方 `'<div data-onx="{{ v }}">'`、`'<p title="on{{ v }}">'`、`'<a href="{{ u }}">'` は例外なし |
| E29 | `ObjectHTML(HTMLDoc("t", "<script>let x={{ x }}</script>"))`、`'<script>var a = {{x}}</script>'`、`'<SCRIPT>{{x}}</SCRIPT>'`、`'<style>p{color:{{c}}}</style>'` | いずれも構築時に `TemplateUnsafeSlotError` (OH06、メッセージに `script/style body`)。理由: 通せば `let x=alert(1)` が実行可能なまま出る (エスケープ対象文字が無い)。一方 `'<script src="{{ s }}"></script><p>{{ y }}</p>'` は例外なし (`src` は属性値位置、`{{ y }}` は終了タグ後の DATA)、`'<script></script>{{x}}'` も例外なし |
| E31 | Codex 第 2 パスの迂回例: `'<div title="a < {{ x }}">'` と `'<div title="a <!-- {{ x }}">'` に `x=Markup(' onmouseover="alert(1)" ')` | いずれも `title="a &lt; …"` / `title="a &lt;!-- …"` の形で `onmouseover=&quot;alert(1)&quot;` に escape される (引用符内の `<` / `<!--` で属性値位置の判定がリセットされない。RG02)。同じ x を `'<a title="a <span {{ x }}">'` に渡しても escape。`'<p/onclick="{{ x }}">'`、`'<iframe/srcdoc="{{ x }}">'` → 構築時 OH06 (`/` を属性区切りとして読む。RG03)。`'<{{ t }}>'`、`'<p {{ a }}>'` → OH06 (`tag/attribute name position`)。`'<!-- {{ x }} -->'` → OH06 (`comment`)。`'<a title={{ x }}>'` → OH06 (`unquoted attribute`) |
| E30 | `safe_url(Markup("jav&#x61;script:alert(1)"))` → `""` (文字参照を復号してから判定)。`safe_url(Markup("https://a/x"))` → `"https://a/x"`。`safe_url("https://a/?x=1&amp;y=2")` → `"https://a/?x=1&amp;y=2"` (復号 → `&y=2` → 再 escape)。`safe_url('https://a/?q="')` → `"https://a/?q=&quot;"`。戻り値の型は全て `_AttrSafe` (E18〜E20 も同じ。文字列値は不変) | |

### 17.2 Cookie (K)

| # | 入力 | 期待 |
|---|---|---|
| K1 | `str(Cookie("_nxt", "abc", max_age=3600))` | `_nxt=abc; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax` (現状: `_nxt=abc; HttpOnly; Secure;` 末尾 `;` 付き、SameSite 無し) |
| K2 | `str(Cookie.delete("_nxt"))` | `_nxt=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax` |
| K3 | `Cookie("sid", "v", secure=False, http_only=False, same_site="Strict", domain="example.com")` | `sid=v; Path=/; Domain=example.com; SameSite=Strict` |
| K4 | `Cookie("k", "v", expires=datetime(2026, 10, 21, 12, 0, 0))` (naive) | `Expires=Wed, 21 Oct 2026 12:00:00 GMT` を含む。`tzinfo=timezone(timedelta(hours=9))` の 21:00 を渡しても同じ文字列 |
| K5 | `Cookie("k", "v", max_age=-5)` | `Max-Age=0` |
| K6 | `Cookie("k", "v", same_site="None", secure=False)` | `CookieInvalidAttributeError` (C02)。`secure=True` なら `…; Secure; HttpOnly; SameSite=None` |
| K7 | `Cookie("k", "v", same_site="lax")` / `"none"` / `"strict"` (小文字) | C02 |
| K8 | `Cookie("k", "v; Path=/evil")` | `CookieInvalidValueError` (C01) (現状: 属性注入が通る) |
| K9 | `Cookie("k", "a b")`, `'a"b'`, `"a,b"`, `"a\\b"`, `"ä"`, `"abc\r\n"` | 全て C01。`Cookie("k", "a=b")`, `Cookie("k", "")`, `Cookie("k", secrets.token_urlsafe(24))` は通る |
| K10 | `Cookie("my cookie", "v")`, `Cookie("a=b", "v")`, `Cookie("", "v")`, `Cookie("x\r\ny", "v")` | C01 |
| K11 | `Cookie("k", "v", path="/\r\nSet-Cookie: evil=1")` | C02 (現状: Set-Cookie 行が 2 本分出る)。`path="relative"` (先頭 `/` 無し) も C02 |
| K12 | `Cookie("k", "v", domain="evil.com; Path=/")` | C02 |
| K13 | `Cookie("k", "v", Path="/")` / `MaxAge=0` / `Max_Age=1` / `SameSite="Lax"` (旧 kwargs) | `TypeError` (unexpected keyword) |
| K14 | `hasattr(Cookie("k","v"), "set")` | False |
| K15 | `Response("x", cookie=Cookie("k", "v"))` | `("Set-Cookie", "k=v; Path=/; Secure; HttpOnly; SameSite=Lax") in headers`。`cookie=str(Cookie(...))` も同じ |
| K16 | `Cookie("k", "v").response("body")` | `Response` で status 200、Set-Cookie 1 本 |

### 17.3 Response ヘッダ / Redirect (H / R)

| # | 入力 | 期待 |
|---|---|---|
| H1 | `JsonResponse({"a": "<b>"}, headers=[("X-A", "1")]).headers` | §6.2 の 7 要素のリストに**この順で**一致 (現状: `[('X-A','1'), ('Content-Length','12')]`) |
| H2 | `HtmlResponse("<p>", headers=[("X-A", "1")])` | `("Content-Type", "text/html; charset=utf-8")` と `("X-A","1")` と `("Content-Length","3")` を含む |
| H3 | `Response(b"x")` | `("X-Content-Type-Options","nosniff")`, `("X-Frame-Options","DENY")`, `("Referrer-Policy","strict-origin-when-cross-origin")`, `("Content-Security-Policy","frame-ancestors 'none'; base-uri 'self'; object-src 'none'")` を全て含む (現状: 0 件)。`Strict-Transport-Security` を含まない |
| H4 | `Response(b"x", headers=[("X-Frame-Options", "SAMEORIGIN")])` | `X-Frame-Options` は 1 件で値 `SAMEORIGIN` |
| H5 | `Response(b"x", headers=[("content-type", "text/csv")])` | `Content-Type` 系ヘッダは 1 件で `("content-type", "text/csv")` (名前は caller の表記、既定は除去) |
| H6 | `Response(b"x", security_headers=False)` | 4 つのセキュリティヘッダをいずれも含まない。`Content-Type` と `Content-Length` はある |
| H7 | `Response.security_headers.pop("Content-Security-Policy")` の後に `Response(b"x")` | CSP を含まない (テスト後に元へ戻す: monkeypatch で辞書をコピー差し替え) |
| H8 | `Response(b"x", headers=[("X-A", "a\r\nb")])` | `ResponseHeaderInvalidError` (RS01) |
| H9 | `Response(b"x", headers=[("Bad Name", "v")])` / `("X:A", "v")` | RS01 |
| H10 | `r = Response(b"x"); r.append_header("X-A", "v\n")` | RS01。`r.append_header("X-A", "a\tb")` は通る |
| H11 | `Response(b"x", headers=[("X-A", "日本語")])` | RS01 (Latin-1 範囲外) |
| H14 | `Response(b"x", content_type="text/plain\r\nX-Evil: 1")`、`Response(b"x", content_type="text/plain", charset="utf-8\r\nX: y", include_charset=True)` | RS01。`Response(b"x", content_type="text/csv; header=present")` は通る |
| H12 | `Response(b"x", headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])` | Set-Cookie が 2 本残る |
| H13 | 既存 `test_response_headers` / `test_json_response_and_redirect` | 不変で通る |
| R1 | `Redirect("/next")` | status 302、`("Location", "/next") in headers`、セキュリティヘッダあり |
| R2 | `Redirect("//evil.example")`, `Redirect("/\\evil.example")`, `Redirect("\\\\evil.example")`, `Redirect("///evil")`, `Redirect("https://x")`, `Redirect("http:evil")`, `Redirect("javascript:alert(1)")` | いずれも `ResponseRedirectExternalError` (RS02) (現状: そのまま Location) |
| R3 | `Redirect("https://apps.example", allow_external=True)` | 302、Location そのまま |
| R4 | `Redirect("/x\r\nSet-Cookie: a=b")` | RS01 (ヘッダ値検証) |
| R5 | `Redirect("/x", status=308)` → 308; `Redirect("/x", status=200)` → `ValueError` | |
| R6 | `Redirect("next")`, `Redirect("?a=1")`, `Redirect("/x?u=https://ok")` | 通る (ローカル) |
| R7 | `Redirect(" /\\evil.example")` (先頭空白)、`Redirect("\t/next")` (先頭 TAB)、`Redirect("")` | RS02 (ヘッダ値としては合法、Location として不正)。**`allow_external=True` を付けても RS02** (`Redirect(" https://x", allow_external=True)` も RS02) |
| R9 | `Redirect("/\\t\\\\evil.example")` (途中 TAB、Python リテラル `"/\t\\evil.example"`)、`Redirect("https://ok.example/\\tx", allow_external=True)` | **RS02** (TAB はヘッダ検証を通るが Location として拒否。`allow_external=True` でも) |
| R10 | `Redirect("/ne\\x7fxt")`、`Redirect("/a\\nb")`、`Redirect("/a\\x00b")`、`Redirect("/x\\r\\nSet-Cookie: a=b")` (R4 と同じ) | **RS01** (`ResponseHeaderInvalidError`。ヘッダ値検証が先に走る)。`allow_external=True` でも RS01 |
| R8 | `Redirect("/a b")` (先頭以外の空白) | 通る (`Location: /a b`。ヘッダ値検証は空白を許す) |

### 17.4 Request (Q)

| # | 入力 | 期待 |
|---|---|---|
| Q1 | multipart 本文 (1 パート、12 MiB の `b"x"`) + 正しい CL、`Request(env)` (既定 10 MiB) `.files()` | `RequestEntityTooLargeError`。**`wsgi.input` から 1 byte も読まれていない** (`BytesIO.tell() == 0`) (現状: 全量受理) |
| Q2 | 同本文で `CONTENT_LENGTH` を削除 (chunked 相当) | `RequestEntityTooLargeError`。`wsgi.input.tell() <= 10 * 1024 * 1024 + 1` (`_LimitedStream` は limit + 1 byte までしか読まない、Q-R9) |
| Q3 | 同本文で `Request(env, max_body_size=16 * 1024 * 1024).files()` | 成功。`form["file"].size == 12 * 1024 * 1024`、`.file.read()` の長さ一致 |
| Q4 | 65 個の text パート (各 `a=1`) | `RequestEntityTooLargeError`。64 個なら成功 |
| Q5 | `Request(env, max_multipart_parts=2)` で 3 パート | RQ01 |
| Q6 | 壊れた multipart (`boundary` ヘッダはあるが本文が `b"garbage"`) | `RequestParseError` (RQ02) |
| Q7 | `Content-Type: multipart/form-data` で boundary 無し | RQ02 (現状: `ValueError`) |
| Q8 | 既存 `test_request_files_simple` | 不変で通り、さらに `form["file"].size == 5` |
| Q20 | 同 multipart 本文 (ファイルパートに `Content-Type: text/plain` あり) → `form["file"].content_type` | `"text/plain"` (現状: `None`)。ファイルパートの `Content-Type` 行を外した本文では `"application/octet-stream"` (multipart ライブラリの既定)。テキストフィールド (`form["public_id"]`) は従来どおり `str` |
| Q9 | `CONTENT_LENGTH="abc"` / `"-5"` / `"1e3"` で `Request(env)` | **構築時に** `RequestParseError` (RQ02)。`CONTENT_LENGTH=" 3"` (前後空白) は `int()` が通るので正常 |
| Q10 | `CONTENT_LENGTH=str(20 MiB)`, body 5 byte, `.body` | RQ01 (現状: `ValueError`) |
| Q11 | CL 無し、body = 10 MiB + 1 byte、`.body` | RQ01 |
| Q12 | `application/json` で body `b"{bad"` → `.json()` | RQ02 (現状: `json.JSONDecodeError`)。`b"\xff"` (不正 UTF-8) も RQ02 |
| Q13 | `.json()` で Content-Type 不一致 → `None`; 空 body → `None`; 既存 `test_request_json` 不変 | |
| Q14 | `application/x-www-form-urlencoded` で 1001 フィールド `a=1&a=1&…` → `.form()` | RQ02。既存 `test_request_form` 不変 |
| Q15 | `HTTP_COOKIE="a=b; bad\x7fname=1; c=d"` | `req.cookie == {"a": "b", "c": "d"}` (現状: `{'a':'b'}`) |
| Q16 | `HTTP_COOKIE="a<b=1"` | 例外なし、`req.cookie == {}` かつ `req.cookie is not None` (現状: `CookieError`) |
| Q17 | `HTTP_COOKIE='k="quoted"; k=second'` | `req.cookie["k"] == "quoted"` (引用符除去、最初が勝つ) |
| Q18 | `HTTP_COOKIE` 無し | `req.cookie is None` |
| Q21 | `HTTP_COOKIE="self=1; a=b"` | `isinstance(req.cookie, RequestCookies)`、`req.cookie == {"self": "1", "a": "b"}`、`req.cookie.get("self") == "1"` (現状: `TypeError` → 素の `dict` に落ちる)。`RequestCookies({"a": "b"}) == {"a": "b"}`、`RequestCookies() == {}`、`RequestCookies(a="b")` → `TypeError` |
| Q19 | `req.remote_addr` | `environ["REMOTE_ADDR"]`、無ければ `""` |

### 17.5 client_ip (X)

| # | 入力 (`REMOTE_ADDR=127.0.0.1`) | 期待 |
|---|---|---|
| X1 | `XFF="1.1.1.1, 203.0.113.9"`, N=0 | `127.0.0.1` |
| X2 | 同、N=1 | `203.0.113.9` |
| X3 | 同、N=2 | `1.1.1.1` |
| X4 | 同、N=3 | `127.0.0.1` (段数不足 → フォールバック) |
| X5 | `XFF="FAKE LOG\nLINE"`, N=1 | `127.0.0.1` |
| X6 | XFF 無し、N=1 | `127.0.0.1` |
| X7 | `XFF="2001:db8::1"`, N=1 | `2001:db8::1` |
| X8 | `XFF=" 10.0.0.1 ,, 10.0.0.2 "`, N=1 | `10.0.0.2` (strip、空要素除去) |
| X9 | REMOTE_ADDR 無し、N=0 | `"-"` |
| X10 | `Request(env)` (trusted_proxy_count 既定 0)、env に `REMOTE_ADDR=127.0.0.1`, `XFF="6.6.6.6"` → `req.client_ip` | `"127.0.0.1"` (偽装 XFF は無視)。`req.remote_addr == "127.0.0.1"` |
| X11 | `Request(env, trusted_proxy_count=1)`、`XFF="6.6.6.6, 203.0.113.9"` → `req.client_ip` | `"203.0.113.9"` (攻撃者が左に足した `6.6.6.6` は採られない)。`XFF="6.6.6.6"` だけなら `"6.6.6.6"` (1 段構成では右端 = プロキシが見た接続元なので、プロキシを経由した限りこれは偽装不能) |
| X12 | `Request(env, trusted_proxy_count=1)`、`XFF="garbage"` → `req.client_ip` | `"127.0.0.1"`。`Request(make_environ())` (REMOTE_ADDR 無し) の `client_ip` → `"-"`、`remote_addr` → `""` |

### 17.6 Static (S)

| # | 入力 (root 下に `a.txt`, `.env`, `sub/index.html -> <root 外>/outside.txt` symlink, `link.txt -> outside.txt`, `.hidden/x.txt`, `up.html`, `d/` (index 無し)) | 期待 |
|---|---|---|
| S1 | `/static/sub/` と `/static/sub` | `PathNotFoundError` (現状: `200 OUTSIDE`) |
| S2 | `/static/link.txt`, `/static/../outside.txt`, `/static/etcdir/hosts` (symlink dir) | `PathNotFoundError` (現状どおり) |
| S3 | `/static/.env` | `PathNotFoundError` (現状: 200)。`Static(..., allow_dotfiles=True)` なら 200 |
| S4 | `/static/.hidden/x.txt` | 404 (ディレクトリ名のドットも拒否) |
| S5 | `/static/a.txt` | 200、`Content-Type: text/plain; charset=utf-8`、`X-Content-Type-Options: nosniff` あり、body `b"A"`。既存 `test_static_files` 不変 |
| S6 | `/static/up.html` | 200、`text/html; charset=utf-8` |
| S7 | `/static/d/` (index 無し) → 404。`Static(..., index_file=None)` で `sub2/index.html` が実在しても `/static/sub2/` → 404 | |
| S8 | `Router(Static(...)).handle(POST /static/a.txt)` | `PathMethodNotAllowedError`、`allow_header == "GET, HEAD, OPTIONS"`。`HEAD /static/a.txt` → 200 |
| S9 | `/static/a\x00.txt`、11 セグメント超 | 404 (現状どおり) |

### 17.7 CORS (C)

| # | 入力 | 期待 |
|---|---|---|
| C1 | `CORSMiddleware(access_control_allow_credentials=True)` | `ValueError` (現状: 構築成功、任意 Origin を echo) |
| C2 | `CORSMiddleware(allowed_origins=["*"], access_control_allow_credentials=True)`、`allowed_origins=["https://a", "*"]` + credentials、`allowed_origins=["null"]` + credentials | `ValueError` |
| C3 | `CORSMiddleware(allowed_origins=["https://app.example"], access_control_allow_credentials=True)` + `Origin: https://app.example` | `ACAO: https://app.example`、`Allow-Credentials: true`、`Vary: Origin` |
| C4 | 同、`Origin: https://app.example.evil` / `Origin: null` | Access-Control-* ヘッダ無し |
| C5 | `CORSMiddleware()` + `Origin: null` | `ACAO: *` (echo しない) |
| C6 | `CORSMiddleware(allowed_origins=["null"])` + `Origin: null` | `ACAO: null` |
| C7 | 既存 `test_middleware_chain_and_cors` | 不変で通る |
| C8 | `r = Router(Post("submit/", h, "S")); r.add_middleware(CORSMiddleware(allowed_origins=["https://a"]))`、`OPTIONS /submit/` + `Origin: https://a` + `Access-Control-Request-Method: POST` | status 204、`ACAO: https://a`、`Allow` に `POST`、handler 未呼出 |

### 17.8 メソッド (M)

| # | 入力 | 期待 |
|---|---|---|
| M1 | `Router(Get("ping/"), Post("submit/"))` に `OPTIONS /submit/` (CORS 無し) | status 204、`("Allow", "OPTIONS, POST")`、handler 未呼出 (現状: handler が OPTIONS で実行され 200) |
| M2 | `PUT /submit/` / `DELETE /submit/` / `GET /submit/` | `PathMethodNotAllowedError`、`e.allowed == frozenset({"POST", "OPTIONS"})`、`e.allow_header == "OPTIONS, POST"`、`e.http_status == 405` (現状: 404) |
| M3 | `HEAD /ping/` | handler 実行、200 (現状: 404)。`POST /ping/` → 405 with `allow_header == "GET, HEAD, OPTIONS"` |
| M4 | `Router(Path("any/", h, "A"))` (methods None) に `OPTIONS` / `HEAD` / `PUT` | 全て handler に届く (不変) |
| M5 | `Router(Get("x/", h1, "G"), Post("x/", h2, "P"))` に `GET /x/` → h1、`POST /x/` → h2、`OPTIONS /x/` → 204 `Allow: GET, HEAD, OPTIONS, POST` | |
| M6 | `Router(Path("x/{a}", h, "Any"), Get("x/fixed", h2, "G"))` に `POST /x/fixed` | `Path` (agnostic) にフォールバック → h 実行 (現行の優先規則を維持) |
| M7 | `r.get("/submit/")` (method 無し) | `Post` を返す (AuthPages 経路、不変) |
| M8 | `r.raise_if_not_exist = False; r.get("/nope/", method="GET")` → `None`; `r.get("/submit/", method="GET")` (パス一致・メソッド不一致) → **`None`** (旧契約維持)。既定 `raise_if_not_exist=True` なら前者 `PathNotFoundError`、後者 `PathMethodNotAllowedError` | |
| M11 | `r.raise_if_not_exist = False` のまま `r.handle(Request(GET /submit/))` → `PathMethodNotAllowedError`、`r.handle(Request(OPTIONS /submit/))` → 204 + `Allow`、`r.handle(Request(GET /nope/))` → `PathNotFoundError` (`handle` はフラグを見ない) | |
| M9 | `Post("x/").methods == {"POST"}`、`Get("x/").methods == {"GET"}` | |
| M10 | `GET /nope/` | `PathNotFoundError` (不変) |

### 17.9 雛形 / CLI / エラー型 (G / B)

| # | 入力 | 期待 |
|---|---|---|
| G1 | `create_app(tmp, "banana")` 後の `banana/config.py` | `'ADDRESS: str = "127.0.0.1"'`、`"MAX_BODY_SIZE: int = 10 * 1024 * 1024"`、`"TRUSTED_PROXY_COUNT: int = 0"` を含み、`"__g_trusted_proxies__"` を含まない (現状: `0.0.0.0`、2 項目無し) |
| G11 | `(tmp / "gateway").mkdir(); create_app(tmp, "b", gateway_config="nginx")` → `b/config.py` | `"TRUSTED_PROXY_COUNT: int = 1"`。`create_app(tmp, "c", options=AppBuildOptions(trusted_proxy_count=2), gateway_config="nginx")` → `= 2` (明示が導出に勝つ)。`AppBuildOptions(trusted_proxy_count=-1)` を渡すと `ValueError` |
| G12 | `start_project(project_root=tmp, gateway="nginx")` → `tmp/app/config.py` は `= 1`、`start_project(project_root=tmp2, gateway="none")` → `= 0`。両方で `tmp/auth/config.py` に `"__g_trusted_proxies__"` が残っていない (プレースホルダがあれば `0` に置換、無ければ元のまま)。`gateway/app.nginx.conf` は従来どおり生成される |
| G13 | `nexom.__main__.main(["create-app", "d", "--out", str(tmp), "--trusted-proxy-count", "3"])` → `d/config.py` に `= 3`。`main(["start-project", "--root", str(tmp3), "--gateway", "apache"])` → `app/config.py` に `= 1`。`start-project --help` の出力に `--trusted-proxy-count` と `--auth-trusted-proxy-count` が出る |
| G2 | 同 `banana/wsgi.py` | `"req.client_ip"`, `"sanitize_log_field("`, `"PathMethodNotAllowedError"`, `"RequestEntityTooLargeError"`, `"max_body_size=MAX_BODY_SIZE, trusted_proxy_count=TRUSTED_PROXY_COUNT"` を含み、`"HTTP_X_FORWARDED_FOR"`, `"AuthLogger"`, `"logger.warn("` を含まない (404 を warning.log に書かない) |
| G14 | `nexom.__main__.main(["--help"])` の出力 (capsys、`SystemExit`) | `"usage: nexom"` で始まり `"naxom"` を含まない (現状: `prog="naxom"` の typo) |
| G3 | 同 `banana/pages/default.py` | `"Markup("` を含み、`'f"Hello <i>'` を含まない |
| G4 | `AppBuildOptions().address` | `"127.0.0.1"` (現状: `"0.0.0.0"`)。`AppBuildOptions(port=7070).address` も同じ |
| G5 | `nexom.__main__.main(["start-project", "--help"])` の出力 (capsys。argparse は `SystemExit(0)` を投げるので `pytest.raises(SystemExit)` で包む) | `"default: 127.0.0.1"` を含み `"default: 0.0.0.0"` を含まない。`create-app --help` / `create-auth --help` / `create-config --help` も同じ |
| G6 | `e = PathMethodNotAllowedError("/x", {"POST", "OPTIONS"})` | `e.allowed == frozenset({"POST", "OPTIONS"})`、`e.allow_header == "OPTIONS, POST"`、`str(e) == "P05 -> Method is not allowed for this path. '/x'"`、`e.http_status == 405`。`PathMethodNotAllowedError("/x", {"POST"}).allow_header == "POST"` (**`OPTIONS` の付加は `Router._allowed_methods` の責務**で、例外クラスは渡された集合をそのまま持つ) |
| G7 | `RequestEntityTooLargeError().code == "RQ01"`, `.http_status == 413`; `RequestParseError("x").code == "RQ02"`, `.http_status == 400`; `PathNotFoundError("/").http_status == 404`; `NexomError("X", "y").http_status == 500` | |
| G8 | `ResponseHeaderInvalidError("X-A").code == "RS01"`; `ResponseRedirectExternalError("//e").code == "RS02"`; `CookieInvalidAttributeError("path", "…").code == "C02"` | |
| G9 | 既存 `test_core.py` 3 件 | 不変 |
| G10 | `from nexom.app import Markup, escape, safe_url, json_script, CORSMiddleware, client_ip, File` | import 成功 |

---

## 18. テスト基盤

- フレームワーク: pytest。実行 `cd Muraki/projects/nexom; .venv/bin/python -m pytest -q`。ベースライン 32 passed / 1 xfailed (`.knowledge/known-failures.md`。xfail は `test_parallel_storage.py::…comp_img` で本 doc 無関係、storage doc が扱う)
- 配置: 既存 3 ファイルを変更 + 新規 `tests/test_http_hardening.py` (§17 の E/K/H/R/Q/X/S/C/M/G を ID ごとに関数化。`test_e01_…` の命名で ID を関数名に残す)
- 既存ヘルパ `tests/conftest.py::make_environ` を使う。CL を外すケースは `env.pop("CONTENT_LENGTH")`。symlink ケースは `os.symlink` (macOS / Linux 両対応、Windows は `pytest.skip`)
- 雛形テキストの検証 (G1〜G3) は `create_app(tmp_path, ...)` の生成物を `read_text` で見る (import しない。`__app_name__` パッケージが無いので import 不可)
- `Response.security_headers` を触るテストは `monkeypatch.setattr(Response, "security_headers", dict(Response.security_headers))` で隔離する

### 18.1 既存テストの変更表 (grep で機械的に洗った結果)

| ファイル::テスト | 変更 | 理由 |
|---|---|---|
| `tests/test_router_static_middleware.py::test_router_get_post_and_options` | OPTIONS の期待を `200` → `204` + `("Allow", "OPTIONS, POST") in headers` に変更。handler 呼出回数を数えて OPTIONS で増えないことを足す | HTTP-09 (M1) |
| `tests/test_router_static_middleware.py::test_static_files` | 変更なし (body のみ assert) | S5 |
| `tests/test_router_static_middleware.py::test_middleware_chain_and_cors` | 変更なし | `CORSMiddleware()` 既定は credentials=False |
| `tests/test_router_static_middleware.py::test_router_does_not_match_extra_segments_for_static_route` / `…missing_trailing…` / `…missing_leading…` | 変更なし (GET のみ、`Get` 経路) | |
| `tests/test_request_response.py::test_error_response` | 変更なし (`b"missing" in body` は成立)。E23 を新規ファイル側に足す | |
| `tests/test_request_response.py::test_request_files_simple` | 変更なし。Q8 として `size == 5` を新規側で確認 | |
| `tests/test_request_response.py` 残り 4 件 | 変更なし | |
| `tests/test_core.py` | 変更なし。G6〜G8 は新規側 | |
| `tests/test_templates_and_buildtools.py::test_object_html_render_simple` (他 doc 所有) | **変えない**。`out.strip() == "<div>hello</div>"` は Markup が str の派生なので成立 (E14 で同趣旨を再確認) | |
| `tests/test_templates_and_buildtools.py::test_auth_pages_login_get` (他 doc 所有) | **変えない**。`_OHTML.render("login", page_path="user/login")` はエスケープ対象文字を含まず同じ HTML、`HtmlResponse` のまま | |
| `tests/test_templates_and_buildtools.py::test_buildtools_create_app_and_auth` (他 doc 所有) | **変えない**。assert 対象は auth config の `AUTH_DB` / `MASTER_USER` / `MASTER_PASSWORD` のみで `ADDRESS` を見ていない (auth doc が `MASTER_PASSWORD` 行を書き換える) | |
| `tests/test_auth_and_db.py` (他 doc 所有) | **変えない**。`Cookie(` / `Response(headers=` / `Router.handle` を使っていない (grep 0 件) | |

---

## 19. 移行ガイド (aisaba_platform 等、1.2.0 へ上げるアプリ)

grep 元: `Developments/Projects/aisaba_platform 2/services/**` (2026-10-21、HEAD 7cd6a73)。「症状」は直さずに上げたときに起きること。

| # | パターン (grep 実例) | 症状 | 直し方 |
|---|---|---|---|
| 1 | `Cookie(KEY_NAME, token, http_only=True, secure=…, Domain=…, SameSite=…, Path="/", Max_Age=expires_at)` (`aisaba_user/app/auth_api.py:119,152`) | `TypeError` (旧 kwargs)。**現状は `Max-Age=<絶対 epoch>` が有効属性として出ており約 56 年 cookie になっている (本番の生バグ)** | `Cookie(KEY_NAME, token, domain=AUTH_COOKIE_DOMAIN, same_site=AUTH_COOKIE_SAMESITE, secure=AUTH_COOKIE_SECURE, max_age=max(0, expires_at - int(time.time())))`。logout は `Cookie.delete(KEY_NAME, domain=…, secure=…, same_site=…)`。`AUTH_COOKIE_SAMESITE` の値は `"Strict"/"Lax"/"None"` の表記に揃える |
| 2 | `CORSMiddleware(allowed_origins=["*"], …, access_control_allow_credentials=True)` (`uploader/router.py:16`) | **import 時 `ValueError` でサービスが起動しない** | `allowed_origins=["https://apps.aisaba.net", "https://aisaba.net"]` のように明示列挙 |
| 3 | レンダ結果の合成 `"\n".join(tags)` / `"\n".join(cards)` (`aisaba_main/pages/default.py:73,80,109,…`) | 中身が `&lt;div&gt;` 表示になる (壊れるが安全) | `Markup("\n").join(cards)`。`cards = ["<p>タグが見つかりませんでした</p>"]` → `[Markup("<p>…</p>")]` |
| 4 | Python 側で組んだ HTML 文字列をスロットに渡す (`aisca/render.py:_build_styles_html / _build_scripts_html / _build_bootstrap_html`、`contents_description=render_html_cached(...)`) | 同上 | 文字列を作る側で `escape(href)` 等を済ませてから `Markup(...)` で包む。`_build_bootstrap_html` は `json_script(boot, element_id=BOOTSTRAP_SCRIPT_ID)` に置換可 |
| 5 | ユーザ由来値のスロット (`/works/tag/{tag}` の `tag_name`、`title=f"{tag} \| Portfolio::"`) | **直るだけ** (AIS-01)。テキスト位置と通常テキスト属性 (`content="{{ title }}"`) は何もしなくてよい | URL 属性 (`tag_link.html` の `href="{{ url }}"` に `_tag_link("works", t)` = タグ名由来の URL、`works/page.html` の `src="{{ contents_header }}"`) は `url=safe_url(_tag_link(...))` のように `safe_url()` を通す (E-R6 (a))。テンプレートに `on*=` / `style=` / `srcdoc=` のスロットがあれば起動時 OH06 で落ちる (aisaba の 73 スロットを grep した範囲では該当なし) |
| 6 | `Redirect("https://apps.aisaba.net")` / `Redirect(LOGIN_REDIRECTS[...])` (絶対 URL) (`aisaba_user/pages/auth_page.py:25,46`, `app/auth_api.py:149,162`, `aisaba_main/pages/default.py:171`) | `ResponseRedirectExternalError` → 500 | 固定の自サイト URL は `allow_external=True`。ユーザ入力由来 (`is_redirect`) は allowlist 照合してから |
| 7 | `request.files()` で 10 MiB チャンク (`uploader/app/multiuploader.py:41`、`chunk_max_size = 10 MiB`) | multipart 本文 = チャンク + フィールド + boundary > 10 MiB → **413** | `uploader/wsgi.py` で `Request(environ, max_body_size=12 * 1024 * 1024)` (または config に `MAX_BODY_SIZE`)。storage doc のチャンク上限とは別に Request 層で 2 MiB 余裕を見る |
| 8 | 各サービスの `wsgi.py` (8 本: aisaba_main / aisaba_user / apps / uploader / dev_uc / dev_assets / nexom_web / auth) | 405/413/400 が 500 に落ちる、XFF 先頭を信用、ログ改行 | §14.2 の雛形に揃える。`TRUSTED_PROXY_COUNT` は aisaba の段数 (Cloudflare → nginx なら 2) |
| 9 | `except json.JSONDecodeError` / `except ValueError` で `req.json()` / `.body` を囲んでいる箇所 | 捕まらなくなる | `except RequestParseError` / `except RequestEntityTooLargeError` (いずれも `NexomError` 派生) |
| 10 | `AppPost` が `methods={"POST", "OPTIONS"}` (`aisca/apps.py:139`)、`AppRouter(Router)` (`aisca/apps.py:69`) | 動くが handler が OPTIONS を見続ける。`AppRouter` が `get()` を override していなければ 405 / 204 の新挙動を継承 | `{"POST"}` に変えて preflight を Router に任せる。`AppRouter` の override 有無を確認 |
| 11 | `apps_handler._build_static_response` (`apps/app/apps_handler.py:66-90`) が Static を再実装 (index.html 再検査なし = NEX-03 と同じ穴、dotfile 配信) | nexom を上げても直らない | §10 の手順 2〜5 を同関数に移植 (または `Static` を使う) |
| 12 | iframe で他オリジンに埋め込まれるページがあるか (apps プラットフォーム) | `X-Frame-Options: DENY` + `frame-ancestors 'none'` で表示不可 | wsgi.py の import 時に `Response.security_headers["X-Frame-Options"] = "SAMEORIGIN"` と CSP を `frame-ancestors 'self' https://apps.aisaba.net` に |
| 13 | `Response(…, headers=app_response.headers)` の素通し (`apps_handler.py:104-121`) | 問題なし (名前一致で置換・併合)。ヘッダ値に CR/LF があれば RS01 | 変更不要 |
| 14 | `Cookie(key, value)` (`apps_handler.py:98`) | 問題なし (`Secure; HttpOnly; SameSite=Lax` が付くようになる) | 変更不要。クロスサイトで送る必要があれば `same_site="None"` を明示 |
| 15 | `Static(...)` 利用 (`dev_uc/router.py:12-13` の `USER_CONTENTS` = ユーザコンテンツを Static で配信) | ドットファイル 404、GET/HEAD のみ。**ユーザアップロード物を Static で配る構成は §10 の方針に反する** | storage doc の配信経路 (attachment / 拡張子正規化) へ移す。移すまでは `.html` / `.svg` が同一オリジンで実行可能なまま |
| 16 | `str(Cookie(...))` の末尾 `;` に依存する文字列比較 | 形式変更 | 無いはず (grep 0 件)。あれば修正 |
| 17 | `nexom_web/pages/documents.py:19` のネスト render (`document_contents=templates.render(...)`) | 自動で素通し (Markup) | 変更不要 |

手順: `pip install -U nexom==1.2.*` → 起動 (#2 で落ちる箱を直す) → `grep -rn "Cookie(\|Redirect(\|\.join(\|CORSMiddleware(" services` で #1/#3/#4/#6 を潰す → 各 wsgi.py を雛形に揃える → ブラウザで主要ページを開いて `&lt;` の露出 (#3/#4 の漏れ) を目視 → `curl -I` で `X-Frame-Options` 等が付いているか確認。

---

## 20. 他 doc への申し送り

### auth doc (`templates/auth.py`, `assets/auth/**`) — auth-hardening doc からの要求 3 件への回答
- (a) `Request.client_ip: str` プロパティ → §8.1 / §9 で定義、挙動は X10〜X12。`Request(environ, trusted_proxy_count=N)` で N を渡す (auth 雛形は `auth/config.py` の `TRUSTED_PROXY_COUNT` を渡す。loopback 直結なら 0)。レート制限の IP 軸はこれを使う
- (b) Cookie 削除ヘルパ名は **`Cookie.delete`** で確定。署名は §5.1 `Cookie.delete(name, *, path="/", domain=None, secure=True, http_only=True, same_site="Lax") -> Cookie` — auth doc の仮称 `Cookie.delete(name, *, path="/", domain=None)` はこの部分適用なので**修正不要**
- (c) `Request._parse_cookies` の `CookieError` 耐性 → §8.2 Q-R8 (SimpleCookie を捨てて自前の寛容解析、不正片だけ捨てる、例外なし)、挙動 Q15〜Q18。`Request()` 構築時に Cookie ヘッダで例外が出る経路は無くなる
- Cookie: §5.5 の 2 箇所。`same_site` 既定 Lax で AUTH-03 が閉じる
- `LogoutPage` の `Redirect(redirect_url)`: Referer が `//evil` だと RS02 で 500 になる。固定 `/` か allowlist へ (AUTH-14 と同時に)
- `ErrorResponse(500, str(e))` (`:138`) は E-R10 でエスケープされるので XSS は消えるが、例外文字列をユーザに見せない方針なら定数へ
- `assets/auth/wsgi.py`: §14.2 と同じ構造にし、`client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)` と `sanitize_log_field` を使う。auth 側 `config.py` には `TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__` と書く — build.py (§14.6) が `0` (または `--auth-trusted-proxy-count` の明示値) で埋める。**処理順は §14.2「処理順の契約」どおり: `allowed_clients` ガード (REMOTE_ADDR のみ) → `Request()` 構築を try 内で (`RequestParseError` → 400) → `service.handler`** (RG08: `CONTENT_LENGTH=abc` が 500 になっていた)。`Request.__init__` が cookie で例外を投げなくなる (Q-R8) ので AUTH-12 の片側は本 doc で閉じる
- **`login.html:150` / `signup.html:220` の `const PAGE_PATH = "/{{ page_path }}"` は `<script>` 本文内のスロットなので、1.2.0 では `_OHTML = ObjectHTML(...)` の構築時に OH06 で落ちる (E-R8 / E29、`templates/auth.py` の import 時)。auth doc 側で必ず書き換える**: 例 `<form id="auth" data-page-path="/{{ page_path }}">` にして JS で `document.getElementById("auth").dataset.pagePath` を読む (通常テキスト属性なので E-R6 で安全)、または `json_script({"page_path": ...}, element_id="boot")`。`test_auth_pages_login_get` はこの書き換え後に通る
- `AuthPages._handler` の `self.routing.get(req.path)` は method 無し呼び出しなので §12 の変更を受けない (M7)。`LoginPage` 等は `methods=None` なので OPTIONS/HEAD も handler に届く (従来どおり)

### storage doc (`core/log.py`, `pyproject.toml`, `parallel_storage.py`) — storage-hardening doc §9 からの要求 4 件への回答
- (1) multipart 未インストール時のエラー文 → §8.2 Q-R7 (`pip install multipart`)
- (2) `files()` の `p.headers` dict 判定 → §8.2 Q-R5 (g) で `p.content_type` に置換、挙動 Q20
- (3) 匿名 404 を warning.log に書かない → §13 / §14.2 の wsgi 雛形 (404 分岐から `logger.warn` を削除)、検証 G2
- (4) `prog="naxom"` → `nexom` → §14.5 表、検証 G14
- `sanitize_log_field(s: str) -> str` を `nexom.core.log` に提供 (契約は §13)
- Request 層の `MAX_BODY_SIZE` (10 MiB) と ParallelStorage の `chunk_max_size` (10 MiB) は**別の上限**。チャンクを multipart で運ぶなら Request 側に余裕が要る (§19 #7)。README / CLAUDE.md に注記するなら storage doc 側
- 「ユーザアップロード物は Static で配らない」の配信側 (attachment / 拡張子正規化) は DATA-04 の実装に含める

### Leader
- (解決済) `--gateway` からの `TRUSTED_PROXY_COUNT` 自動生成は 2026-10-21 裁定で採用、§14.6 に規則、build.py / __main__.py の該当部分を本 doc 所有に拡大 (§0)

---

## 21. 不採用案

1. **`markupsafe` を依存に追加**: pyproject は storage doc 所有 + Touri の「標準部品で足りる所に依存を増やさない」方針。必要なのは `__html__` / `escape` / `join` / `format` だけで 40 行で済む。`__html__` プロトコルは互換にしたので後から差し替えも可能
2. **`autoescape` を opt-in (既定 False) にして次メジャーで反転** (Researcher の段階導入案): Leader 方針 1 (1.2.0 で破壊的変更を許容) に反する。aisaba 本番の XSS が実証済なので既定 True。`autoescape=False` は猶予用に残す
3. **コンテキストごとに escape 方式を変える (属性なら属性用、JS なら JS 文字列用、CSS なら CSS 用)**: 当初は「判別器を足すと誤判定が新しい穴になる」としてコンテキスト判別そのものを不採用にしたが、Codex 第 1・第 2 パスで正規表現と局所的な状態機械が計 4 通り迂回され、**判別しない方が穴になる**と確定した。そこで **テンプレート全体を 1 パスで走査する HTML トークナイザによる位置分類は採用** (§4.1) し、その使い方を「拒否 (OH06) と属性値位置での Markup escape の判定」に限定した。escape 方式は `html.escape(quote=True)` 1 種類のまま変えない — JS / CSS / URL 用のエスケープを足すと「どの方式が当たるか」がトークナイザの精度に依存し、精度の穴がそのまま注入になる。拒否なら誤分類は「正当なテンプレートが起動時に落ちる」(気付ける) 側にしか倒れない
4. **テンプレート読み込み時のスロット位置検査を全属性に広げる (引用符なし属性 `attr={{ x }}`、`<script>` 内、全 URL 属性)**: 引用符なし属性や script 内は正規表現では `<pre>` 内テキストや `a={{ b }}` と区別できず偽陽性で既存テンプレートを落とす。URL 属性は `safe_url()` を通した正当なスロットと区別できない。**`on*` / `srcdoc` / `style` の 3 種に限っては値が丸ごとコードとして解釈される位置で正当な使い方が無く偽陽性が実質ゼロなので、この限定形だけ採用した** (E-R6 (b)、`TemplateUnsafeSlotError`。Codex 第二見解 2026-10-21)。残りは規約 (E-R6 (a)(c)、E-R8) + Reviewer の E2/E3/E29 で代替
5. **CSP に `default-src 'self'` / `script-src 'self'` を既定で付ける**: 雛形の `login.html` / `signup.html` が inline `<script>`、`error.html` が inline `<style>` + Google Fonts `@import` で、既定を付けると雛形自身が壊れる。`'unsafe-inline'` を付けた CSP は XSS 緩和として機能しない。`frame-ancestors / base-uri / object-src` だけは inline script と無関係に効くので既定に採用し、スクリプト制限は opt-in
6. **セキュリティヘッダを wsgi 雛形 / middleware で付与**: middleware は `Router.handle` 内の Path 一致時しか走らず、wsgi 雛形の `except` 経路や aisaba の既存 wsgi.py (雛形を更新しない限り) には効かない。`Response.__init__` が唯一全応答を通る点
7. **ヘッダ値検証を CR/LF のみに限定**: gunicorn が `[ \t\x21-\x7e\x80-\xff]*` で検査しており、FW 側を緩くすると「テストでは通るが gunicorn で 400」のずれが残る。同じ集合に揃えた
8. **Cookie 値の検証を CR/LF/`;` のみに限定**: 空白・`,`・`"`・`\` はブラウザ側の解析で切られたり別 cookie に見えたりして、黙って壊れる。RFC 6265 cookie-octet に揃え、JSON 等を入れたいアプリには base64url を案内
9. **`TRUSTED_PROXY_COUNT` を雛形に `0` 固定で書き、利用者が手で直す** (初稿の案): `--gateway nginx` を指定した人が config を直し忘れると、アクセスログと auth のレート制限 IP 軸が全部 `127.0.0.1` になり、レート制限が全ユーザー共通バケットに潰れる。bind 既定と同じ「生成既定」の問題なので Leader 裁定 (2026-10-21) で自動導出を採用し §14.6 に置いた
10. **XFF でなく `X-Real-IP` を採用**: nginx 雛形は送っているが Cloudflare → nginx の 2 段では `X-Real-IP` が Cloudflare の IP になり、結局 XFF の右から N 個目が要る。規則を 1 本にした
11. **`REMOTE_ADDR` が信頼プロキシの IP 集合に入っているときだけ XFF を見る (集合方式)**: 集合の管理 (Cloudflare の IP レンジ更新) が運用負荷。bind 127.0.0.1 が前提なら段数方式で足りる
12. **405 を middleware 経由で返す (CORS ヘッダ付き 405)**: `MiddlewareChain` の終端に例外を投げる handler を置く形になり、middleware が例外を握る契約が無い。OPTIONS だけ 204 として middleware を通し、他は例外で雛形に上げる方が単純
13. **HEAD を `Get.methods = {"GET", "HEAD"}` の宣言で実現**: `Path(..., methods={"GET"})` や aisaba の `AppGet` が HEAD 404 のまま残る。Router の規則 1 本にした
14. **Static の大ファイルをイテレータで返す / Range / ETag**: `Response.body: bytes` と `__iter__` の契約変更が要り、`Content-Length` 自動付与・ログの `res.body` 参照にも波及。セキュリティ目的でないので 1.2.0 から外す
15. **`Static` の MIME を allowlist 化 / `.html` `.svg` を `attachment` で返す**: Static の root は開発者管理の資産 (ドキュメント HTML、アイコン SVG) で、ここを縛るとドキュメントサイト (nexom_web) が壊れる。「ユーザアップロード物を Static に置かない」を規約にし、配信側の対策は storage doc の経路に置く
16. **`Request.max_body_size=None` で無制限**: 無制限の口があると雛形コピーで無制限が伝播する。大きい値を明示させる
17. **`escape(None)` を `""` にする**: 現行 `str(values[key])` の `"None"` と差が出ると「表示が消えた」バグの発見が遅れる。従来どおり `"None"` のまま (必要なら呼び出し側で `or ""`)
18. **cookie 解析を `SimpleCookie` のまま `CookieError` だけ捕捉**: 捕捉しても `a=b; bad\x7f=1; c=d` の `c` を落とす問題が残る。自前の寛容解析に置換
19. **`Redirect` の外部拒否を `netloc` のみで判定**: `/\evil.example` をブラウザは `//evil.example` と解釈する。先頭 2 文字の `/` `\` と先頭 `\` を追加判定 (実走で 7 形全て拒否を確認)

---

## 22. 触るファイル表と実装順

| 順 | ファイル | 変更 |
|---|---|---|
| 1 | `core/error.py` | `NexomError.http_status`、P05 / RQ01 / RQ02 / RS01 / RS02 / C02 / OH06 追加、`PathNotFoundError.http_status = 404` |
| 2 | `core/object_html_render.py` | `Markup` / `_AttrSafe(Markup)` (非公開) / `escape` / `safe_url` (unescape → 検査 → 常に escape → `_AttrSafe`) / `json_script`、`_classify_slots` HTML トークナイザ (DATA / TAG_OPEN / IN_TAG / ATTR_VALUE_DQ / _SQ / _UNQUOTED / COMMENT / RAWTEXT)、`ObjectHTML(autoescape)`、`__init__` の OH06 検査 (unsafe 属性 / unquoted / RAWTEXT / IN_TAG・TAG_OPEN / COMMENT)、`render → Markup`、`_apply_slots_strict` のエスケープ + ATTR_VALUE なら Markup も escape (`_AttrSafe` は素通し)、`_set_doc` の予約名スキップ |
| 3 | `app/template.py` | `autoescape` 引き渡し、戻り値 Markup、再 export |
| 4 | `app/response.py` | §6 / §7 / `ErrorResponse(headers, escape, charset)` |
| 5 | `app/cookie.py` | §5 (`Cookie` 全面、`RequestCookies.__init__` をマッピング受けに) |
| 6 | `app/request.py` | §8 / §9 (`client_ip`、`_LimitedStream`、寛容 cookie 解析、`File.size`) |
| 7 | `app/path.py` | §10 / §12 |
| 8 | `app/middleware.py` | §11 |
| 9 | `app/__init__.py` | §16 |
| 10 | `assets/app/config.py` / `wsgi.py` / `pages/default.py` | §14.1〜14.3 (`config.py` は `__g_trusted_proxies__` プレースホルダ) |
| 11 | `buildTools/build.py` | `AppBuildOptions.address` 既定値 + `trusted_proxy_count: int \| None = None` 追加、`create_app` / `create_auth` / `create_config` / `start_project` の 4 辞書に `__g_trusted_proxies__`、導出と負値検査 (§14.5 / §14.6) |
| 11b | `__main__.py:22` `prog="nexom"`、`:53,59,67,76,93` の既定値と help、`--trusted-proxy-count` (start-project / create-app / create-auth / create-config) と `--auth-trusted-proxy-count` (start-project) の追加と `AppBuildOptions(...)` への配線 | §14.5 / §14.6 |
| 12 | `tests/test_router_static_middleware.py` (1 件変更)、新規 `tests/test_http_hardening.py` | §17 / §18 |

実装後の確認: `.venv/bin/python -m pytest -q` が 32 + 新規 N passed / 1 xfailed。`known-failures.md` に追記なし (本 doc で新たな xfail は作らない)。
