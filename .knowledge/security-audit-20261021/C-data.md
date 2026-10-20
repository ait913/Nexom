# Nexom 静的セキュリティ監査 — C: DB・ストレージ・ログ・ビルド/実行・パッケージング

- 対象: `/Users/touri/Documents/Creatives/Developments/Muraki/projects/nexom` 作業ツリー (= pip 1.1.41 sdist と `diff` で同一を確認。git HEAD d3570cd=1.1.40 との差は `parallel_storage.py` の `ImageOps.exif_transpose` 2 行 + pyproject version のみ)。行番号は作業ツリー (1.1.41) 基準
- 手法: 全担当ファイルを全行 Read + scratchpad 上の使い捨て DB/ディレクトリで挙動プローブ (`/private/tmp/claude-501/.../scratchpad/probe-c/`、リポジトリは無変更) + OSV API / GitHub Advisory / PyPI JSON で依存の CVE・対応版・requires-python を照合
- 先行知見 (Codex 2026-10-12) NEX-02 は **再現・確定** (DATA-01)。同種の穴を全メソッドで洗った結果が DATA-02

---

### DATA-01 ParallelStorageDBM.remove の所有者検査が常に True (NEX-02 確定)
- 深刻度: High
- 箇所: `src/nexom/app/parallel_storage.py:356-370`
- 内容: Codex 指摘を該当行で確認。`pid` を受け取るが照合せず、`possession_authoriry = True` の定数で DELETE に進む。
  ```python
  def remove(self, pid: str | None, *, contents_id:str | None = None, public_id:str | None = None) -> None:
      meta = self.getMeta(contents_id=contents_id, public_id=public_id)
      """permissons 実装後、ここで pid の認証をする。"""
      possession_authoriry = True
      if not possession_authoriry : ...
      self.execute("DELETE FROM parallel_storage WHERE contents_id = ?", meta.contents_id)
  ```
  プローブ: userA が COMMITTED したレコードを `remove("userB", public_id=...)` → **例外なく削除成功**。`ParallelStorage.delete` (220-246) は 229-230 行で `fMeta.pid != pid` を検査しているので、そこ経由なら守られるが、DBM を直接使う経路 (`MultiPartUploader._failed` 448-455、アプリから `ParallelStorageDBM` 直接利用) は無防備。`permission_id` カラム (267, 283) は register で保存されるだけで、**全ファイル grep で参照箇所ゼロ** = 共有権限は未実装。
- 到達条件: 雛形 (`start-project`) には ParallelStorage のルートは生成されないので直接到達は無い。アプリが public_id をクライアントから受けて DBM.remove を呼ぶ実装 (aisaba uploader 等) なら、他人の public_id (192bit ランダム、推測不能だが URL 共有で漏れる) を知る利用者がメタデータ削除可能 → ファイル実体は残り、DB だけ消える孤児化 (後続の GC 不能) にもなる。
- 修正案: `if pid is not None and meta.pid != pid: raise PsPermissionError()` を入れ、SQL 側も `DELETE ... WHERE contents_id = ? AND (? IS NULL OR pid = ?)` で二重化。`force` 相当は `pid=None` のまま維持すれば `ParallelStorage.delete(force=True)` の互換は保てる。`permission_id` を使う共有機能は、実装するまで「所有者以外 fail-closed」を明文化。`PsPermissionError` のメッセージ `"Data is over size"` (`core/error.py:379`) はコピペ誤りなので同時に直す。

### DATA-02 ParallelStorage の get/update 系に所有者パラメータ自体が無い (認可は全部アプリ任せ)
- 深刻度: Medium
- 箇所: `src/nexom/app/parallel_storage.py:129-146` (format_psc_public_id), `148-201` (comp_img), `203-208` (update_suffix), `210-214` (update_status), `216-218` (getMeta); DBM 側 `324-354` (status_change / update_public_id / update_types / update_suffix), `374-385` (getMeta)
- 内容: pid を照合しているのは `ParallelStorage.delete` (229)、`MultiPartUploader.parts_upload` (490)、`MultiPartUploader.commit` (519) の 3 箇所のみ。読み出し (`getMeta`, `format_psc_public_id`, `comp_img`) と更新 (`update_suffix`, `update_status`) は public_id だけで通る。プローブ: userA のレコードに対し `ps.update_suffix(public_id, ...)` / `ps.update_status(...)` が pid 無しで成功。`comp_img` はキャッシュ生成 (= ディスク書き込み) を伴うのに所有者もアクセス権も見ない。
- 到達条件: アプリが public_id をリクエストから受けてこれらを呼ぶ場合。public_id は `secrets.token_urlsafe(24)` (25-26) なので列挙は不可能、「URL を知っている人は誰でも」モデル。非公開ファイルを扱うなら枠組みとして不足。
- 修正案: 「public_id を知っている = 読める」を仕様として明文化するか、`getMeta(public_id, *, pid=None)` のように任意の pid 検査を追加して `update_*` では必須にする。既存呼び出しは keyword 追加なら無修正で動く (ただし既定が fail-open のままになるので、`update_*` だけは必須引数にして互換を切るのが安全側)。

### DATA-03 update_suffix の検証が `startswith(".")` のみ → `Path.resolve()` の字句的 `..` 畳み込みで contents_dir 外のパスを返す
- 深刻度: Medium (到達条件次第で High)
- 箇所: `src/nexom/app/parallel_storage.py:203-206` (検証), `145-146` (resolve), `167-169, 199` (comp_img の読み書き)
- 内容: `update_suffix` は `if not suffix.startswith("."): raise` だけ。`"./../../evil"` は通る。`format_psc_public_id` は `(self.contents_dir / f"{cid}__PSC_{suffix}").resolve()` を返し、Python の `realpath` は存在しないコンポーネントでも `..` を字句的に畳む。プローブ: suffix を `./../../evil` にした後 `format_psc_public_id` → `<scratchpad>/probe-c/evil` (contents_dir は `probe-c/ct`) を返した。`comp_img(public_id, None, None, None)` では cache_path == original_path (kwargs 全 None → tail `__PSC_` のみ、143 行の `.webp` 化も効かない) なので、その外側パスを `Image.open` で読み、同じパスへ `im.save(..., format="WEBP")` で**上書き**する。アプリが戻り値を X-Accel-Redirect に載せるなら、任意ファイルの配信にもなる。一方 `MultiPartUploader.commit` (525, 553) の `shutil.move` は POSIX が `cid__PSC_.` を実在ディレクトリとして要求するため ENOENT で失敗する = ここは実害なし (resolve を通る経路だけが危険)。
  付随: `register` (462-463) の `Path(filename).suffix` は `/` を含めないが、空白・改行・NUL は通る (`Path("x.\x00").suffix == ".\x00"` を確認)。NUL 入り suffix は書き込み時 `ValueError` → 500。
- 到達条件: アプリが `update_suffix` にユーザ入力をそのまま渡す + `comp_img` か X-Accel 配信が同じ public_id で呼べる。雛形には無い。aisaba 側で `update_suffix` を外部入力で呼んでいるかは **未確認**。
- 修正案: suffix を `^\.[A-Za-z0-9]{1,16}$` で検証 (register / update_suffix / DBM.update_suffix の 3 箇所)。`format_psc_public_id` は `resolve()` 後に `contents_dir.resolve()` 配下か `is_relative_to` で再検査して外なら `PsArgmentsError`。`format_psc_filename` の kwargs 値も `str` 化前に `[A-Za-z0-9_-]` 制限 (現状 `/` を含む値を渡せば同じ経路)。API 互換: 正規の拡張子は全て通るので実質無影響。

### DATA-04 保存ファイル名の拡張子がユーザ由来のまま、`_detect_file_type` は分類するだけで拒否・補正しない (格納型 XSS の下地)
- 深刻度: High (配信経路が X-Accel-Redirect で拡張子から Content-Type を決める構成の場合)
- 箇所: `src/nexom/app/parallel_storage.py:38-76` (_detect_file_type), `457-463` (register: suffix = `Path(filename).suffix`), `525, 546-553` (commit: 検出結果は types に保存するだけで dest_file は元 suffix)
- 内容: プローブ結果
  - 正当な GIF の末尾に `<script>` を付けたバイト列 + filename `poly2.html` → `Images`、COMMITTED、保存名 `<cid>__PSC_.html`
  - 同バイト列 + `.svg` → `Images`
  - 素の `<svg onload=...>` (Pillow は開けない) → `mimetypes` が `image/svg+xml` → **`Images`** に分類 (SVG はスクリプト実行可能なのに画像扱い)
  - 素の HTML + `.html` → `Documents` (拒否されず格納、suffix `.html`)
  `format_psc_filename` の docstring (79-86) 自体が「X-Accel-Redirect 用」と言っており、nginx は拡張子で Content-Type を決める。この構成では `.html`/`.svg` suffix のファイルがアップロード元と同一オリジンで `text/html` / `image/svg+xml` として配信され、格納型 XSS になる。`Dangerous` 分類 (69-74) も格納・配信を止めない。
- 到達条件: アップロード API を公開するアプリ全般 (Bloom 等、一般ユーザー受け入れで直撃)。`types` を見て配信を制御するコードがアプリ側に無ければそのまま到達。
- 修正案: (1) `Images` は Pillow の `im.format` から suffix を**決め直す** (`JPEG→.jpg`, `PNG→.png`, `GIF→.gif`, `WEBP→.webp`) — ユーザ suffix を捨てる。(2) 拡張子 allowlist を framework 既定で持ち (`.jpg .jpeg .png .gif .webp .pdf .txt ...`)、外は `.bin` に正規化する。(3) SVG は `Images` から外す (`Documents` か `Dangerous`)。(4) 配信側ガイド: `Documents`/`Binary`/`Dangerous` は `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`。互換: 既存レコードの suffix は変えない (新規のみ) か、migration で `types=Images` の suffix を再検出。`FileMeta.filename` は元名 (stem) を保持するので表示名は壊れない。

### DATA-05 comp_img に decompression bomb / リソース上限が無い (メモリ・CPU・ディスク DoS)
- 深刻度: Medium
- 箇所: `src/nexom/app/parallel_storage.py:158-163` (引数検証は <=0 のみ), `181-199` (open → exif_transpose → convert → resize → save method=6), `49-56` (_detect_file_type の verify)
- 内容:
  - Pillow 既定 `MAX_IMAGE_PIXELS = 89,478,485`。公式ドキュメント: 超過は `DecompressionBombWarning` (警告のみ)、**2 倍超で初めて `DecompressionBombError`** — https://pillow.readthedocs.io/en/stable/reference/Image.html 。プローブ: 12000x12000 (1.44 億 px) の 1bit PNG は **17,559 bytes** で、`_detect_file_type` は警告を出しつつ `Images` を返した。`comp_img` はこれを `exif_transpose` (コピー返却) → `convert("RGB")` で約 430MB に展開する。
  - `width`/`height` は上限無し。`comp_img(pid, 20000, 20000, q)` で 1.2GB の出力バッファ。`Image.LANCZOS` + WEBP `method=6` (最遅) で CPU も最大。gunicorn sync worker (雛形既定 4 workers) を数リクエストで塞げる。
  - キャッシュ存在チェックが無い (169 → 199 で毎回再生成)。`(width,height,quality)` の組み合わせごとに `__PSC_height-H_quality-Q_width-W.webp` が無限に増える (ディスク DoS)。
  - `_detect_file_type` は `DecompressionBombError` を `except Exception` で握って非画像に落とすだけで、ファイルは格納される。
- 到達条件: 画像変換 API を公開するアプリ (サムネイル用途は Bloom でまず作られる)。認証後でも 1 ユーザーで到達。
- 修正案: `Image.open` 直後に `im.size[0]*im.size[1] > PIXEL_LIMIT` で拒否 (framework 既定 例 24M px、`warnings.simplefilter("error", Image.DecompressionBombWarning)` も併用)。`width/height` に上限 (例 4096) と「元画像より大きくしない」ルール。`cache_path.exists()` なら即返す。許容サイズをプリセット (例 `{256,512,1024,2048}`) に丸めてキャッシュ爆発を止める。互換: 既存呼び出しで大きな値を渡しているものは例外になる (意図通り)。

### DATA-06 アップロード総量・チャンク番号・放置セッションに上限/GC が無い (ディスク DoS)
- 深刻度: Medium
- 箇所: `src/nexom/app/parallel_storage.py:457-460` (size/total_chunks > 0 のみ), `479-512` (parts_upload), `18` (chunk_max_size = 10MB), `497` (`#self._failed` コメントアウト)
- 内容: プローブ: `register(total_chunks=10**9)` 受理、`parts_upload(count=999999)` で `chunk999999.parts` が書かれた (`count` は `0 <= count < total_chunks` の検査が無い、負数も通る)。1 チャンク ≤10MB だが件数上限・pid 別クォータ・`size` との整合検査 (`total_chunks * chunk_max_size >= size`、累積 > size で拒否) が無い。sha256 不一致でも `ERROR` に遷移するだけで作業ディレクトリは残る (497 行で `_failed` が無効化)。`INIT`/`UPLOADING`/`ERROR` のまま放置されたセッションを掃除する API / TTL が無い。`count` の型も検査されず、str を渡せば `f"chunk{count}.parts"` に混入 (POSIX では `chunk..` が実在しないため traversal には至らない)。
- 到達条件: アップロード API を持つアプリの認証ユーザー 1 人。
- 修正案: `register` で `size <= MAX_UPLOAD_SIZE` (framework 既定を置く、例 100MB) と `ceil(size/chunk_max_size) == total_chunks` を要求。`parts_upload` で `isinstance(count,int) and 0 <= count < total_chunks`、既存チャンクの上書き可否を決める。`MultiPartUploader.gc(older_than=...)` を追加して作業ディレクトリと `INIT/UPLOADING/ERROR` レコードを掃除。互換: 既存クライアントが total_chunks を切り上げで送っていれば影響なし。

### DATA-07 全アップロードを Pillow で開く + `Pillow>=10.0` の下限が既知 CVE を許容
- 深刻度: High (依存下限) / Medium (攻撃面)
- 箇所: `pyproject.toml:17`、`src/nexom/app/parallel_storage.py:49-56, 181-183, 199`
- 内容: `_detect_file_type` は宣言型に関係なく**全コミット済ファイル**を `Image.open` + `verify()` に通す = Pillow の全プラグイン (PSD/EPS/FITS/PDF/TGA/JPEG2000/GD...) がアップロード経由で到達する。`comp_img` はさらにフルデコード + WEBP エンコード。下限 10.0 で入り得る版に、この経路で踏める既知脆弱性が多数 (OSV `api.osv.dev/v1/query` PyPI/Pillow 照合):
  - 10.0.0 wheel 同梱 libwebp の **CVE-2023-4863** (BuildHuffmanTable OOB write、実際に悪用された) — 修正 10.0.1。nexom は WEBP を decode/encode 両方する — https://github.com/advisories/GHSA-j7hp-h8jx-5ppr , https://osv.dev/vulnerability/PYSEC-2023-175
  - CVE-2023-50447 `ImageMath.eval` ACE — 修正 10.2.0 (nexom 未使用、防御的) — https://github.com/advisories/GHSA-3f63-hfp8-52jq
  - CVE-2024-28219 `_imagingcms` strcpy overflow — 修正 10.3.0 (nexom 未使用) — https://github.com/advisories/GHSA-44wm-f244-xhp3
  - CVE-2025-48379 BCn エンコード overflow — 修正 11.3.0 (DDS 書き出し、nexom は WEBP のみ書くので非到達) — https://github.com/advisories/GHSA-xg8h-j46f-w952
  - **到達する decode 系 (2026)**: CVE-2026-25990 PSD OOB write (12.1.1)、CVE-2026-40192 FITS gzip bomb / CVE-2026-42310 PDF trailer 無限ループ / CVE-2026-42311 PSD tile OOB (12.2.0)、CVE-2026-55380 GD の bomb check 欠落 / CVE-2026-59203 EPS 無限ループ / CVE-2026-59204 JPEG2000 DoS / CVE-2026-59200 PDF bomb (12.3.0)、CVE-2026-112403 **JPEG decode heap overflow** / CVE-2026-112400 GIF seek DoS / CVE-2026-112404 TIFF OOB read (13.0.0) — 各 https://github.com/advisories/<GHSA> は OSV 出力に対応 (例 GHSA-cfh3-3jmp-rvhc, GHSA-whj4-6x5x-4v2j, GHSA-r73j-pqj5-w3x7, GHSA-phj9-mv4w-65pm, GHSA-pg7v-jwj7-p798, GHSA-vjc4-5qp5-m44j, GHSA-8g5g-8vmr-9782, GHSA-65qm-jvmh-6pqg, GHSA-c6hw-5grf-ff96)
  requires-python (PyPI JSON): Pillow 12.3.0 = `>=3.10`、**13.0.0 = `>=3.11`**。nexom は `requires-python >=3.10`。
- 到達条件: アップロード API を持つアプリ全般。依存版は利用側 venv の `pip install -U nexom` 時点で決まる (aisaba 各サービスの実インストール版は未確認)。
- 修正案: `Pillow>=12.3.0` に上げる (3.10 を維持する間の最大)。3.10 を切れるなら `>=13.0.0` (JPEG decode の heap overflow を塞ぐ)。コード側: `Image.open(path, formats=["JPEG","PNG","GIF","WEBP"])` で開けるフォーマットを allowlist 化し、宣言 suffix が画像でないファイルは Pillow に通さない。互換: 利用側 venv のアップグレードのみ。

### DATA-08 `gunicorn>=21.2` / `multipart>=1.3.0` の下限が既知 CVE 版を許容
- 深刻度: High (gunicorn) / Medium (multipart)
- 箇所: `pyproject.toml:15-16`、`src/nexom/app/request.py:217, 242` (multipart の到達経路)
- 内容:
  - gunicorn 21.2.0 は **CVE-2024-1135** (Transfer-Encoding 検証不備による request smuggling、endpoint 制限バイパス) と **CVE-2024-6827** (TE.CL smuggling) に該当。GitHub Advisory は双方「affected < 22.0.0 / patched 22.0.0」 — https://github.com/advisories/GHSA-w3h3-4rj7-4ph4 , https://github.com/advisories/GHSA-hc5x-x2vx-497g 。nginx 前段構成 (雛形 gateway) はまさに smuggling が効く形。最新 26.2.0 (2026-08-24、requires-python >=3.10)。
  - multipart 1.3.0 は **CVE-2026-28356** (`parse_options_header()` の ReDoS) 該当、patched 1.3.1 / 1.2.2 — https://github.com/advisories/GHSA-p2m9-wcp5-6qw3 。`Request.files()` → `MultipartParser` がパートヘッダ (Content-Disposition) を同関数で解析するので、multipart ボディを送れる匿名クライアントから到達。最新 2.0.1 (2026-09-25、requires-python >=3.10)。venv には 2.0.1 が入っておりテストは通っているが、担当 2 ファイルに multipart のテストは無く、**2.x での `MultipartParser(stream, boundary)` API 互換は本調査では未検証**。
  - 付随 (Info): `request.py:219-221` のエラー文は「python-multipart を入れろ」だが、依存は defnull の `multipart`。python-multipart を入れると別 API の `multipart` モジュールになり実行時に壊れる (OSV にも python-multipart の別 CVE 群が出て混同しやすい)。
- 到達条件: 利用側が下限ギリギリの古い版を持つ場合 (pip は最新を取るので新規環境は概ね安全。長期稼働 venv が危険)。
- 修正案: `gunicorn>=22.0.0` (推奨 `>=23.0.0`)、`multipart>=1.3.1`、`Pillow>=12.3.0`。エラー文を `pip install multipart` に修正。aisaba 各サービスの venv で `pip list | grep -i -E "gunicorn|pillow|multipart"` を棚卸しする運用手順を CLAUDE.md に足す。

### DATA-09 auth 雛形の `MASTER_PASSWORD` が全インストール共通の固定文字列
- 深刻度: High
- 箇所: `src/nexom/assets/auth/config.py:19`、`src/nexom/app/auth.py:185, 619`、`tests/test_templates_and_buildtools.py:43`
- 内容: 雛形は `MASTER_PASSWORD: str = "NexomWebFramework"` を**生成時に置換せず**書き出す (build.py の `_replace_many` 辞書 250-262 / 404-416 に該当プレースホルダが無い)。`AuthService.__init__` の既定値も同じ文字列 (auth.py:185)。用途は `master_users_deactivate` (auth.py:600-622) の第 2 要素で、`if master_password != self.master_password` と**非定数時間比較**。テストが固定値のまま残ることを assert している (test_templates_and_buildtools.py:43) ので、直すとテストを直す必要がある。Codex 報告の「既定の管理操作用補助パスワード」はこれ。
- 到達条件: master のログインセッション token が必要 (Codex と同判断)。ただし master セッションが XSS (AIS-01) 等で奪われた瞬間に第 2 要素が無意味になる。公開リポジトリに載っているので秘密として機能していない。
- 修正案: build.py で `secrets.token_urlsafe(32)` を生成し `__master_password__` プレースホルダで config に書く (login password と同様に stdout にも出す)。`AuthService.__init__` の既定値を削除して必須引数化、比較は `hmac.compare_digest`。既存 aisaba の config.py は手動で値を差し替える移行手順を設計 doc に明記。テスト 43 行目を「固定値でないこと」に反転。

### DATA-10 雛形の既定 bind が `0.0.0.0` + `_ip()` が X-Forwarded-For を無条件に信頼
- 深刻度: Medium
- 箇所: `src/nexom/buildTools/build.py:16`、`src/nexom/__main__.py:53, 59, 67, 76, 93`、`src/nexom/assets/gateway/nginx_app.conf:19`、`src/nexom/assets/app/wsgi.py:26-30`、`src/nexom/assets/auth/wsgi.py:44-48`
- 内容: `AppBuildOptions.address` 既定 `"0.0.0.0"`。`start-project --address`、`create-app`、`create-auth`、`create-config` も全部 `0.0.0.0` 既定。gateway 雛形は `proxy_pass http://127.0.0.1:__APP_PORT__` なので、設計上はローカル専用のはずの gunicorn が全インタフェースに露出し、nginx の制御 (将来の rate limit / WAF / TLS) を直接 :8080 で迂回できる。`start-project --auth-address` だけ既定 `127.0.0.1` だが help 文は「default: 0.0.0.0」で不一致 (`__main__.py:59`)。両 wsgi 雛形の `_ip()` は `HTTP_X_FORWARDED_FOR` の先頭を無条件に採用 → 直接到達した攻撃者は任意 IP をアクセスログ・auth ログ・IP ベース制御に注入できる。gunicorn 側の `forwarded_allow_ips` (既定 127.0.0.1) は gunicorn が作る `REMOTE_ADDR` 等にしか効かず、アプリが生ヘッダを読むこの実装には無関係。gunicorn.conf 雛形 (app/auth 共通) は `bind/workers/reload` のみで `forwarded_allow_ips`・`proxy_protocol`・`limit_request_*`・`timeout` の明示なし (gunicorn 既定値に依存、`reload` 既定 False は良い)。
- 到達条件: 雛形そのままで到達。ホストのファイアウォール / Docker のポート公開設定に依存。
- 修正案: 既定を `127.0.0.1` に反転し、コンテナ等で必要なら `--address 0.0.0.0` を明示 (opt-in)。`_ip()` は `REMOTE_ADDR` が信頼プロキシ (config に `TRUSTED_PROXIES` を生成) のときだけ XFF を見る。gunicorn.conf 雛形に `forwarded_allow_ips` と `limit_request_line/fields` を明示。help 文修正。互換: 既存生成物は無影響 (新規生成のみ)。

### DATA-11 ログインジェクション (改行) — パスとユーザ ID が無加工で書かれる
- 深刻度: Low
- 箇所: `src/nexom/core/log.py:67-75` (AppLogger._write), `115-121` (AuthLogger._write)、`src/nexom/core/error.py:44`、`src/nexom/assets/app/wsgi.py:47, 60`
- 内容: gunicorn は `PATH_INFO` を percent-decode する (`gunicorn/http/wsgi.py:279` `util.unquote_to_wsgi_str`) ので `GET /%0a[2026-...]%20[INFO]%20fake` は `req.path` に生改行で入る。雛形は `logger.warn(str(PathNotFoundError))` (メッセージにパスを埋める、error.py:44) と access 行にパスを書き、`_write` は `msg` を一切エスケープしない。`AuthLogger` の `subject=user_id` も同様 (login_failed は攻撃者が user_id を自由に選べる)。UA は HTTP ヘッダなので生改行は入らない。
- 到達条件: 雛形そのまま、匿名で到達。影響は監査ログの偽装・ログ解析ツールの誤動作。
- 修正案: `_write` で `msg.replace("\r", "\\r").replace("\n", "\\n")` (traceback を書く `error()` は除外するか行頭にプレフィクスを付ける)、または 1 行 JSON (json.dumps) 形式に変える。互換: ログ形式の変更のみ。

### DATA-12 ログ運用: ローテーション無し・匿名 404 で warning.log が無限増加
- 深刻度: Low
- 箇所: `src/nexom/core/log.py:71-75, 116-121`、`src/nexom/assets/app/wsgi.py:46-47`
- 内容: 毎回 `open("a")` で追記、サイズ上限・ローテーション無し。雛形は全 404 を `warning.log` に書くので、未認証スキャンだけで `data/log/<app>/warning.log` と `access.log` を無限に伸ばせる (ディスク DoS)。パスはプロジェクト直下 `data/log/` (config 雛形 22-26) で固定、権限は umask 依存。`datetime.utcnow()` は 3.12 で deprecated。秘密のログ出力は無し (AuthLogger は token を 8 文字に切る 110 行、良い)。
- 到達条件: 雛形そのまま、匿名で到達 (時間はかかる)。
- 修正案: stdlib `logging` + `RotatingFileHandler(maxBytes, backupCount)` に寄せるか、README に logrotate 設定を同梱。404 は access ログに集約し warning に書かない。`datetime.now(timezone.utc)`。

### DATA-13 ファイル権限は umask 依存 (明示指定なし)
- 深刻度: Info
- 箇所: `src/nexom/app/parallel_storage.py:472-473, 493-494, 529, 553`、`src/nexom/app/db.py:63`
- 内容: チャンク・meta.json・完成ファイル・SQLite DB・ログの全てが既定 umask で作られる (プローブ: 0644)。`grep -rn "umask\|chmod" src/nexom` ヒットなし。同一ホストの他ユーザーから読める。nginx 配信用には読み取りが必要なので contents_dir は 0644 が妥当だが、DB と作業ディレクトリは 0600/0700 が望ましい。
- 修正案: `MultiPartUploader` の working_root と DB は `os.open(..., 0o600)` / `mkdir(mode=0o700)` を使う。運用側は systemd unit で `UMask=0027`。

### DATA-14 db.py: SQL は全てプレースホルダ、識別子結合なし (確認済・問題なし)
- 深刻度: Info
- 箇所: `src/nexom/app/db.py:100-137`、`src/nexom/app/parallel_storage.py` 全 SQL、`src/nexom/app/auth.py` の SQL 文字列 (grep)
- 内容: `execute(sql, *args)` → `cursor.execute(sql, tuple(args))`、`execute_many` → `(sql, values)` の列。f-string / `.format` / `+` でテーブル名・カラム名・ORDER BY を組む箇所は db.py・parallel_storage.py・auth.py に無し (auth.py の `+` は URL 連結のみ、`ORDER BY g.group_id` / `ORDER BY user_id` は固定リテラル)。`status`/`types` は Literal 検査 (22-23, 110-114) もある。
  非セキュリティの注意点: `execute` は `sql.lstrip().upper().startswith("SELECT")` のときだけ fetchall するので `WITH ... SELECT` / `... RETURNING` / `PRAGMA` は結果が捨てられる。`connect(db_file)` は `check_same_thread=True` 既定で gunicorn sync worker (プロセス) なら問題なし、threads worker にすると落ちる。`DBOperationalError(str(e))` は sqlite の生メッセージを運ぶが、雛形 auth の 500 応答は `e.code` のみ返すので漏れない。
- 修正案: なし (現状維持)。将来 ORDER BY を動的化する場合は allowlist で。

### DATA-15 run.py / __main__.py: shell 不使用・引数は配列・パスは resolve 済 (確認済・問題なし)
- 深刻度: Info
- 箇所: `src/nexom/buildTools/run.py:34-55, 65-68, 110-111, 129-136`、`src/nexom/__main__.py:98-198`、`src/nexom/buildTools/build.py:22, 71-73`
- 内容: `subprocess.Popen([gunicorn, "<app>.wsgi:app", "--config", conf], cwd=root, env=env, start_new_session=True)` — `shell=True` 無し、引数は list。アプリ名はディレクトリ走査結果 (`iterdir` で `wsgi.py` と `gunicorn.conf.py` を両方持つ直下ディレクトリ) に限定され、`run <name>` は検出済 dict に無ければ `RunError`。`PYTHONPATH` に project root を先頭追加 (root 直下に `json/` 等のディレクトリがあれば標準ライブラリを影で隠す — 運用者制御下なので Info)。環境変数は全継承 (secrets を env で渡す運用なら gunicorn 子プロセスに引き継がれるのは意図通り)。`gunicorn` は `shutil.which` (PATH 依存)。`--root/--out` は `expanduser().resolve()`、`app_name` は `^[A-Za-z0-9_]+$` (build.py:22) で `..`/`/` を拒否。`create_auth` は名前固定。CLI `prog="naxom"` と run.py の文言 "naxom run" は typo (Info)。
- 修正案: なし。

### DATA-16 `ImageOps.exif_transpose` 追加 (1.1.41) の新規リスク
- 深刻度: Info
- 箇所: `src/nexom/app/parallel_storage.py:182-183`
- 内容: 公式仕様 (https://pillow.readthedocs.io/en/stable/reference/ImageOps.html): `in_place=False` 既定では**常に新しい Image (コピー) を返す** → `convert("RGB")` 前にフルデコード済コピーがもう 1 枚メモリに乗る (DATA-05 のメモリ係数が増える)。EXIF/TIFF IFD を解析するので壊れた EXIF で `struct.error` / `TypeError` が上がった履歴がある (Pillow #7458 「Catch struct.error from truncated EXIF」2023-10 merge、#7839 `IFDRational` TypeError 10.2.0) — https://github.com/python-pillow/Pillow/pull/7458 , https://github.com/python-pillow/Pillow/issues/7839 。例外は雛形の 500 ハンドラに落ちるだけで新しい書き込み経路は無い。**どの Pillow 版で #7458 が収録されたかは本調査で未確認** (DATA-07 の下限引き上げで解消する見込み)。
- 修正案: `exif_transpose(im, in_place=True)` でコピーを避け、`try/except Exception: pass` で向き補正失敗を非致命にする。

---

## チェックリスト結果表

| # | 観点 | 結果 | 根拠 / 所見 |
|---|---|---|---|
| 1 | SQL インジェクション | 確認済・問題なし | DATA-14。db.py / parallel_storage.py / auth.py の SQL は全てプレースホルダ、識別子・ORDER BY は固定リテラル |
| 2 | 認可 (ParallelStorageDBM 全メソッド) | **該当あり** | DATA-01 (remove fail-open、プローブで再現) / DATA-02 (get/update 系に pid 引数なし、permission_id 未実装) |
| 3 | ファイル保存 (パス・衝突・権限) | **該当あり** | DATA-03 (update_suffix → resolve 外出し) / DATA-13 (umask 依存)。衝突: contents_id/public_id は 192bit ランダムで実質なし、commit は `dest_file.unlink()` で上書き (549-551) |
| 4 | 画像処理 (Pillow) | **該当あり** | DATA-05 (bomb 警告のみ・width/height 上限なし・キャッシュ爆発) / DATA-04 (SVG を Images、ポリグロット) / DATA-16 (exif_transpose) / DATA-07 (全アップロードを Pillow に通す) |
| 5 | アップロード上限 (サイズ/件数/MIME) | **該当あり** | DATA-06 (chunk 10MB のみ、総量・件数・count 範囲・GC なし) / DATA-04 (MIME allowlist なし)。HTTP ボディは request.py `DEFAULT_MAX_BODY_SIZE` 10MB があるが `files()` の multipart ストリームには適用されない (242 行、別担当領域として申し送り) |
| 6 | ログ | **該当あり** | DATA-11 (改行注入) / DATA-12 (ローテなし・404 で増加)。秘密出力は無し (token 8 文字切り) |
| 7 | ビルド雛形の既定 | **該当あり** | DATA-09 (固定 MASTER_PASSWORD) / DATA-10 (bind 0.0.0.0、XFF 無条件信頼、gunicorn.conf に proxy 系未指定)。login password は `secrets.token_urlsafe(14)` で生成され config には書かれない (良い)。`reload` 既定 False、`debug` フラグは存在しない。生成物に秘密をコミットさせる構造は MASTER_PASSWORD 以外なし |
| 8 | run.py | 確認済・問題なし | DATA-15 |
| 9 | 依存の下限 CVE | **該当あり** | DATA-07 (Pillow) / DATA-08 (gunicorn CVE-2024-1135 / CVE-2024-6827 → 22.0.0、multipart CVE-2026-28356 → 1.3.1) |
| 10 | __main__.py (パス注入・cwd 依存) | 確認済・問題なし | DATA-15。`--root/--out` 既定 "." は cwd 依存だが CLI の性質上妥当、resolve 済 |

## 設計への含意 (優先順)

1. ★ **依存下限の引き上げは今日できる最小コストの修正**: `gunicorn>=22.0.0` (推奨 >=23)、`multipart>=1.3.1`、`Pillow>=12.3.0` (3.10 維持の上限。3.11 に上げられるなら 13.0.0)。合わせて aisaba 各 venv の実インストール版の棚卸し (DATA-07/08)
2. ★ **ParallelStorage を「所有者 fail-closed」に書き換える**: remove の pid 照合 (DATA-01)、update 系の pid 必須化 (DATA-02)、suffix の正規表現検証 + resolve 後の root 再検査 (DATA-03)。Bloom 投入前に必須
3. ★ **保存拡張子をコンテンツ由来に決め直し、SVG/HTML を画像扱いしない** (DATA-04)。配信側 (X-Accel) の Content-Type 決定が拡張子依存なので、ここを framework 既定で安全側に倒さないと格納型 XSS が各アプリに再発する
4. **画像変換とアップロードの上限を framework 既定で持つ** (DATA-05/06): pixel 上限・width/height 上限・キャッシュ再利用・size/total_chunks/count 整合・GC API。アプリ任せにすると Bloom で確実に抜ける
5. **auth 雛形の MASTER_PASSWORD を生成値に** + compare_digest (DATA-09)。既存 aisaba config の差し替え手順を設計 doc に
6. **雛形既定を 127.0.0.1 に反転し、`_ip()` を信頼プロキシ条件付きに** (DATA-10)。コンテナ化 (Coolify 移行構想) の際に 0.0.0.0 が必要になるので、そのときの opt-in フラグも同時に設計
7. ログは JSON 1 行 + ローテーション (DATA-11/12)。優先度は低いが監査ログの信頼性に直結
