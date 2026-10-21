# Nexom 1.2.0 — ParallelStorage / ログ / 依存・パッケージングの安全既定化 (storage-deps-hardening)

作成: 2026-10-21 / Architect。並列 3 doc (auth-hardening / http-hardening / 本 doc) の 1 本。根拠: `.knowledge/security-audit-20261021/C-data.md` (DATA-01〜16)、外部診断 NEX-02、`Muraki/knowledge/library/python-web-deps-cve-floors-2026.md`。

## 0. スコープ境界

| 区分 | ファイル |
|---|---|
| **本 doc が変更する** | `src/nexom/app/parallel_storage.py`, `src/nexom/app/db.py`, `src/nexom/core/log.py`, `pyproject.toml`, `src/nexom/__init__.py`, `src/nexom/buildTools/run.py`, `tests/test_parallel_storage.py` (全面書き換え), `tests/test_version_and_log.py` (新規) |
| **共有ファイル (節を分けて追記)** | `src/nexom/core/error.py` — 本 doc は `# ParallelStorage` 節 (PS01〜PS16) のみ触る。auth / http doc は自分の節 (A* / H*) を触る。同一ファイルの別節なので merge 競合は textual のみ |
| **触らない** | `app/request.py`, `app/response.py`, `app/path.py`, `app/middleware.py`, `app/cookie.py`, `core/object_html_render.py`, `assets/**`, `buildTools/build.py`, `__main__.py` (http doc) / `app/auth.py`, `app/user.py`, `templates/auth.py` (auth doc) / `tests/test_templates_and_buildtools.py` (buildtools 部分は本 doc 所有だが **変更なし**。43 行目の `MASTER_PASSWORD` 固定値 assert は DATA-09 を扱う doc が反転する) |

本 doc が他 doc に出す要求は §9。

## 1. 目的

一般ユーザー受け入れ (Bloom) の前に、Nexom の保存層 (ParallelStorage / MultiPartUploader) を「所有者 fail-closed・コンテンツ由来の保存名・資源上限あり」の既定に倒し、ログの改行注入とディスク無限増加を塞ぎ、依存下限を既知 CVE の修正版に上げる。互換性は壊してよい (1.2.0、移行ガイド §8 付き)。

## 2. Leader 横断方針との対応

| # | 方針 | 採否 | 本 doc の決定 |
|---|---|---|---|
| 1 | 安全既定 / 1.2.0 / version 単一ソース | 採 | pyproject を単一ソース、`__version__` は `importlib.metadata` (§3.2) |
| 2 | 依存下限、py3.10 維持、multipart 上限 | 採 | `gunicorn>=22.0.0`, `multipart>=1.3.1,<3`, `Pillow>=12.3.0` (§3.1)。エラー文修正は request.py 所有の http doc へ要求 (§9-1) |
| 3 | 認可 fail-closed、pid 必須、permission_id、suffix 検証 | **一部変更** | 変更系は `pid: str` 必須。参照系 (`getMeta` / `format_psc_public_id` / `comp_img`) は `pid: str \| None` を **必須引数** にし、`None` を明示した時だけ capability モデル (public_id を知っている = 読める) で通す。理由: aisaba の user icon は閲覧者 ≠ 所有者で配信される (`uc.aisaba.net`、§8-3)。所有者以外に読ませない用途は pid を渡せば検査される。`permission_id` は **API から削除** (参照ゼロ、列は残置) |
| 4 | 保存拡張子はコンテンツ由来 | 採 | `classify_file` (§6 PS-C)。Images は Pillow `im.format` 由来 4 形式のみ、他は allowlist 外を `.bin` に正規化 |
| 5 | 画像変換・アップロード上限の既定化 | 採 (総量クォータは不採用) | §6 PS-D / PS-E。pid 別の **同時進行セッション数** で未完了分のディスクを束ね、コミット済み総量のクォータはアプリ側 (§10-6) |
| 6 | xfail 解消 | 採 | 原因は `PsFileTypesError()` の `TypeError` (§6 PS-D-1 現状)。例外シグネチャを直し、テストは commit 経由の実画像で書き直す (§7) |
| 7 | ログ: `sanitize_log_field`, ローテーション, `utcnow` | 採 | §6 LOG |
| 8 | パーミッション既定 | **一部採用** | DB 0600、作業ディレクトリ 0700 / チャンク 0600。**contents とログは umask 依存のまま** (nginx が alias で直読みしており 0640 にすると配信が壊れる、§10-8) |
| 9 | `exif_transpose` の例外 | 採 | `in_place=True` + `except Exception: pass` (向き補正失敗は非致命) |

## 3. 依存・パッケージング

### 3.1 pyproject.toml

```toml
[project]
version = "1.2.0"
requires-python = ">=3.10"
dependencies = [
  "gunicorn>=22.0.0",
  "multipart>=1.3.1,<3",
  "Pillow>=12.3.0",
]
[project.urls]
Homepage = "https://nexom.aisaba.net"
```

- `gunicorn>=22.0.0`: CVE-2024-1135 / CVE-2024-6827 の修正版 (GHSA は双方 patched 22.0.0)。
- `multipart>=1.3.1,<3`: 1.3.1 が CVE-2026-28356 修正。**2.0.1 との互換は確認済**: `request.py` が使う `MultipartParser(stream, boundary)`・部品の `.name / .filename / .file / .raw / .value` は 1.3.1 wheel と 2.0.1 (venv) の両方に同名で存在 (公開メソッド一覧の diff は内部 `_cached_property` → `cached_property` と `MultipartSegment` の内部メソッド差のみ)。2.0 の破壊的変更は py3.8/3.9 廃止・`PushMultipartParser` が `bytes` を返す・boundary が本文に現れたら fatal の 3 点で、いずれも request.py の経路に影響しない。3.x は未検証なので `<3` で止める。**付随 (http doc 宛)**: 部品の `.headers` は 1.3.1 でも 2.0.1 でも `Headers` 型 (dict でない) なので `request.py:258` の `isinstance(headers, dict)` は常に False → `content_type` が常に None。`p.content_type` 属性 (両版に存在) を使うべき (§9-1)。
- `Pillow>=12.3.0`: Python 3.10 で入る最後の系列 (13.0.0 は `>=3.11`)。12.3.0 までで DATA-07 列挙の decode 系 CVE のうち 13.0.0 修正分 (JPEG heap overflow 等) 以外を塞ぐ。13.0.0 を下限にしない理由: `requires-python >=3.10` を維持する裁定。3.11 以上の環境では pip が 13.x を取るので、aisaba 側は venv の Python が 3.11 以上なら自動で 13.x になる。**コード側の緩和**: `Image.open(..., formats=["JPEG","PNG","GIF","WEBP"])` で開けるプラグインを 4 つに絞り、PSD / EPS / FITS / PDF / JPEG2000 / TIFF / GIF-seek 系の CVE 経路を到達不能にする (§6 PS-C-1)。

### 3.2 `__version__` の単一ソース (auth / http doc はこの節番号 §3.2 を参照する。版の正典は `pyproject.toml` の `version` のみで、他 doc は version 文字列をどこにも書かない)

`src/nexom/__init__.py` の `__version__ = "1.1.0"` を削除し、以下に置換:

```python
from importlib.metadata import PackageNotFoundError, version as _pkg_version
try:
    __version__ = _pkg_version("nexom")
except PackageNotFoundError:  # 未インストールのソースツリーから import した時
    __version__ = "0.0.0+unknown"
```

- `__all__` の `"__version__"` は維持。
- 注意 (CLAUDE.md「PyPI へリリース」手順に追記する): editable install はメタデータを install 時点で焼くので、`pyproject.toml` の version を上げたら `.venv/bin/pip install -e .` を再実行しないと `__version__` が旧値を返す。

### 3.3 buildTools/run.py

セキュリティ上の変更なし (DATA-15)。文言 typo のみ: `RunError` docstring と `run_project` 冒頭の `"naxom run ..."` 2 箇所を `nexom` に置換。`__main__.py:prog="naxom"` は http doc 所有なので §9-4 で申し送り。

## 4. データモデル

### 4.1 テーブル `parallel_storage` (1.2.0)

```sql
CREATE TABLE IF NOT EXISTS parallel_storage (
    contents_id     TEXT PRIMARY KEY,
    public_id       TEXT UNIQUE,
    types           TEXT DEFAULT 'Binary',
    size            INT  NOT NULL,
    pid             TEXT NOT NULL,
    filename        TEXT NOT NULL,          -- 元ファイル名の stem (拡張子なし)。表示時はアプリがエスケープ
    suffix          TEXT NOT NULL,          -- 保存名の拡張子 (commit 後はコンテンツ由来)
    original_suffix TEXT DEFAULT NULL,      -- 新規: クライアント宣言の拡張子 (lowercase、SUFFIX_RE 不一致なら NULL)
    status          TEXT DEFAULT 'INIT',
    permission_id   TEXT DEFAULT NULL,      -- 死に列。1.2.0 で書き込み停止 (常に NULL)。削除は次のメジャー
    creation_date   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_access     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS parallel_storage_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);   -- ('schema_version', '1')
```

`PRAGMA user_version` を使わない理由: DB ファイルを他の DatabaseManager と共有しているアプリがあると値を取り合う。専用テーブルなら共有でも安全。

### 4.2 既存 SQLite を 1.2.0 で開いた時の移行 (`ParallelStorageDBM._init`)

冪等。コンストラクタのたびに走る。

1. `CREATE TABLE IF NOT EXISTS parallel_storage (...)` (4.1 の定義、新規 DB は列が揃った状態で作られる)
2. `CREATE TABLE IF NOT EXISTS parallel_storage_meta (...)`
3. `v = int(SELECT value FROM parallel_storage_meta WHERE key='schema_version')`、行なしは 0
4. `v < 1` のとき:
   - `PRAGMA table_info(parallel_storage)` に `original_suffix` が無ければ `ALTER TABLE parallel_storage ADD COLUMN original_suffix TEXT DEFAULT NULL`
   - `UPDATE parallel_storage SET types='Binary' WHERE types='Images' AND lower(suffix) NOT IN ('.jpg','.jpeg','.png','.gif','.webp')` — 旧版で `Images` に分類された SVG / HTML / ポリグロットを画像扱いから外す (fail-closed)。ファイルは改名しない (§11-1)
   - `INSERT OR REPLACE INTO parallel_storage_meta VALUES ('schema_version','1')`
5. commit

`PRAGMA table_info` の結果を受けるため、`DatabaseManager.execute` の行返却条件を `cursor.description is not None` に変える (§5.5)。

### 4.3 型定義 (parallel_storage.py)

```python
FileTypes  = Literal["Documents", "Images", "Binary", "Media", "Dangerous"]      # 不変
FileStatus = Literal["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED", "ERROR"]
# _FileStatusTypesCheck の許容リストに "ERROR" を追加 (現状: 欠けているため status_change(cid,"ERROR") が PsStatusTypesError)

@dataclass(frozen=True)
class FileMeta:
    contents_id: str
    public_id: str
    types: str
    size: int
    pid: str
    filename: str
    suffix: str
    original_suffix: str | None     # 新規
    status: str
    creation_date: str
    last_access: str
    # permission_id は削除
    def isTypes(self, types: FileTypes) -> bool   # 不変 (無効値は PsFileTypesError(types))

@dataclass(frozen=True)
class Classification:
    types: FileTypes
    suffix: str                 # 保存に使う拡張子 (".jpg" 等 / ".bin")
    image_format: str | None    # Pillow の im.format ("JPEG" 等)、画像でなければ None
    width: int | None
    height: int | None

@dataclass(frozen=True)
class GcReport:
    removed_rows: int
    removed_dirs: int

@dataclass(frozen=True)
class UploadMeta:               # 不変 (public_id, total_chunks, sha256)
```

### 4.4 定数 (parallel_storage.py モジュール先頭、全て公開名)

```python
DEFAULT_CHUNK_MAX_SIZE            = 10 * 1024 * 1024    # 既存 chunk_max_size と同値。chunk_max_size = DEFAULT_CHUNK_MAX_SIZE を別名で残す
DEFAULT_MIN_CHUNK_SIZE            = 256 * 1024
DEFAULT_MAX_UPLOAD_SIZE           = 100 * 1024 * 1024
DEFAULT_MAX_ACTIVE_UPLOADS_PER_PID = 8
DEFAULT_MAX_IMAGE_PIXELS          = 50_000_000          # 48 MP (8064x6048 = 48,771,072) を通す。Pillow 既定 89M は警告のみなので使わない
IMAGE_SIZE_STEPS    = (64, 128, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096)
IMAGE_QUALITY_STEPS = (50, 70, 85, 95)
DEFAULT_IMAGE_QUALITY = 70
IMAGE_FORMATS: dict[str, str] = {"JPEG": ".jpg", "PNG": ".png", "GIF": ".gif", "WEBP": ".webp"}
IMAGE_SUFFIXES    = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp"})
DOCUMENT_SUFFIXES = frozenset({".pdf", ".txt", ".md", ".csv", ".json"})
MEDIA_SUFFIXES    = frozenset({".mp3", ".m4a", ".wav", ".ogg", ".mp4", ".mov", ".webm"})
BINARY_SUFFIXES   = frozenset({".zip", ".bin"})
DANGEROUS_SUFFIXES = frozenset({".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".msi", ".app", ".dylib", ".so", ".jar"})
FALLBACK_SUFFIX = ".bin"
SUFFIX_RE = re.compile(r"^\.[A-Za-z0-9]{1,16}$")
ID_RE     = re.compile(r"^[A-Za-z0-9_-]{16,64}$")       # public_id (token_urlsafe(24) = 32 文字)。パスに載る前に必ず通す
CID_RE    = re.compile(r"^[A-Za-z0-9_-]{1,64}$")        # format_psc_filename の contents_id (テストの "cid" を許す)
KWARG_RE  = re.compile(r"^[A-Za-z0-9_-]{1,32}$")        # PSC ファイル名の kwargs キーと値
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IMAGE_CONTENT_TYPES = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp"}
```

## 5. API / 関数シグネチャ (変更前 → 後)

凡例: **破壊** = 既存呼び出しが動かなくなる (§8 の移行対象)。pid の位置は既存の `delete(pid, public_id)` / `parts_upload(pid, ...)` / `commit(pid, ...)` に合わせ **先頭** で統一。

### 5.1 `ParallelStorage`

| 変更前 | 変更後 | 区分 |
|---|---|---|
| `__init__(db_file, contents_dir, working_dir=None)` | `__init__(db_file: str, contents_dir: str, working_dir: str \| None = None, *, max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS)` | 互換 |
| `getMeta(public_id) -> FileMeta` | `getMeta(pid: str \| None, public_id: str) -> FileMeta` | **破壊** |
| `format_psc_public_id(public_id, **kwargs) -> Path` | `format_psc_public_id(pid: str \| None, public_id: str, **kwargs) -> Path` | **破壊** |
| `comp_img(public_id, width, height, quality) -> Path` | `comp_img(pid: str \| None, public_id: str, width: int \| None, height: int \| None, quality: int \| None) -> Path` | **破壊** |
| `update_suffix(public_id, suffix) -> None` | `update_suffix(pid: str, public_id: str, suffix: str) -> None` (commit 前のみ、宣言拡張子の上書き) | **破壊** |
| `update_status(public_id, status) -> None` | **削除** (中止は `delete` を使う) | **破壊** |
| `delete(pid, public_id, *, force=False) -> None` | `delete(pid: str \| None, public_id: str, *, force: bool = False) -> None`。手順: (1) `ID_RE`; (2) `getMeta`; (3) **所有者検査を先に**: `not force and (pid が None / 空 / != meta.pid)` → `PsPermissionError` (ファイルには触らない); (4) `contents/<cid>__PSC_*` を削除; (5) `working_dir/<public_id>` を削除; (6) `DBM.remove(pid, public_id=..., force=force)` | 互換 (force=True で pid None を許可) |

### 5.2 `ParallelStorageDBM` (`DatabaseManager` 継承)

| 変更前 | 変更後 | 区分 |
|---|---|---|
| `register(filename, suffix, size, pid, permission_id=None) -> str` | `register(filename: str, suffix: str, size: int, pid: str, *, original_suffix: str \| None) -> str` | **破壊** |
| `getMeta(*, contents_id=None, public_id=None) -> FileMeta` | `getMeta(*, contents_id: str \| None = None, public_id: str \| None = None, pid: str \| None = None) -> FileMeta` (pid 指定時は所有者照合) | 互換 |
| `status_change(contents_id, status)` | `status_change(pid: str, contents_id: str, status: FileStatus, *, force: bool = False)` | **破壊** |
| `update_public_id(contents_id) -> None` | `update_public_id(pid: str, contents_id: str) -> str` (新 public_id を返す) | **破壊** |
| `update_types(contents_id, types)` | `update_types(pid: str, contents_id: str, types: FileTypes)` | **破壊** |
| `update_suffix(contents_id, suffix)` | `update_suffix(pid: str, contents_id: str, suffix: str)` | **破壊** |
| — | `finalize_commit(pid: str, contents_id: str, *, types: FileTypes, suffix: str) -> None` (types + suffix + status='COMMITTED' を 1 UPDATE) | 新規 |
| `remove(pid: str \| None, *, contents_id=None, public_id=None)` | `remove(pid: str \| None, *, contents_id: str \| None = None, public_id: str \| None = None, force: bool = False)`。`force=False` で pid が None / 空 / 不一致 → `PsPermissionError`。`force=True` は pid を見ない (None 可、管理用途) | **破壊** (暗黙の無検査削除が消える) |
| — | `count_active(pid: str) -> int` (status IN INIT/UPLOADING/READY の行数。ERROR は数えない — ERROR 遷移時に作業ディレクトリを即時削除するのでディスクを持たない。READY は結合前の全チャンクを持つので数える) | 新規 |
| — | `list_stale(older_than_seconds: int) -> list[FileMeta]` (status IN INIT/UPLOADING/READY/ERROR/ABORTED かつ `creation_date <= datetime('now', ?)`、引数 `f"-{n} seconds"`) | 新規 |

全変更系メソッドの共通手順: (1) `getMeta` で行を取る (無ければ `PsContentsIDInvalidError` / `PsPublicIDInvalidError`)、(2) `not force and meta.pid != pid` なら `PsPermissionError`、(3) SQL は `... WHERE contents_id = ? AND pid = ?` (force 時は pid 条件なし) で二重化、(4) commit。

### 5.3 `MultiPartUploader`

| 変更前 | 変更後 | 区分 |
|---|---|---|
| `__init__(db_file, working_dir, contents_dir)` | `__init__(db_file: str, working_dir: str, contents_dir: str, *, max_upload_size: int = DEFAULT_MAX_UPLOAD_SIZE, chunk_max_size: int = DEFAULT_CHUNK_MAX_SIZE, min_chunk_size: int = DEFAULT_MIN_CHUNK_SIZE, max_active_uploads_per_pid: int = DEFAULT_MAX_ACTIVE_UPLOADS_PER_PID, max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS)` | 互換 |
| `register(filename, size, pid, permission_id, total_chunks, sha256) -> str` | `register(filename: str, size: int, pid: str, total_chunks: int, sha256: str) -> str` | **破壊** (旧 6 引数の位置呼び出しは新 5 引数シグネチャに対して Python の `TypeError`) |
| `parts_upload(pid, public_id, count, blob, sha256) -> None` | 同じシグネチャ、検査追加 | 互換 (挙動変更) |
| `commit(pid, public_id) -> FileMeta` | 同じ、検査追加 | 互換 (挙動変更) |
| `_failed(pid, public_id)` (未使用) | `_failed(pid: str, public_id: str) -> None` を復活: status を ERROR にして作業ディレクトリを rmtree (行は残す)。**ERROR への遷移は全てこの関数経由で、呼ぶのは commit だけ** (結合後の sha / サイズ不一致、画像上限超過)。parts_upload のチャンク sha 不一致は ERROR にしない (`PsChunkHashMismatchError`、再送で回復) | 内部 |
| — | `gc(*, older_than_seconds: int = 86400) -> GcReport` | 新規 |
| — | `expected_chunk_size(size: int, total_chunks: int, count: int) -> int` (モジュール関数) | 新規 |

### 5.4 モジュール関数

| 変更前 | 変更後 |
|---|---|
| `format_psc_filename(contents_id, suffix, **kwargs) -> str` | 同じ。追加検査: `CID_RE`、`SUFFIX_RE`、kwargs のキーと `str(値)` が `KWARG_RE` (None の値は従来どおり省く)。不一致は `PsArgmentsError(名前)` (suffix は `PsSuffixInvalidError`) |
| `_detect_file_type(path, filename) -> FileTypes` | **削除** → `classify_file(path: Path, declared_suffix: str, *, max_image_pixels: int) -> Classification` |
| — | `normalize_image_variant(width: int \| None, height: int \| None, quality: int \| None) -> tuple[int \| None, int \| None, int]` (検証 + プリセット丸め。`comp_img` と `format_psc_public_id` が共用) |
| — | `psc_response_headers(meta: FileMeta) -> dict[str, str]` (配信ヘッダの推奨値、§6 PS-C-6) |

### 5.5 `DatabaseManager` (db.py)

| 変更前 | 変更後 |
|---|---|
| `__init__(db_file, auto_commit=True)` | `__init__(db_file: str, auto_commit: bool = True, *, file_mode: int \| None = 0o600)`。`sqlite3.connect()` の **前** に `fd = os.open(db_file, os.O_CREAT \| os.O_RDWR, file_mode); os.close(fd)` を 1 回呼ぶ (`O_EXCL` 無し: ファイルが無ければ `file_mode & ~umask` で作られ、既にあれば mode は **変更しない**。毎回の chmod はしない — 運用が 0640 にした DB を起動ごとに戻さない、`connect()` が umask で作ってから chmod するまでの窓も無い)。対象外: `":memory:"`、`file:` で始まる URI、`file_mode=None`。`OSError` は `DBOperationalError(str(e))`。WAL / SHM は SQLite が本体の mode を継承する (実測: 本体 0600 → `-wal` / `-shm` も 0600)。**接続後の初期化 (PRAGMA / サブクラスの `_init` = テーブル作成・移行) が例外を上げたら、`self._conn.close()` して `_conn` / `_cursor` を None に戻した上で再送出する** (接続リークと、半端な状態のオブジェクトが残るのを防ぐ、RG09) |
| — | `immediate_transaction() -> contextmanager` (新規)。接続が **トランザクション外** (`self._conn.in_transaction is False`) なら `BEGIN IMMEDIATE` を発行し、ブロック正常終了で `COMMIT`、例外で `ROLLBACK` して再送出。接続が **既にトランザクション中** なら `SAVEPOINT sp_<n>` を切り、正常終了で `RELEASE sp_<n>` (内側で明示 COMMIT はしない — 外側に委ねる)、例外で `ROLLBACK TO sp_<n>; RELEASE sp_<n>` して再送出。ネスト深さは接続ごとのカウンタで `n` を振る。ブロック内の `execute` は `auto_commit` を無視して commit しない (`auto_commit=True` の DatabaseManager でも、ブロック中は `in_transaction` を見て自動 commit を抑止する)。外側が例外で ROLLBACK すれば内側で RELEASE 済みの変更も消える (SAVEPOINT の意味論どおり) |
| `execute(sql, *args)`: `SELECT` で始まる時だけ fetchall | `self._cursor.description is not None` のとき fetchall (PRAGMA / WITH / RETURNING も行を返す)。INSERT / UPDATE / DELETE は従来どおり None |

サブクラス (`AuthDBM`, `UserDatabaseManager`) は位置引数で `super().__init__` を呼んでいるので既定 0600 が自動で効く (横断効果、§8-5)。

### 5.6 `core/log.py`

```python
def sanitize_log_field(s: str) -> str
    # None -> "-"。str 以外は str(s) に変換してから処理。
    # "\r" -> "\\r", "\n" -> "\\n", "\t" -> "\\t"、その他 U+0000–U+001F と U+007F -> "\\x%02x"、
    # U+0080–U+009F と U+2028 / U+2029 -> "\\u%04x"。それ以外はそのまま (日本語・絵文字は保持)。

class AppLogger:
    def __init__(self, *, info=None, warn=None, error=None, access=None,
                 max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5) -> None
    def info(self, msg: str) -> None
    def warn(self, msg: str) -> None
    def error(self, err: Exception | str) -> None
    def access(self, msg: str) -> None

class AuthLogger:
    def __init__(self, path: str | Path, *, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5) -> None
    # login_success / login_failed / signup / token_invalid は不変
    def event(self, action: str, *, subject: str, ip: str | None = None, detail: str | None = None) -> None
    # 汎用イベント (auth doc の要求)。行形式 `[ts] [ACTION] subject=<subject> ip=<ip or "-"> detail=<detail or "-">`。
    # action は大文字化せずそのまま書く (呼び出し側が "MASTER_DEACTIVATE" 等を渡す)。
    # action / subject / ip / detail の全フィールドを sanitize_log_field に通す。既存 4 メソッドも内部で同じ _write を使う。
```

`sanitize_log_field` は `nexom.core.log` のモジュールトップレベル関数 (アンダースコア無し) として公開し、`from nexom.core.log import sanitize_log_field` で http / auth doc から import できる。`core/log.py` に `__all__ = ["sanitize_log_field", "AppLogger", "AuthLogger"]` を置く。

### 5.7 `core/error.py` ParallelStorage 節

| コード | 例外 | 変更 |
|---|---|---|
| PS01 | `PsStatusTypesError(status)` | 不変 |
| PS02 | `PsFileStatusInvalidError()` | **重複定義 (PS02 / PS03 の同名クラス 2 つ) を 1 つに**。残すのは PS02、メッセージ "This file is in an invalid status for the operation." |
| PS04 | `PsArgmentsError(name=None)` | 不変 (tests/test_core.py が依存) |
| PS05 / PS06 | `PsPublicIDInvalidError()` / `PsContentsIDInvalidError()` | 不変 |
| PS07 | `PsDataCorruotedError()` | 不変 |
| PS08 | `PsChunkEntityTooLargeError()` | メッセージを "Chunk is over size." に |
| PS09 | `PsPermissionError()` | メッセージを "Permission denied. pid does not own this content." に (コピペ誤りの修正) |
| PS010 | `PsFileTypesError(types: str \| None = None)` | **引数を省略可に** (現状は必須で `PsFileTypesError()` が `TypeError`) |
| PS11 | `PsSuffixInvalidError(suffix: str)` | 新規 |
| PS12 | `PsPathEscapeError()` | 新規 |
| PS13 | `PsImageTooLargeError(pixels: int \| None = None)` | 新規 |
| PS14 | `PsUploadTooLargeError(size: int, limit: int)` | 新規 |
| PS15 | `PsChunkSizeMismatchError(expected: int, actual: int)` | 新規 |
| PS16 | `PsTooManyActiveUploadsError(limit: int)` | 新規 |
| PS17 | `PsChunkHashMismatchError(count: int)` | 新規 (チャンク単位の sha256 不一致。再送で回復可能、`PsDataCorruotedError` とは区別する) |

全て `NexomError` 直下 (`except NexomError` で既存アプリが捕まえられる)。HTTP への写像はアプリ側 (推奨: PS09→403、PS08/13/14/15→413、PS16→429、PS17→422 (クライアントは同じ count を再送)、PS04/11/12→400、PS05/06→404、PS02→409、PS07→422)。

## 6. 挙動仕様

Reviewer はこの節から直接テストを生成する。各項目は「入力 → 期待結果 → 副作用」。「現状」は 1.1.41 の実測 (Researcher プローブ / 本 doc 執筆時の再現)。`A` = 所有者 pid、`B` = 別 pid。前提フィクスチャ: `uploader = MultiPartUploader(db, workers, contents, min_chunk_size=1)` (小さなテストデータで複数チャンクを許すため) と `ps = ParallelStorage(db, contents, workers)`。

### PS-A 認可 (DATA-01 / 02)

| # | 操作 | 期待 | 副作用 | 現状 |
|---|---|---|---|---|
| A-1 | A が COMMITTED にしたオブジェクトを `ps.delete("B", public_id)` | `PsPermissionError` | DB 行は残る、`contents/<cid>__PSC_*` は残る | 同じ (ParallelStorage.delete は検査あり) |
| A-2 | 同じ行を `ps._PSDBM.remove("B", public_id=public_id)` | `PsPermissionError` | DB 行は残る | **削除成功** (NEX-02 / DATA-01) |
| A-3 | `ps._PSDBM.remove("A", public_id=public_id)` | 正常終了 | DB 行が消える | 同じ |
| A-4 | `ps._PSDBM.remove("B", public_id=public_id, force=True)` | 正常終了 | DB 行が消える | — |
| A-5 | `ps.delete("B", public_id, force=True)` | 正常終了 | 行・ファイル・作業ディレクトリが消える | 同じ |
| A-5a | `ps.delete(None, public_id, force=True)` | 正常終了 (管理用途) | 全て消える | — |
| A-5b | `ps.delete(None, public_id)` / `ps.delete("", public_id)` / `ps.delete("B", public_id)` (A のオブジェクト、キャッシュ `.webp` も作成済) | `PsPermissionError` **かつ** `contents/<cid>__PSC_*` の全ファイルと DB 行が残る (所有者検査がファイル削除より前。半適用削除なし) | なし | force=False で pid 不一致は同じだが、検査の位置は同じ (本項は順序を固定するための回帰テスト) |
| A-6 | `ps.getMeta("B", public_id)` | `PsPermissionError` | なし | pid 引数なしで取得可 |
| A-7 | `ps.getMeta(None, public_id)` | `FileMeta` を返す (capability モデル) | なし | 同等 |
| A-8 | `ps.getMeta("A", public_id)` | `FileMeta` | なし | — |
| A-9 | `ps.format_psc_public_id("B", public_id)` / `ps.comp_img("B", public_id, 64, None, None)` | `PsPermissionError` | キャッシュファイルは作られない | pid なしで成功 |
| A-10 | `ps.update_suffix("B", public_id, ".txt")` | `PsPermissionError` | suffix 不変 | pid なしで成功 |
| A-11 | `ps._PSDBM.status_change("B", cid, "ABORTED")` / `update_types("B", cid, "Binary")` / `update_suffix("B", cid, ".txt")` / `update_public_id("B", cid)` / `finalize_commit("B", cid, types="Binary", suffix=".bin")` | いずれも `PsPermissionError` | 行は不変 | pid 引数なし |
| A-12 | `uploader.parts_upload("B", public_id, 0, blob, sha)` | `PsPermissionError` | チャンクファイルは書かれない、status 不変 | 同じ (ただし現状は status 検査が先) |
| A-13 | `uploader.commit("B", public_id)` | `PsPermissionError` | 作業ディレクトリ・status 不変 | 同じ |
| A-14 | 存在しない public_id (形式は正しい 32 文字) で `getMeta(None, ...)` | `PsPublicIDInvalidError` | なし | 同じ |
| A-15 | 形式不正の public_id (`"../x"`, `""`, 15 文字, 65 文字, `"a b"`) を `getMeta` / `format_psc_public_id` / `comp_img` / `update_suffix` / `delete` / `parts_upload` / `commit` に渡す | `PsPublicIDInvalidError` (DB 参照より前) | なし | DB 参照 → 行なしの PsPublicIDInvalidError (結果は同じ、ファイルパスには載らない) |
| A-16 | `MultiPartUploader.register(..., pid="")` または `pid=None` | `PsArgmentsError("pid")` | 行なし | 受理 |
| A-17 | `ps._PSDBM.register("f", ".txt", 1, "A", original_suffix=None)` に `permission_id=` キーワードを付ける | `TypeError` (引数が存在しない) | — | 受理 |
| A-18 | `ps.update_status` を呼ぶ | `AttributeError` (削除済) | — | 存在 |

### PS-B 拡張子・パス (DATA-03)

| # | 操作 | 期待 | 副作用 | 現状 |
|---|---|---|---|---|
| B-1 | `ps.update_suffix("A", public_id, "./../../evil")` | `PsSuffixInvalidError` | suffix 不変 | 受理され `format_psc_public_id` が contents_dir 外 (`<parent>/evil`) を返す |
| B-2 | `update_suffix` に `".tar.gz"`, `".x y"`, `".\x00"`, `"bin"` (ドット無し), `""`, `"." + "a"*17` | `PsSuffixInvalidError` | 不変 | `"bin"`/`""` 以外は受理 |
| B-3 | `update_suffix("A", public_id, ".BIN")` (status INIT) | 正常、`getMeta(...).suffix == ".bin"` (小文字化) かつ `original_suffix == ".bin"` | DB 更新 | `.BIN` のまま保存 |
| B-4 | COMMITTED の行に `update_suffix("A", ...)` | `PsFileStatusInvalidError` | 不変 (保存名と DB がずれる操作を禁止) | 受理 (ずれる) |
| B-5 | `format_psc_filename("cid", ".txt", b=2, a=1, z=None)` | `"cid__PSC_a-1_b-2.txt"` | — | 同じ (既存テスト) |
| B-6 | `format_psc_filename("cid", ".txt", w="../x")` / `format_psc_filename("cid", ".txt", **{"a/b": 1})` | `PsArgmentsError` | — | 受理 |
| B-7 | `format_psc_filename("../cid", ".txt")` / `format_psc_filename("cid", "../x")` | `PsArgmentsError("contents_id")` / `PsSuffixInvalidError` | — | 受理 |
| B-8 | `ps.format_psc_public_id(None, public_id)` の戻り値 | `contents_dir.resolve()` の **直下** の Path (`path.parent == contents_dir.resolve()`) | — | 同じ (正常系) |
| B-9 | DB の suffix を直接 SQL で `./../../evil` に書き換えた上で `format_psc_public_id(None, public_id)` (旧データ・DB 改竄の防御) | `PsSuffixInvalidError` (format_psc_filename の検査) | ファイル操作なし | 外側パスを返す |
| B-10 | `register(filename="../../etc/passwd")` | 正常。`filename == "passwd"`、`suffix == ".bin"`、`original_suffix is None` (`Path(filename).name` の stem を使い、suffix は無しなので FALLBACK) | 行作成 | stem は `passwd`、suffix `""` |
| B-11 | `register(filename="a.PNG")` | `suffix == ".png"`, `original_suffix == ".png"` | — | `.PNG` |
| B-12 | `register(filename="x.\x00")` | `suffix == ".bin"`, `original_suffix is None` | — | `.\x00` が保存され書き込み時 ValueError |

### PS-C 分類とコンテンツ由来の保存名 (DATA-04 / 07)

`classify_file(path, declared_suffix, *, max_image_pixels)` の規則:

1. `Image.open(path, formats=["JPEG","PNG","GIF","WEBP"])` で開く。開けた場合: `w, h = im.size`; `w*h > max_image_pixels` → `PsImageTooLargeError(w*h)`; `im.verify()` 成功 → `Classification("Images", IMAGE_FORMATS[im.format], im.format, w, h)`。`Image.open` 自身が `DecompressionBombError` を上げた場合 (Pillow 既定の 2 倍超 = 178,956,970 px 超) → `PsImageTooLargeError(None)`。`PsImageTooLargeError` 以外の例外 (`UnidentifiedImageError`、verify 失敗等) → 非画像として 2 へ。
2. 非画像: `d = declared_suffix.lower()`、`SUFFIX_RE` 不一致なら `d = ""`。`d ∈ DOCUMENT_SUFFIXES` → `("Documents", d)`; `MEDIA_SUFFIXES` → `("Media", d)`; `BINARY_SUFFIXES` → `("Binary", d)`; `DANGEROUS_SUFFIXES` → `("Dangerous", ".bin")`; それ以外 → `("Binary", ".bin")`。`image_format / width / height` は None。

| # | 入力 (commit まで完了) | 期待 `FileMeta` | 保存ファイル | 現状 |
|---|---|---|---|---|
| C-1 | 正当な GIF バイト列 + `<script>alert(1)</script>` を末尾に付加、filename `poly.html` | `types == "Images"`, `suffix == ".gif"`, `original_suffix == ".html"` | `contents/<cid>__PSC_.gif` のみ存在、`__PSC_.html` は存在しない | `Images`、保存名 `.html` |
| C-2 | 同バイト列、filename `poly.svg` | `types == "Images"`, `suffix == ".gif"` | `.gif` | `Images`、`.svg` |
| C-3 | 素の `<svg onload=...>` テキスト、filename `a.svg` | `types == "Binary"`, `suffix == ".bin"`, `original_suffix == ".svg"` | `.bin` | **`Images`** (mimetypes 由来)、`.svg` |
| C-4 | HTML テキスト、filename `a.html` | `types == "Binary"`, `suffix == ".bin"` | `.bin` | `Documents`、`.html` |
| C-5 | JPEG バイト列、filename `a.png` | `types == "Images"`, `suffix == ".jpg"`, `original_suffix == ".png"` | `.jpg` | `.png` |
| C-6 | PNG バイト列、filename `a.jpeg` | `suffix == ".png"` | `.png` | `.jpeg` |
| C-7 | `b"hello"` テキスト、filename `a.txt` | `types == "Documents"`, `suffix == ".txt"` | `.txt` | 同じ |
| C-8 | `b"hello"`、filename `a.exe` | `types == "Dangerous"`, `suffix == ".bin"` | `.bin` | `Dangerous`、`.exe` |
| C-9 | 4x4 BMP バイト列、filename `a.bmp` | `types == "Binary"`, `suffix == ".bin"` (BMP は allowlist 外、Pillow は `UnidentifiedImageError`) | `.bin` | `Images`、`.bmp` |
| C-10 | 12000x12000 の 1bit PNG (約 41 KB、1.44 億 px)、filename `bomb.png` | `commit` が `PsImageTooLargeError`; その後 `getMeta(None, pid).status == "ERROR"`; 作業ディレクトリは削除済; `contents/` にファイル無し | — | `Images` で COMMITTED、`comp_img` で約 430 MB 展開 |
| C-11 | 7000x7000 の 1bit PNG (4900 万 px、上限 5000 万以下) | `types == "Images"`, COMMITTED | `.png` | 同じ |
| C-12 | `MultiPartUploader(..., max_image_pixels=1_000)` で 40x40 PNG を commit | `PsImageTooLargeError`、status ERROR | — | — |
| C-13 | `psc_response_headers(meta)` (Images, `.jpg`) | `{"Content-Type": "image/jpeg", "Content-Disposition": "inline", "X-Content-Type-Options": "nosniff"}` | — | 関数なし |
| C-14 | `psc_response_headers(meta)` (Documents, filename `report`, suffix `.txt`, original_suffix `.txt`) | `{"Content-Type": "application/octet-stream", "Content-Disposition": 'attachment; filename="report.txt"', "X-Content-Type-Options": "nosniff"}`。filename は `[^A-Za-z0-9._-]` を `_` に置換、original_suffix が None なら suffix を使う | — | — |

### PS-D 画像変換 (DATA-05 / 16)

`normalize_image_variant(width, height, quality)`: `width` / `height` は None か `int` (bool 不可) で `1 <= v <= IMAGE_SIZE_STEPS[-1]` (4096)、違えば `PsArgmentsError("width")` / `("height")`。`quality` は None か `1..100`、違えば `PsArgmentsError("quality")`。丸め: 寸法は `IMAGE_SIZE_STEPS` のうち要求値以上で最小のもの、quality は `IMAGE_QUALITY_STEPS` のうち要求値以上で最小のもの (96〜100 は 95)、None の quality は `DEFAULT_IMAGE_QUALITY` (70) を丸めたもの (= 70)。

`comp_img(pid, public_id, width, height, quality)` の手順: (1) `getMeta(pid, public_id)`; (2) `status != "COMMITTED"` → `PsFileStatusInvalidError` を **先に**、次に `types != "Images"` → `PsFileTypesError` (register 直後の INIT 行は types が Binary なので、この順でないと D-10 が成立しない); (3) `normalize_image_variant`; (4) `cache_path = format_psc_public_id(pid, public_id, width=bw, height=bh, quality=q)`; `cache_path.exists()` → 即返す (再生成しない); (5) `original = format_psc_public_id(pid, public_id)` が無ければ `PsDataCorruotedError`; (6) `Image.open(original, formats=[...4 形式])`; `w*h > max_image_pixels` または `DecompressionBombError` → `PsImageTooLargeError`; (7) `ImageOps.exif_transpose(im, in_place=True)` を `try/except Exception: pass` で; `im.convert("RGB")`; (8) 出力サイズ: `(bw, bh)` が `(None, None)` → リサイズなし。`(bw, None)` → `ow <= bw` ならリサイズなし、それ以外 `(bw, max(1, round(oh*bw/ow)))`。`(None, bh)` は対称。`(bw, bh)` → `scale = min(bw/ow, bh/oh)`、`scale >= 1` ならリサイズなし、それ以外 `(max(1, round(ow*scale)), max(1, round(oh*scale)))` (アスペクト維持の contain、拡大はしない); `Image.Resampling.LANCZOS`; (9) `cache_path.name + ".tmp-" + _rand(8)` に `save(format="WEBP", quality=q, method=6)` → `os.replace` で `cache_path` に。失敗時は tmp を unlink して再送出。戻り値 `cache_path`。

`format_psc_public_id(pid, public_id, **kwargs)`: `getMeta(pid, public_id)`; `types == "Images"` かつ kwargs に `width` / `height` / `quality` のいずれかがある → それらを `normalize_image_variant` に通して丸め、suffix を `.webp` に; `format_psc_filename(cid, suffix, **kwargs)`; `(contents_dir / name).resolve()` が `contents_dir.resolve()` の直下でなければ `PsPathEscapeError`。

| # | 操作 (前提: 10x10 の赤 PNG を A が commit 済) | 期待 | 副作用 | 現状 |
|---|---|---|---|---|
| D-1 | `ps.comp_img("A", public_id, 8, 8, 80)` | 戻り値 `Path` が存在し `.suffix == ".webp"`、名前が `<cid>__PSC_height-64_quality-85_width-64.webp`、画像を開くと `size == (10, 10)` (拡大しない)、`format == "WEBP"` | ファイル 1 個生成 | `TypeError: PsFileTypesError.__init__() missing 1 required positional argument` (xfail の実因。テストが commit を経ないため types が Binary → 例外生成で落ちる) |
| D-2 | D-1 の直後に同じ呼び出し | 同じ Path、ファイルの `st_mtime_ns` が変わらない (再生成しない) | なし | 毎回再生成 |
| D-3 | `comp_img("A", public_id, 300, None, None)` | 名前に `width-384` と `quality-70`、`height-` を含まない | — | `width-300` |
| D-4 | `ps.format_psc_public_id(None, public_id, width=300)` | D-3 と同じ Path (同じ丸めを通る) | なし | `width-300` |
| D-5 | 400x200 の PNG を commit 後 `comp_img("A", pid, 100, 100, None)` | 丸めで `(bw, bh) = (128, 128)`、contain で出力 `size == (128, 64)`、名前 `height-128_quality-70_width-128` | — | `(100, 100)` に歪む |
| D-6 | `comp_img("A", public_id, 20000, 20000, None)` | `PsArgmentsError("width")` | ファイル生成なし | 1.2 GB のバッファ確保に進む |
| D-7 | `comp_img("A", public_id, 0, None, None)` / `(None, -1, None)` / `(None, None, 0)` / `(None, None, 101)` / `(True, None, None)` | `PsArgmentsError` (順に width / height / quality / quality / width) | なし | 0 / 負は同じ、True は通る |
| D-8 | `comp_img("A", public_id, None, None, None)` | `quality-70` の `.webp`、サイズ不変 | ファイル 1 個 | 同じ (キャッシュ名は `__PSC_.webp`) |
| D-9 | `types != "Images"` の行 (C-7 の txt) に `comp_img` | `PsFileTypesError` | なし | TypeError |
| D-10 | `status == "INIT"` の行 (register のみ) に `comp_img` | `PsFileStatusInvalidError` | なし | — |
| D-11 | 旧版で COMMITTED 済みの行に対し、ディスク上の原本だけを 12000x12000 PNG に差し替えて `comp_img` | `PsImageTooLargeError` | キャッシュ無し、原本不変 | 約 430 MB 展開して生成 |
| D-12 | 原本に壊れた EXIF (切り詰めた IFD) を持つ JPEG | 正常に `.webp` が生成される (向き補正はスキップ) | — | Pillow 版次第で例外 |
| D-13 | 原本ファイルを削除してから `comp_img` | `PsDataCorruotedError` | なし | `FileNotFoundError` |
| D-14 | `ps = ParallelStorage(db, contents, max_image_pixels=50)` で 10x10 (100 px) の原本に `comp_img` | `PsImageTooLargeError` | なし | — |

### PS-E アップロード上限・チャンク整合・GC (DATA-06)

`expected_chunk_size(size, total_chunks, count)`: `chunk = ceil(size / total_chunks)`; `count < total_chunks - 1` → `chunk`、最後は `size - chunk * (total_chunks - 1)`。

`register(filename, size, pid, total_chunks, sha256)` の検査順: (1) `pid` が非空 str でなければ `PsArgmentsError("pid")`; (2) `size` が `int` (bool 不可) で `> 0` でなければ `PsArgmentsError("size")`; `size > max_upload_size` → `PsUploadTooLargeError(size, max_upload_size)`; (3) `total_chunks` が `int` で `>= 1` でなければ `PsArgmentsError("total_chunks")`; (4) `chunk = ceil(size/total_chunks)`; `chunk > chunk_max_size` → `PsArgmentsError("total_chunks")`; `total_chunks > max(1, ceil(size / min_chunk_size))` → `PsArgmentsError("total_chunks")`; `size <= (total_chunks - 1) * chunk` → `PsArgmentsError("total_chunks")` (最終チャンクが 0 以下になり永遠に完了できない組: size=5, total=4 → chunk=2, 3×2=6 ≥ 5); (5) `SHA256_RE` 不一致 → `PsArgmentsError("sha256")`; (6)(7) は **同一トランザクション** (`with self._PSDBM.immediate_transaction():`、§5.5): `BEGIN IMMEDIATE` で書きロックを取ってから `count_active(pid)` を数え、`>= max_active_uploads_per_pid` なら例外 `PsTooManyActiveUploadsError(limit)` で抜けて rollback、そうでなければ同じトランザクション内で行 INSERT → ブロックを抜けて commit (別接続の並行 register は `BEGIN IMMEDIATE` で `busy_timeout` 3 秒まで待つので、カウントと INSERT の間に他方が割り込めず上限を超えない。呼び出し側が既に外側のトランザクションを張っていれば SAVEPOINT に畳まれ、外側の例外で登録行も消える — DB-9); (7) 行 INSERT (`filename = Path(filename).name` の stem を 200 文字で切る、`suffix` / `original_suffix` は B-10〜12)、作業ディレクトリ `mkdir(parents=True)` 後 `os.chmod(dir, 0o700)`、`meta.json` を `os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o600)` で書く。

`parts_upload(pid, public_id, count, blob, sha256)` の検査順: (1) `ID_RE` → `PsPublicIDInvalidError`; (2) 行なし → `PsPublicIDInvalidError`; (3) `meta.pid != pid` → `PsPermissionError`; (4) `status ∉ {INIT, UPLOADING}` または作業ディレクトリ無し → `PsFileStatusInvalidError` (ERROR は作業ディレクトリが既に無いので再送不可、register からやり直し); (5) `count` が `int` (bool 不可) で `0 <= count < total_chunks` でなければ `PsArgmentsError("count")`; (6) `blob` が `bytes | bytearray` でなければ `PsArgmentsError("blob")`; `len(blob) > chunk_max_size` → `PsChunkEntityTooLargeError`; `len(blob) != expected_chunk_size(...)` → `PsChunkSizeMismatchError(expected, actual)`; (7) `sha256(blob)` を **メモリ上で** 計算し不一致 → `PsChunkHashMismatchError(count)` を投げるだけ。status は変えない (INIT なら INIT、UPLOADING なら UPLOADING のまま)、作業ディレクトリと他のチャンクも残す、チャンクファイルは書かない (同じ count を再送すれば回復。ERROR 遷移と作業ディレクトリ削除は commit 側の失敗だけ — モバイル回線の 1 チャンク破損で全再送を強いない。クォータは INIT / UPLOADING / READY で数えるので穴にならない); (8) `chunk<count>.parts` を 0600 で書く (既存なら上書き = 再送許容); (9) 全チャンクの存在を毎回数え、揃えば `READY`、揃わなければ `UPLOADING`。

`commit(pid, public_id)`: (1)(2)(3) 同上; (4) `status != "READY"` → `PsFileStatusInvalidError`; (5) 結合 → 全体 sha256 不一致 / サイズ不一致 → `_failed` (status ERROR + 作業ディレクトリ削除) して `PsDataCorruotedError`; (6) `classify_file` → `PsImageTooLargeError` なら `_failed` して再送出; (7) `contents_root / format_psc_filename(cid, cls.suffix)` に `shutil.move` (既存は unlink)、(8) `finalize_commit(pid, cid, types=cls.types, suffix=cls.suffix)`; (9) 作業ディレクトリ削除; 戻り値 `getMeta(contents_id=cid)`。

`gc(*, older_than_seconds=86400)`: `list_stale(older_than_seconds)` の各行について作業ディレクトリ `rmtree(ignore_errors=True)` → `remove(meta.pid, contents_id=..., force=True)` → `removed_rows += 1`。次に `working_root` 直下の、`ID_RE` に合致する名前のディレクトリで行が無く `st_mtime` が `now - older_than_seconds` より古いもの → rmtree、`removed_dirs += 1`。

| # | 操作 | 期待 | 副作用 | 現状 |
|---|---|---|---|---|
| E-1 | `register("f.bin", 10**9 + 1, "A", 1, sha)` (`max_upload_size` 既定 100 MiB) | `PsUploadTooLargeError` | 行なし、ディレクトリなし | 受理 |
| E-2 | `register("f.bin", 100, "A", 10**9, sha)` (min_chunk_size=1) | `PsArgmentsError("total_chunks")` (100 バイトに 10^9 チャンクは不可) | 行なし | 受理 (DATA-06) |
| E-3 | `register("f.bin", 30 * 1024 * 1024, "A", 2, sha)` (既定 chunk_max 10 MiB) | `PsArgmentsError("total_chunks")` (1 チャンク 15 MiB > 10 MiB) | 行なし | 受理 |
| E-4 | 既定 `min_chunk_size` (256 KiB) で `register("f.bin", 1000, "A", 2, sha)` | `PsArgmentsError("total_chunks")` | — | 受理 |
| E-5 | `register("f.bin", 18, "A", 2, sha)` (min_chunk_size=1) | 正常、public_id (32 文字、`ID_RE` 合致) を返す。`workers/<public_id>` の mode が `0o700`、`meta.json` が `0o600` | — | umask 依存 (0755 / 0644) |
| E-6 | `register(..., sha256="xyz")` / `"A"*64` 以外の長さ | `PsArgmentsError("sha256")` | — | 受理 |
| E-2a | `register("f.bin", 5, "A", 4, sha)` (min_chunk_size=1) | `PsArgmentsError("total_chunks")` (chunk=2、3×2=6 ≥ 5 で最終チャンク長が −1) | 行なし | 受理され永遠に READY にならない |
| E-7 | 同じ pid で `register` を 8 回 (既定 `max_active_uploads_per_pid`) → 9 回目 | 9 回目が `PsTooManyActiveUploadsError(8)`; `MultiPartUploader(..., max_active_uploads_per_pid=2)` なら 3 回目 | — | 無制限 |
| E-8 | E-7 の後、1 件を `delete` (または commit) して再度 `register` | 正常 (COMMITTED は active に数えない) | — | — |
| E-8b | `max_active_uploads_per_pid=2` で、同じ pid の 2 件を E-17 の手順 (全体 sha 不一致の commit) で `ERROR` にした直後に `register` | 正常 (ERROR は active に数えない。失敗の積み重ねで register 不能にならない) | — | — |
| E-8a | 同じ DB ファイルに別接続の `MultiPartUploader` を 2 本作り、同じ pid で active 7 件にした上で、2 本から **同時に** (スレッド 2 本、`threading.Barrier` で揃えて) `register` | ちょうど 1 本が成功し、もう 1 本が `PsTooManyActiveUploadsError(8)`。終了後 `count_active(pid) == 8` (9 にならない) | — | 2 本とも成功し 9 件 (RG06) |
| E-9 | `data = b"hello-world-012345"` (18 B), total 2 → chunk0 を `data[:8]`、chunk1 を `data[8:]` で送る | chunk0 で `PsChunkSizeMismatchError(9, 8)`; `chunk0.parts` は書かれない; status INIT のまま | — | 受理 |
| E-10 | 同データを `data[:9]`, `data[9:]` で送る | 両方正常、1 つ目後 `status == "UPLOADING"`、2 つ目後 `"READY"`。`chunk0.parts` / `chunk1.parts` の mode 0o600 | — | 0644 |
| E-11 | E-10 を **逆順** (count 1 → count 0) | 2 つ目後に `READY` | — | count==total-1 でだけ判定するため 0 → 1 の順でないと READY にならない |
| E-12 | `parts_upload("A", pid, 999999, blob, sha)` / `-1` / `"0"` / `True` | `PsArgmentsError("count")` | ファイル無し | `chunk999999.parts` が書かれる |
| E-13 | `parts_upload` で 10 MiB + 1 バイト | `PsChunkEntityTooLargeError` | — | 同じ |
| E-14 | 2 チャンク中 chunk0 を正常送信後、chunk1 を正しいサイズ・誤った sha256 で送る | `PsChunkHashMismatchError(1)`、`status == "UPLOADING"` のまま、`workers/<public_id>/chunk0.parts` は残り `chunk1.parts` は存在しない、`meta.json` も残る | — | **`PsStatusTypesError`** (ERROR が許容リストに無い) かつ壊れたチャンクがディスクに残る |
| E-14a | register 直後 (INIT) に chunk0 を誤った sha256 で送る | `PsChunkHashMismatchError(0)`、`status == "INIT"` のまま | — | 同上 |
| E-15 | E-14 の後、同じ public_id に正しい chunk1 を同じ count で再送 → commit | `READY` → 正常に COMMITTED (再送で回復、register やり直し不要) | — | — |
| E-16 | 全チャンク揃う前 (`status == "UPLOADING"`) に `commit` | `PsFileStatusInvalidError`、作業ディレクトリは残る | — | 欠けたチャンクで `PsDataCorruotedError` |
| E-17 | 全体 sha256 を誤って register → 全チャンク正常 → commit | `PsDataCorruotedError`、`status == "ERROR"`、`workers/<public_id>` が存在しない、`contents/` にファイル無し | — | 例外のみ、作業ディレクトリ残存 |
| E-18 | COMMITTED 後に再度 `commit` | `PsFileStatusInvalidError` | — | `meta.json` 無しで `PsDataCorruotedError` |
| E-19 | 正常な commit | `FileMeta.status == "COMMITTED"`、`contents/<cid>__PSC_<suffix>` が存在、内容がデータと一致、`workers/<public_id>` 無し | — | 同じ (既存テスト) |
| E-20 | `register` のみの行 2 件 (A, B) と COMMITTED 1 件がある状態で、`creation_date` を SQL で 2 日前に書き換えてから `gc()` | `GcReport(removed_rows=2, removed_dirs=0)`、COMMITTED は残る、2 件の作業ディレクトリ消滅 | — | 関数なし |
| E-21 | 行の無い `workers/<32 文字の名前>/` を作り mtime を 2 日前にして `gc()` | `removed_dirs == 1` | — | — |
| E-22 | 直近 (1 分前) の INIT 行で `gc()` | `removed_rows == 0`、残る | — | — |

### PS-F `permission_id` と FileMeta

| # | 操作 | 期待 |
|---|---|---|
| F-1 | `FileMeta` に `permission_id` 属性 | `AttributeError` (dataclass から削除) |
| F-2 | 新規 DB で `register` 後 `SELECT permission_id` | `NULL` (列は存在、書かない) |
| F-3 | 1.1.41 スキーマ (original_suffix 列なし、`parallel_storage_meta` なし) の DB ファイルを用意し、`types='Images', suffix='.svg'` と `types='Images', suffix='.png'` と `types='Documents', suffix='.html'` の 3 行を入れて `ParallelStorageDBM(db)` を開く | 例外なし。列 `original_suffix` が追加される。1 行目が `types='Binary'`、2 行目 `Images` のまま、3 行目 `Documents` のまま (Images 以外は触らない)。`parallel_storage_meta` に `('schema_version','1')` | 
| F-4 | F-3 の DB を再度開く | 変化なし (冪等)。`getMeta(contents_id=...)` が `original_suffix is None` で返る |

### LOG ログ (DATA-11 / 12、HTTP-14 / AUTH-11 の供給側)

| # | 操作 | 期待 | 現状 |
|---|---|---|---|
| L-1 | `sanitize_log_field("a\nb\rc")` | `"a\\nb\\rc"` (バックスラッシュ + 文字、実際の改行を含まない) | 関数なし |
| L-2 | `sanitize_log_field("\x00\x1b[31m\x7f")` | `"\\x00\\x1b[31m\\x7f"` | — |
| L-3 | `sanitize_log_field("tab\there")` | `"tab\\there"` | — |
| L-4 | `sanitize_log_field("日本語 🙂 /path?q=1")` | 不変 | — |
| L-5 | `sanitize_log_field(" \u0085")` | `"\\u2028\\u0085"` | — |
| L-6 | `sanitize_log_field(None)` / `sanitize_log_field(123)` | `"-"` / `"123"` | — |
| L-7 | `AppLogger(warn=p).warn("GET /\n[2026-01-01 00:00:00] [INFO] fake")` | ファイルは **1 行**、`[... ] [WARN] GET /\\n[2026-01-01 00:00:00] [INFO] fake` の形。行頭 `[` の行数 == 1 | 2 行になり偽の INFO 行が立つ |
| L-8 | `AppLogger(access=p).access('1.2.3.4 "GET /a%0a" 200 1ms "UA"')` | 1 行、`%0a` はそのまま (復号前なので無害) | 同じ |
| L-9 | `AppLogger(error=p).error(PathNotFoundError("/x\n[INFO] fake"))` | 先頭行 `[ts] [ERROR] P01 -> This path is not found. '/x\\n[INFO] fake'`、以降の traceback 各行は **4 空白で始まる** (`    Traceback (most recent call last):` …)。行頭が `[` の行はちょうど 1 行 | traceback 内に生改行で偽行が入る |
| L-10 | `AppLogger(error=p).error("plain")` | `[ts] [ERROR] plain` の 1 行 | 同じ |
| L-11 | タイムスタンプ形式 | `^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] ` で始まる。UTC (`datetime.now(timezone.utc)`)。形式は 1.1.41 と同一 | `utcnow()` (3.12 で DeprecationWarning) |
| L-12 | `AppLogger(info=p, max_bytes=1000, backup_count=2)` に 100 バイトの行を 50 回 | `p` が存在し `st_size <= 1000 + 1 行分`、`p.1` と `p.2` が存在、`p.3` は存在しない | 単一ファイルが無限に伸びる |
| L-13 | `max_bytes=0` | ローテーションなし (1 ファイルが伸び続ける、外部 logrotate 運用向け) | — |
| L-14 | `AppLogger()` (全パス None) で各メソッド | 何も書かず例外なし (aisaba `auth_api.py:16` の使い方) | 同じ |
| L-15 | `AuthLogger(p).login_failed(user_id="bob\n[LOGIN_OK] subject=admin", ip="1.1.1.1\r")` | 1 行、`subject=bob\\n[LOGIN_OK] subject=admin ip=1.1.1.1\\r` | 2 行 |
| L-16 | `AuthLogger(p).token_invalid(token="abcdefghijkl", ip=None)` | `subject=abcdefgh... ip=-` (8 文字切りは不変) | 同じ |
| L-16a | `AuthLogger(p).event("MASTER_DEACTIVATE", subject="bob", ip="10.0.0.1", detail="by=admin")` | 1 行、`[ts] [MASTER_DEACTIVATE] subject=bob ip=10.0.0.1 detail=by=admin` | メソッドなし |
| L-16b | `AuthLogger(p).event("X", subject="s")` | `[ts] [X] subject=s ip=- detail=-` | — |
| L-16c | `AuthLogger(p).event("A\n[LOGIN_OK]", subject="s\r", ip="1\n", detail="d\x00")` | 1 行、`[A\\n[LOGIN_OK]] subject=s\\r ip=1\\n detail=d\\x00` (4 フィールド全てエスケープ) | — |
| L-16d | `from nexom.core.log import sanitize_log_field` | import 成功、`nexom.core.log.__all__` に含まれる | ImportError |
| L-17 | 同じパスで `AppLogger` を 2 回生成して各 1 行書く | 2 行とも書かれ、ハンドラの重複による二重書きが無い (行数 == 2) | — |

実装メモ: パスごとに `logging.getLogger(f"nexom.log.{resolved_path}")` (`propagate=False`) を持ち、`logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")` を **同じ baseFilename のハンドラが無い時だけ** 追加、`Formatter("%(message)s")`、`logger.log(INFO, line)`。マルチプロセス (gunicorn workers) では各プロセスが独立にローテーションするので境界付近の数行が失われ得るが、総量は `(backup_count+1) * max_bytes` 近傍で頭打ちになる (DoS 対策としての目的は満たす)。厳密に失いたくない運用は `max_bytes=0` + logrotate (§10-9)。

### DB `DatabaseManager` (DATA-13 / 14)

| # | 操作 | 期待 | 現状 |
|---|---|---|---|
| DB-1 | 存在しない `tmp/"a.db"` で `DatabaseManager(str(tmp/"a.db"))` 後の `a.db` の mode | `0o600` (テストは `os.umask(0o022)` 下で実行)。`a.db-wal` / `a.db-shm` が生成されていれば同じく `0o600` | umask (0644) |
| DB-1a | 先に `tmp/"a.db"` を `0o644` で作成 (`sqlite3.connect` で空 DB を作り `chmod 0o644`) してから `DatabaseManager(path)` | mode は `0o644` のまま (既存ファイルは変更しない) | 同じ |
| DB-2 | 存在しないパスで `DatabaseManager(path, file_mode=None)` | umask 依存 (`os.open` を呼ばない) | — |
| DB-3 | 存在しないパスで `DatabaseManager(path, file_mode=0o640)` | `0o640` | — |
| DB-4 | `DatabaseManager(":memory:")` | 例外なし | 同じ |
| DB-4a | `_init` が例外を上げるサブクラス (例: `_init` で `raise RuntimeError`) を `tmp/"a.db"` で生成 | `RuntimeError` が呼び出し側に届き、生成途中のインスタンスの `_conn is None` (close 済)。同じパスを別の `DatabaseManager` で直ちに開けて `PRAGMA journal_mode` が通る (ロック・接続リークなし) | — | 接続が開いたまま残る (RG09) |
| DB-5 | `dbm.execute("PRAGMA user_version")` | `[(0,)]` (行が返る) | `None` |
| DB-6 | `dbm.execute("WITH a AS (SELECT 1) SELECT * FROM a")` | `[(1,)]` | `None` |
| DB-7 | `dbm.execute("CREATE TABLE t(x)")` / `execute("INSERT INTO t VALUES (1)")` | `None` | 同じ |
| DB-9 | `ps._PSDBM` (= uploader と同じ DB ファイルを開いた `ParallelStorageDBM`) で `with dbm.immediate_transaction(): uploader_same_conn.register(...); raise RuntimeError` — 外側 tx の中で register を呼び、直後に例外 (uploader は同じ接続を使う構成、例: `MultiPartUploader` に `dbm` を注入するテスト用の内部属性差し替え `uploader._PSDBM = dbm`) | `RuntimeError` が外に届き、`SELECT COUNT(*) FROM parallel_storage` が register 前の値に戻る (登録行が残らない)。作業ディレクトリは register が作ったものが残り得るので、本項では行の消滅のみを assert | — | 登録行が残る (RG06 第 2 パス) |
| DB-9a | `with dbm.immediate_transaction(): with dbm.immediate_transaction(): execute(INSERT)` (ネスト 2 段、例外なし) | 正常終了後に行が見える (内側 RELEASE → 外側 COMMIT) | — | — |
| DB-9b | 外側 `immediate_transaction()` 内で内側ブロックが例外を上げ、外側で `except` して握りつぶして正常終了 | 内側の INSERT は消え (ROLLBACK TO)、外側で内側より前に行った INSERT は残る | — | — |
| DB-8 | 既存の `tests/test_auth_and_db.py` 全件 | 緑のまま (`dbm.verify(...) is None` 等は INSERT/SELECT の意味を変えない) | 緑 |

### VER / DEP

| # | 操作 | 期待 |
|---|---|---|
| V-1 | `import nexom; nexom.__version__` | `importlib.metadata.version("nexom")` と一致、正規表現 `^\d+\.\d+\.\d+` に合致、`"1.1.0"` ではない |
| V-2 | `pyproject.toml` の `version = "..."` を正規表現で読み、`nexom.__version__` と一致 (editable 再インストール後) | 一致。CI 的には `.venv/bin/pip install -e .` 後に走らせる |
| V-3 | `pyproject.toml` の `dependencies` | `gunicorn>=22.0.0`, `multipart>=1.3.1,<3`, `Pillow>=12.3.0` を含み、`gunicorn>=21.2` / `multipart>=1.3.0` / `Pillow>=10.0` を含まない |
| V-4 | `requires-python` | `>=3.10` のまま |
| V-5 | `grep -n naxom src/nexom/buildTools/run.py` | 0 件 |

## 7. テスト基盤

- フレームワーク: pytest。実行 `cd Muraki/projects/nexom; .venv/bin/python -m pytest -q`。ベースライン 32 passed / 1 xfailed → 本 doc 完了時の期待 **xfail 0**、`tests/test_parallel_storage.py` と `tests/test_version_and_log.py` を含めて全緑。
- 配置: `tests/test_parallel_storage.py` (全面書き換え、§6 PS-A〜F)、`tests/test_version_and_log.py` (新規、§6 LOG / DB / VER)。`tests/test_core.py` の `test_ps_arguments_error_message` は `PsArgmentsError("name")` を使うので不変。
- 画像フィクスチャは Pillow で生成 (`Image.new("RGB",(10,10))` → `save(buf, format=...)`)。bomb は `Image.new("1", (12000, 12000), 1)` を PNG 保存 (約 41 KB、実測)。ポリグロットは GIF バイト列 + `b"<script>alert(1)</script>"`。
- 1.1.41 スキーマの fixture (F-3): テスト内で `sqlite3` 直叩きで旧 `CREATE TABLE` (4.1 から `original_suffix` を除いた 11 列) を作って行を挿入する。
- アップロードヘルパ: `_upload(uploader, pid, filename, data, total_chunks)` を conftest ではなくテストファイル内に置く (他ファイルとの結合を作らない)。チャンク分割は `expected_chunk_size` と同じ規則 (`ceil(size/total)` 等分、最後が端数)。
- ファイル mode の assert は `stat.S_IMODE(os.stat(p).st_mode)`。macOS / Linux 共通。
- 役割: 既存 5 テストの書き換えと新規テストは **Reviewer** が書く。Developer はテストを書かない。実装中の Developer の緑確認は `-k "not parallel_storage"` で他ファイルのみ (既存 `test_parallel_storage.py` はシグネチャ変更で赤になるのが正常)。
- 既存テスト移行表:

| 既存テスト | 1.2.0 での扱い |
|---|---|
| `test_format_psc_filename_order` | 不変 (B-5) |
| `test_multipart_upload_and_commit` | `permission_id=None` を外す。チャンクを 8/10 → 9/9 に (E-9/E-10)。`min_chunk_size=1` を渡す。期待は E-19 |
| `test_parallel_storage_update_suffix` | `ps.update_suffix("pid", public_id, ".bin")` に。期待 B-3 |
| `test_parallel_storage_format_public_id` | `ps.format_psc_public_id(None, public_id, v=1, a=2)` に。期待 `name.endswith("__PSC_a-2_v-1.txt")` は不変 (`file.txt` は Documents で `.txt`) |
| `test_comp_img_webp` (xfail) | **xfail を外し** D-1 の形に書き直す (register → 10x10 PNG を 1 チャンクで parts_upload → commit → comp_img)。GREEN 後に `.knowledge/known-failures.md` の該当行を削除 (Leader) |

## 8. 移行ガイド (aisaba 側が 1.2.0 に上げる時)

### 8-1. 呼び出しパターンの置換

| ファイル | 現在 | 1.2.0 |
|---|---|---|
| `services/uploader/app/multiuploader.py:31` | `mpu.register(data["filename"], data["size"], session.pid, None, data["total_chunks"], data["sha256"])` | `mpu.register(data["filename"], data["size"], session.pid, data["total_chunks"], data["sha256"])`。`data["size"]` / `data["total_chunks"]` は `int(...)` で型を固定 (JSON が float / str で来ると `PsArgmentsError`) |
| `services/uploader/app/multiuploader.py:51` | `mpu.parts_upload(session.pid, form["public_id"], count, blob, form["sha256"])` | 不変。ただし新例外 (PS14/15/16/17、PS02) を HTTP に写像する `except NexomError as e` を handler に足す (§5.7 の表) |
| `services/aisaba_user/app/user_api.py:33` | `nps.comp_img(icon_psc, width=USER_DEFAULT_ICON_WIDTH, height=None, quality=None)` | `nps.comp_img(session.pid, icon_psc, width=USER_DEFAULT_ICON_WIDTH, height=None, quality=None)` — **他人の public_id を icon に設定して変換させる経路が閉じる** (現状は誰のでも通る) |
| `services/aisaba_user/app/user_api.py:27` | `nps.delete(session.pid, old_icon_psc)` | 不変 |
| `uc.aisaba.net` 配信サービス (port 62506、リポジトリ外) | 不明 (`format_psc_filename(cid, ".webp", width=W)` を手で組んでいる可能性) | `ps.format_psc_public_id(None, public_id, width=USER_DEFAULT_ICON_WIDTH)` を **必ず経由** する。生の `W` を渡す (丸めは関数内)。`width-<W>` を手で組むと丸め後の名前 (`width-384` 等) と一致せず 404 になる。既存キャッシュ (`width-<旧W>.webp`) は参照されなくなるので削除してよい |
| 同 | nginx `proxy_hide_header Content-Type` + `alias` | 1.2.0 以降の新規保存は allowlist 拡張子のみなので拡張子由来 Content-Type でも `text/html` / `image/svg+xml` は出ない。`psc_response_headers(meta)` を upstream で付ければ `Content-Disposition` / `nosniff` は nginx を通る (Content-Type は hide 設定のまま拡張子で決まる) |
| 全サービス `wsgi.py` の `AppLogger(...)` | 4 パス | 不変 (ローテーション既定 10 MiB × 5 が自動で効く。既存の巨大 `warning.log` は手で 1 回 truncate する) |

### 8-2. クライアント JS (`public/assets/app/appera/forNexom/uploader.js`)

- **要修正 (非互換)**: 現在の JS は 3 MiB 固定でスライスし `total_chunks = ceil(size / 3 MiB)` を送る。1.2.0 の規則は「`ceil(size / total_chunks)` で等分、最後が端数」なので、`size` が 3 MiB の倍数でない限りチャンク長が合わない (例: 4 MiB → `total_chunks = 2`、サーバー期待は 2 MiB + 2 MiB、JS は 3 MiB + 1 MiB を送り chunk0 で `PsChunkSizeMismatchError(2097152, 3145728)`)。
- 修正手順 (`uploader.js` の `upload()`): `total_chunks = calc_total_chunks(size, chunkSize)` の直後に `const sliceSize = Math.ceil(size / total_chunks);` を足し、ループの `start = i * chunkSize` / `end = Math.min(size, start + chunkSize)` を `sliceSize` に置き換える (`count` 0 始まりと最後の端数は既にこの規則と一致)。`sliceSize <= 3 MiB <= chunk_max_size` なので E-3 の上限にも掛からない。
- 100 MiB を超えるファイルは `PsUploadTooLargeError` (413 想定) になる。必要なら `MultiPartUploader(..., max_upload_size=...)` で引き上げる。

### 8-3. 設計上の注意 (capability モデル)

参照系に `pid=None` を渡すのは「public_id を知っている者は読める」宣言。user icon のように第三者に見せるものだけに使い、本人限定のファイルは `session.pid` を渡す。grep で `pid=None` / `(None, ` を監査できる。

### 8-4. 依存更新手順

```
# 各サービス venv で
pip install -U nexom            # 1.2.0 が gunicorn>=22 / multipart>=1.3.1,<3 / Pillow>=12.3 を引く
pip list | grep -i -E "gunicorn|pillow|multipart"
systemctl restart nexom@<service>
```

Python 3.10 の venv では Pillow 12.3.x、3.11 以上では 13.x が入る。`python-multipart` が同じ venv に入っていたら `pip uninstall python-multipart` (同名モジュール `multipart` で衝突)。

### 8-5. 横断効果

- 全 `DatabaseManager` 由来の SQLite (auth.db、`users/<pid>.db`、NPS_DB) が次回 open 時に 0600 になる。別 OS ユーザーで読んでいるツール (sqlite3 CLI 等) があれば所有者で実行する。
- `parallel_storage` の旧 `Images` 行で suffix が画像 4 種以外のものは `Binary` に落ちる (F-3)。該当があれば配信側で画像として出なくなる (意図どおり)。

### 8-6. Nexom リポジトリ側

- `CLAUDE.md`「PyPI へリリース」手順 1 を「`pyproject.toml` の version を上げる → `.venv/bin/pip install -e .` を再実行 (`__version__` は metadata 参照)」に置換。
- `.knowledge/known-failures.md` の xfail 行を削除 (GREEN 後)。
- ドキュメントサイト (`nexom.aisaba.net/documents/ParallelStorage`、aisaba 側 `nexom_web`) のシグネチャ更新は別タスク。

## 9. 他 doc への要求

1. **http doc (`app/request.py`)**: (a) `files()` の `ModuleNotFoundError` 文を `"multipart is required ... pip install multipart"` に (現状は別パッケージ `python-multipart` を案内、入れると壊れる)。(b) `isinstance(headers, dict)` は multipart 1.3.1 / 2.0.1 とも `Headers` 型なので常に False → `p.content_type` (両版に存在) を使う。(c) HTTP-02 の `MultipartParser(..., content_length=, partsize_limit=, disk_limit=, part_limit=)` は 1.3.1 / 2.0.1 で同じキーワード名 (確認済)。
2. **http doc (`assets/app/wsgi.py`)**: `logger.warn(str(e))` の 404 書き込みを access ログだけにする (DATA-12)。`sanitize_log_field` は `AppLogger._write` 内でも適用されるので、wsgi 側で path / UA に二重適用しても害は無い (エスケープ済み文字列の `\\` が再エスケープされることはない — バックスラッシュは対象外)。
3. **auth doc (`app/auth.py`)**: `AuthLogger` の既存 4 メソッドは不変、要求どおり `event(action, *, subject, ip=None, detail=None)` を追加 (§5.6、L-16a〜c)。`user_id` の改行は `_write` で潰れるので呼び出し側の前処理は不要。`AuthLogger(path)` のコンストラクタに `max_bytes` / `backup_count` キーワードが増える (位置引数は不変)。version の揃え方は §3.2。
4. **http doc (`__main__.py`)**: `prog="naxom"` の typo (DATA-15 Info)。
5. **DATA-09 を扱う doc**: `tests/test_templates_and_buildtools.py:43` の `MASTER_PASSWORD` 固定値 assert の反転はそちらで。本 doc はこのファイルを触らない。
6. **error.py 共有**: 本 doc は `# ParallelStorage` 節のみ。PS03 の重複クラスを 1 つ削るので、他 doc が `PsFileStatusInvalidError` を import していても名前は残る。

## 10. 不採用案

1. **参照系も所有者 pid を必須にする (`None` 不可)** — aisaba の user icon は閲覧者 ≠ 所有者で `uc.aisaba.net` から配信され、配信側は所有者の pid を持たない。必須にすると「公開ファイル」が作れない。`pid: str | None` を必須引数にして `None` を明示させる形で「暗黙の fail-open」だけを消した。
2. **`Pillow>=13.0.0`** — JPEG decode heap overflow (CVE-2026-112403) を塞げるが `requires-python >=3.11` になる。3.10 維持の裁定に従い 12.3.0。緩和として開けるフォーマットを 4 つに絞った。3.10 を切る時に上げる。
3. **`multipart` に上限を付けない** — 3.x が出た時に未検証 API で本番が壊れる。2.0.1 までは検証済なので `<3`。
4. **`permission_id` の最小実装 (共有権限)** — 参照ゼロ、要件が無い。空の権限機構は fail-open の温床なので API から外し、列は残置 (DROP COLUMN は SQLite 3.35 以降依存)。
5. **`update_status` を pid 付きで残す / `abort()` を新設** — アプリが `COMMITTED` を直接書けるのは commit の検証を迂回する穴。中止は `delete` で足りる (行・ファイル・作業ディレクトリを一括で消す) ので削除。
6. **pid 別の総量クォータ (コミット済み合計)** — 上限値はプラン・用途で決まるアプリ側ポリシーで、フレームワーク既定を置くと Bloom 等で必ず上書きされる。未完了分だけ `max_active_uploads_per_pid × max_upload_size` で束ねた。アプリは `SELECT SUM(size) ... WHERE pid=?` で足せる。
7. **`total_chunks == ceil(size / chunk_max_size)` の厳密一致 (Researcher 案)** — クライアントは 10 MiB 未満のチャンク (aisaba は 3 MiB) を選べる前提なので不成立。「等分 + 最後が端数」の規則で 1 セッションのディスク使用を `size` に固定した。
8. **contents / ログの 0600・run.py の umask 027** — aisaba の nginx は `alias` で contents を直読み (`gateway/user-contents.conf`)。0640 / 0600 にすると配信が 403 になる。DB と作業ディレクトリだけを締めた。
9. **ローテーションを自前実装 / ログを JSON 1 行に** — stdlib `RotatingFileHandler` で足りる。JSON 化は既存の行形式を読んでいる運用 (grep) を壊すので、行形式を維持してエスケープのみ。
10. **キャッシュ変種を無制限のまま、ファイル数上限だけ付ける** — 攻撃者が上限分を無意味なサイズで埋めると正規サイズが作れなくなる。プリセット丸め (11 寸法 × 4 品質) で変種の全体数を有界にした。
11. **AVIF / HEIC を Images に含める** — Pillow 本体の AVIF は 11.2 以降かつ wheel 依存、HEIC は別パッケージ (pillow-heif)。1.2.0 は 4 形式に限定し、iPhone の HEIC はクライアント側で JPEG 化する前提 (Bloom は Flutter 側で変換)。
12. **`convert("RGBA")` で透過を保つ** — 既存は `RGB` で透過を落としており、変更すると既存キャッシュと見た目が変わる。本 doc の範囲外。
13. **移行で既存ファイルを改名 (旧 `Images` 行の `.svg` 等を `.bin` に)** — DB と FS を同時に触る migration は失敗時の整合が取れない。`types` を `Binary` に落とすだけにし、配信側の判断材料を正す。

## 11. 残リスク

1. 旧版で保存済みの `.svg` / `.html` 名のファイルは FS 上そのまま。`uc.aisaba.net` は拡張子で Content-Type を決めるので、旧ファイルを public_id 経由で引ける経路が残っていれば格納型 XSS は残る。対処は運用: `SELECT contents_id, suffix FROM parallel_storage WHERE lower(suffix) IN ('.svg','.html','.htm','.xhtml','.xml','.js')` で棚卸しして手で削除 (§8-5)。
2. 旧版で `Images` + `.jpg` として保存されたポリグロットは、1.2.0 でも `Images` のまま (中身を開かずに判定できない)。配信は `image/jpeg` なのでブラウザは HTML として実行しないが、`comp_img` の原本として読まれる。`comp_img` 側のピクセル上限とフォーマット allowlist で DoS は塞がる。
3. ログローテーションのマルチプロセス境界で数行が失われ得る (§6 LOG 実装メモ)。
