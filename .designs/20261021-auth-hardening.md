# Nexom 1.2.0 認証・セッション強化 (auth-hardening)

- 対象リポジトリ: `Muraki/projects/nexom` (main 6b63cd5 = PyPI 1.1.41 と同期)
- 版: **1.2.0** (互換性を壊す。既定は安全側 = opt-out)
- 根拠: `.knowledge/security-audit-20261021/A-auth.md` (AUTH-01〜21)、同 `B-http.md` (HTTP-07/08/10/11)、同 `C-data.md` (DATA-09/10/11)、外部診断 `cyber-security-agent/reports/aisaba-nexom-20261012.md` (「既定の管理操作用補助パスワード」= AUTH-01)
- 並列 doc: `20261021-http-hardening.md` (Cookie / 自動エスケープ / プロキシ信頼 / build.py CLI)、`20261021-storage-deps-hardening.md` (ParallelStorage / db.py / core/log.py / pyproject)

## 0. スコープ境界 (並列 3 doc)

| 区分 | ファイル | 備考 |
|---|---|---|
| **本 doc 専属** | `src/nexom/app/auth.py`, `src/nexom/app/user.py`, `src/nexom/templates/auth.py`, `src/nexom/assets/auth/{config,wsgi,gunicorn.conf}.py`, `src/nexom/assets/auth_page/{login,signup}.html`, `tests/test_auth_and_db.py` | |
| **例外的に触る** | `src/nexom/core/error.py` の Auth 節 (`class AuthMissingFieldError` 〜 `_status_for_auth_error`、現 258-329 行) | A11/A12/A13 追加と `field` 属性。http doc が同ファイルの別節 (HTTP 系) を触る可能性あり → 節が違うので textual conflict なし |
| 例外的に触る | `tests/conftest.py` `make_environ` に `"REMOTE_ADDR": "127.0.0.1"` を 1 キー追加 | loopback ガード (§5 G) のため。`tests/test_http_hardening.py` の Q19 / X09 / X12 は REMOTE_ADDR 無しを前提にしているので、同 3 テストは `env.pop("REMOTE_ADDR")` で明示的に外す (§9.1) |
| 例外的に触る | `tests/test_templates_and_buildtools.py` 39-43 行の `cfg` アサーション | `MASTER_PASSWORD` 定数の固定を反転。http doc が同ファイルの CLI 既定テストを触るなら別関数 |
| **触らない** | `app/cookie.py`, `app/request.py`, `app/response.py`, `app/path.py`, `app/middleware.py`, `core/object_html_render.py`, `assets/app/**`, `buildTools/build.py`, `__main__.py` | http doc |
| 触らない | `app/parallel_storage.py`, `app/db.py`, `core/log.py`, `pyproject.toml`, `src/nexom/__init__.py` (`__version__`) | storage doc (版番号 1.2.0 の記入も storage doc) |

### 0.1 他 doc の契約を利用する箇所 (本 doc は利用側)

| 契約 | 提供 doc | 本 doc での使い方 | 本 doc から提供側への要求 (§12 再掲) |
|---|---|---|---|
| `Cookie(name, value, *, max_age: int \| None, expires, path="/", domain, secure=True, http_only=True, same_site="Lax")` + 削除ヘルパ (Max-Age=0) | http | `_nxt` の発行・削除 (§5 K) | 削除ヘルパの名称を `Cookie.delete(name, *, path="/", domain=None) -> Cookie` と仮称。異なる名で確定したら本 doc の K-2 をその名に読み替える |
| 自動エスケープ (`Markup`/`Raw` 相当だけ素通し、レンダ済み出力は Raw 扱い) | http | `templates/auth.py` のスロット表 (§6.3) | なし (全スロットがユーザ入力でない) |
| プロキシ信頼 (bind 既定 127.0.0.1、XFF は信頼プロキシ設定時のみ) | http | AuthPages が末端クライアント IP を得る手段、auth 雛形の access ログ IP (`client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)`、§6.2) | **`Request.client_ip: str` (解決済み末端 IP) を Request に載せること**。無いと AuthPages のレート制限 IP 軸が「アプリサーバーの 127.0.0.1」1 バケツに潰れる (§5 L-3) |
| `sanitize_log_field(s: str) -> str` (`nexom.core.log`) | storage | AuthLogger に渡す subject/detail を全て通す (§8) | **`AuthLogger.event(action: str, *, subject: str, ip: str \| None = None, detail: str \| None = None) -> None` を追加**し行形式 `[ts] [ACTION] subject=.. ip=.. detail=..` (detail 省略時は従来形式)。既存 4 メソッドは維持 |

## 1. 目的

一般ユーザー受け入れ (Bloom 等) の前に、AuthService / AuthClient / auth 雛形の既定を「到達できれば誰でも・何回でも・何でも」から「loopback の信頼済みアプリだけ・回数制限つき・形式検証つき」へ反転する。固定補助パスワード (AUTH-01/DATA-09) と列挙オラクル (AUTH-06) を消し、監査ログ (AUTH-11) を実際に書く。

## 2. 現状 (Researcher 実測) と対応表

| ID | 現状 (1.1.41、[実測] は A-auth.md) | 1.2.0 | 節 |
|---|---|---|---|
| AUTH-01 / DATA-09 | `master_password="NexomWebFramework"` が auth.py:185 と雛形 config:19 に固定、`!=` 比較 | **定数の第 2 パスワードを廃止**。master の破壊的操作は master 自身の login password の再入力 (PBKDF2 検証、compare_digest) に置換。`AuthService.__init__` から `master_password` 引数を削除、雛形 config から `MASTER_PASSWORD` 行を削除 | §4.2, §5 M |
| AUTH-02 | `Cookie(..., MaxAge=sess.expires_at)` → 属性名無効・絶対 epoch [実測: `MaxAge=1761000000`] | `max_age=expires_at - now` (相対秒) で発行、削除は Max-Age=0 ヘルパ | §5 K |
| AUTH-03 | `_nxt` に SameSite なし | `same_site="Lax"` (Cookie 契約の既定)。state-changing POST は同一オリジン検査 `is_same_origin()` を補助に | §5 K, §5 X |
| AUTH-04 | レート制限・ロックアウト皆無。[実測] 誤 pw 1 回 ≈ 0.04-0.05 s CPU、sync worker 4 → 毎秒 100 弱で飽和、verify が timeout → 全ページ 500 | 2 軸 (IP / アカウント) の固定窓カウンタ + ロック (SQLite `auth_attempts`、**ハッシュ前に試行枠を予約**して閾値を厳密上限に)、**プロセス内の時間ベース PBKDF2 ゲージ** (直近 1 秒窓の実測 hash 時間が 50% を超えたら 429) で login が verify を道連れにしない。安い検査を PBKDF2 の前に置く。再認証経路 (`update/password`, master 操作) も同じロック・ゲージ・長さ上限を通る | §5 L, S, H, M |
| AUTH-05 | `password="1"` で 201、`user_id="<img src=x onerror=alert(1)>"` で 201 [実測] | `AuthPolicy` で user_id 正規表現 / public_name 長さ・禁止文字 / password 最小 8 文字・最大 256 byte。**新規登録と変更時のみ**適用 (既存行は免除)。login / 再認証は DoS 上限 (1024 文字 / 1024 byte) だけ | §4.1, §5 S, L-5 |
| AUTH-06 | 無認証 `resolve/pid` が存在確認 + pid を返す。login は未知 0.0001 s / 既知誤 pw 0.05 s [実測 500 倍]。無効化済は pw 不問で A04 | `resolve/pid` **削除** (404)。未知ユーザーでもダミー PBKDF2。`is_active` 判定はパスワード一致の**後** | §5 L-6〜L-8, T-1 |
| AUTH-07 / DATA-10 / HTTP-07 | AuthService に呼び出し元検査なし。`create-auth` 既定 0.0.0.0 | `AuthService(allowed_clients=("127.0.0.1","::1"))` の REMOTE_ADDR ガード (403 A13)。CLI 既定は http doc。雛形 config に `ALLOWED_CLIENTS` / `TRUSTED_PROXY_COUNT` (auth は既定 0) | §5 G, §6 |
| AUTH-08 | 任意ユーザーが任意 group_id を先取り、`group/auth` が非メンバーにも level を返す | `group/auth` は「自分の pid」または「自分がその group の level ≥ 1 のメンバー」のときだけ応答、他は A13。group_id / name に形式検証。**先取り自体は許容** (§11 不採用案 N-6) | §5 P |
| AUTH-09 | `level: true` が int 扱いで 1 保存 [実測] | `bool` を A12 で拒否 | §5 P-3 |
| AUTH-10 | master が自分を deactivate → 回復不能 [実測] | target == master → A13。起動時 `ensure_master_user` が `is_active=1, is_master=1` を自己修復。`master/users/activate` 追加 | §5 M |
| AUTH-11 / DATA-11 | `AuthLogger` 生成のみ、一度も呼ばれない。例外は `e` を捨てる | 全イベントを記録 (§8 の表)。subject は `sanitize_log_field` 経由。`except Exception` は traceback を error ログに | §8 |
| AUTH-12 | 雛形 `auth/wsgi.py` の except で `NameError`、`start_response` 未呼出 [実測] | `assets/app/wsgi.py` と同構造へ書き直し。`AuthService.handler` は `Request(environ)` を try 内に | §6.2, §5 W |
| AUTH-13 | AuthPages login 応答 body に `token` 同梱 | body から `token` を外す (`login.html` は未使用を確認済) | §5 K-4 |
| AUTH-14 / HTTP-11 | logout が GET + Referer リダイレクト | **POST のみ** (GET は 405 + `Allow: POST`)。リダイレクト先は固定 `/` (form POST 時のみ)、JSON 時は `{"ok": true}` | §5 O |
| AUTH-16 | PBKDF2 200,000 回、素 hex 列 | 600,000 回 ([本機実測] 200k=48.9 ms / 600k=123.7 ms)。`pbkdf2_sha256$<iter>$<salt>$<dk>` 形式、ログイン成功時に透過的再ハッシュ | §3.2, §5 H |
| AUTH-17 | sessions 行が無限蓄積 | login ごとに期限切れ・revoked 行を DELETE、1 ユーザー最大 20 セッション | §5 L-11 |
| AUTH-18 | `UserDatabaseManager` が pid を無検証でファイル名に | `[A-Za-z0-9_-]{16,64}` + `users_dir` 配下検査 | §5 U |
| AUTH-19 | master 判定が文字列比較、`is_master` 未使用、`created_at` NULL | `is_master=1` で判定、INSERT を列名指定にして `created_at` DEFAULT を効かせる | §3, §5 M-1 |
| AUTH-20 | `_ip()` が XFF 先頭を無条件信用 | 雛形はローカル `_ip()` を持たず、http doc §14.6 の `client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)` を呼ぶ (auth は既定 0 = XFF を見ない) | §6.2 |
| AUTH-21 | AuthClient: 必須キー欠落で `KeyError`、redirect 追従、`None` → `"None"` | 欠落/型不正 → A09、3xx を追従しない、`user_agent` は `None` を保つ | §5 C |

## 3. データモデル

### 3.1 スキーマ v2 (SQLite、`AuthDBM._init`)

```sql
-- 既存 (変更なし。INSERT は列名指定に変える → created_at に DEFAULT が効く)
CREATE TABLE IF NOT EXISTS users (
    uid TEXT PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    public_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,          -- v2: 'pbkdf2_sha256$<iter>$<salt_hex>$<dk_hex>'。'$' を含まない行は legacy (hex dk、salt は password_salt、200000 回)
    password_salt TEXT NOT NULL,          -- v2 の新規行は '' (NOT NULL は維持)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_master INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_user_id_nocase ON users(user_id COLLATE NOCASE);   -- v2 新規 (signup の大小文字衝突検査用、非 UNIQUE)

CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    uid TEXT NOT NULL REFERENCES users(uid),
    token_hash TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    user_agent TEXT,
    created_at INTEGER NOT NULL DEFAULT 0  -- v2 新規列 (epoch 秒)。legacy 行は 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid);                          -- v2 新規

-- permission_groups / permission_group_members: 変更なし

-- v2 新規
CREATE TABLE IF NOT EXISTS auth_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);                                        -- ('schema_version', '2')

CREATE TABLE IF NOT EXISTS auth_attempts (
    key          TEXT PRIMARY KEY,        -- 'login_user:<user_id>' | 'login_ip:<ip>' | 'signup_ip:<ip>'
    count        INTEGER NOT NULL,
    window_start INTEGER NOT NULL,        -- epoch 秒
    locked_until INTEGER                  -- NULL = 未ロック
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_window ON auth_attempts(window_start);
```

### 3.2 パスワードハッシュ形式

| 形式 | 例 | 判定 |
|---|---|---|
| v2 | `pbkdf2_sha256$600000$2dc5c53cad983c25eea99ece8663a88d$c205e6…820bdc` (118 文字) | `password_hash` に `$` を含む。`split("$")` で 4 要素、`[0]=="pbkdf2_sha256"`、`[1]` は int |
| legacy (1.1.x) | `password_hash` = 64 文字 hex、`password_salt` = 32 文字 hex | `$` を含まない。反復 200,000 固定 |

`needs_rehash = legacy or iterations != policy.pbkdf2_iterations`。照合成功後のセッション発行と再ハッシュは **1 つの `BEGIN IMMEDIATE` トランザクション** (`_issue_session_tx`) で行う: ① `SELECT password_hash, password_salt FROM users WHERE uid=?` を再読 ② 照合時に使った値と**両方一致**するときだけ ③ (`needs_rehash` なら) `UPDATE users SET password_hash=?, password_salt='' WHERE uid=?` ④ `INSERT INTO sessions …` ⑤ COMMIT。②で不一致 (照合と tx の間に別接続の `update_password` が完了した) なら ROLLBACK して **`AuthInvalidCredentialsError` (A03)** — 旧パスワードの照合結果から token を出さない (L-18b)。`DatabaseManager` は文単位 auto-commit なので、tx 中は `self.auto_commit=False` にして `execute("BEGIN IMMEDIATE")` … `commit()`、`finally` で復元 (例外時は `rollback()`)。PBKDF2 は tx の外で終えているので DB を握るのは SELECT + UPDATE + INSERT の間だけ。

### 3.3 マイグレーション (既存 SQLite を 1.2.0 で開いたとき)

`AuthDBM._init()` が毎起動時に冪等に実行 (他プロセス/他 worker との同時実行は WAL + `busy_timeout=3000` で直列化、全文が `IF NOT EXISTS` / 存在検査つき):

1. `CREATE TABLE IF NOT EXISTS` を全テーブル分 (users / sessions / permission_groups / permission_group_members / auth_meta / auth_attempts)
2. `SELECT value FROM auth_meta WHERE key='schema_version'` → 行なし = 1
3. version < 2 のとき:
   - `SELECT name FROM pragma_table_info('sessions')` に `created_at` が無ければ `ALTER TABLE sessions ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`
   - `CREATE INDEX IF NOT EXISTS idx_users_user_id_nocase …`, `idx_sessions_uid …`, `idx_auth_attempts_window …`
   - `INSERT INTO auth_meta(key, value) VALUES('schema_version','2') ON CONFLICT(key) DO UPDATE SET value='2'`
4. `ensure_master_user` (§5 M-1)

`DatabaseManager.execute` は `SELECT` で始まる文だけ fetch する (`db.py:114`) ので、PRAGMA は `SELECT … FROM pragma_table_info(...)` の形で読む。`users.password_salt` 列は削除しない (SQLite の DROP COLUMN は 3.35+、既存 venv の sqlite 版を仮定しない)。ユーザーのパスワードは**ログイン成功時に 1 人ずつ** v2 形式へ書き換わる (§5 H)。一括再ハッシュは不可能 (平文が無い)。

## 4. API / 関数シグネチャ

### 4.1 `AuthPolicy` (新規、`nexom.app.auth`)

```python
@dataclass(frozen=True)
class AuthPolicy:
    # ハッシュ
    pbkdf2_iterations: int = 600_000
    # フィールド形式
    user_id_pattern: str = r"[a-z0-9][a-z0-9_.-]{2,31}"   # re.fullmatch。3〜32 文字、小文字英数で始まる
    user_id_max_len: int = 32                            # pattern の上限と揃える (validate_user_id は両方を検査)
    public_name_max_len: int = 64                        # NFC 正規化 + strip 後のコードポイント数。最小は 1
    password_min_len: int = 8                            # コードポイント数
    password_max_bytes: int = 256                        # UTF-8 バイト数
    # login / reauth の DoS 上限 (形式は見ない。既存行をログイン不能にしないため signup ポリシーより緩い) — フィールドでなく導出 property:
    #   @property login_user_id_max_len   -> max(1024, self.user_id_max_len)        # 既定 1024
    #   @property login_password_max_bytes -> max(1024, self.password_max_bytes)    # 既定 1024
    # (AuthPolicy(password_max_bytes=2048) で登録できる pw が login で A12 になる矛盾を防ぐ。既定値では 1024 のまま)
    group_id_pattern: str = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}"
    # アカウント軸ロック (login_user:<user_id>)
    account_lock_threshold: int = 5
    account_window_sec: int = 900
    account_lock_sec: int = 900
    # IP 軸 (login_ip:<ip>) — 失敗のみ数える
    ip_fail_threshold: int = 30
    ip_window_sec: int = 900
    ip_lock_sec: int = 900
    # signup IP 軸 (signup_ip:<ip>) — 成否を問わず数える
    signup_ip_threshold: int = 10
    signup_window_sec: int = 3600
    signup_lock_sec: int = 3600
    # PBKDF2 ゲージ (プロセス内、時間ベース)
    hash_busy_ratio: float | None = 0.5                  # 直近 hash_window_sec に PBKDF2 へ費やした実測 wall time の上限比。None = ゲージ無効 (テスト用)、0.0 = 窓あたり 1 回だけ
    hash_window_sec: float = 1.0
    # セッション
    max_sessions_per_user: int = 20
```

数値の根拠: アカウント 5 回/15 分は NIST SP 800-63B の「100 回未満」より厳しめ、NAT 共有 IP を想定して IP 軸は失敗 30 回/15 分 (成功は数えない)。signup 10 回/時/IP は列挙 (A02) と大量作成の両方を絞る。

**PBKDF2 ゲージの論証** (測定環境に依存しない形): worker プロセスは `time.perf_counter` で各 PBKDF2 の所要時間を記録し (`deque[(end, duration)]`)、新しいハッシュの前に「`now - hash_window_sec` より後に終わったハッシュの duration 合計」が `hash_busy_ratio × hash_window_sec` (既定 500 ms) を超えていれば 429 を返してハッシュしない。gunicorn sync worker は 1 プロセス 1 要求なので、(a) verify 要求が待つ最悪値は「いま走っている 1 ハッシュ分」(600k で本機 ≈ 125 ms、遅い機械でもハッシュ 1 回分) に有界、(b) どの 1 秒窓でも worker がハッシュに使える時間は 500 ms + 超過 1 回分 以下で、残りが verify に回る。ハッシュの実コストが機械で変わっても比率で効くので、`123.7 ms × 4 回/s` のような測定値を定数に焼かない。本機では 600k ≈ 124 ms → 実効 4 hash/s/worker、既定 4 worker で 16 hash/s。ダミーハッシュ (L-6) もゲージに計上する。

### 4.2 `AuthService`

```python
class AuthService:
    def __init__(
        self,
        db_path: str,
        log_path: str,
        *,
        ttl_sec: int = 60 * 60 * 24 * 7,
        master_user: str = "master_user",
        master_login_password: str = "",
        prefix: str = "",
        allowed_clients: tuple[str, ...] | None = ("127.0.0.1", "::1"),   # None = ガード無効 (opt-out)
        policy: AuthPolicy = AuthPolicy(),
        clock: Callable[[], int] = _now,                                   # テストで時刻を差し替える
    ) -> None: ...
    # 削除: master_password (渡すと TypeError。1.1.x 呼び出しは起動時に落ちる = 明示的)
    # __init__ の順序: AuthDBM(db_path) を開く → ensure_master_user (M-1〜M-3) → Router 構築 → _hash_log クリア。
    # ensure_master_user / マイグレーションが例外を投げたら self.dbm.rip_connection() で SQLite 接続を閉じてから同じ例外を再送出する
    # (起動失敗時に接続を抱えたまま落ちない。gunicorn の再試行ごとに WAL ハンドルが積まれるのを防ぐ)

    def handler(self, environ: dict) -> JsonResponse: ...
```

ルート表 (prefix 配下、全て POST。GET 等は 405 `{"ok": false, "error": "MethodNotAllowed"}` 変更なし):

| path | body | 変更 |
|---|---|---|
| `signup` | `{user_id, public_name, password, client_ip}` | `client_ip` 必須 |
| `login` | `{user_id, password, client_ip, user_agent?}` | `client_ip` 必須、`user_agent` は body 優先 (無ければ HTTP ヘッダ) |
| `logout` | `{token, client_ip?}` | ログ用に `client_ip` 任意 |
| `verify` | `{token}` | 変更なし |
| ~~`resolve/pid`~~ | — | **削除** (404) |
| `convert/pid`, `convert/user-id` | `{token, user_id}` / `{token, pid}` | 変更なし |
| `update/public-name` | `{token, public_name}` | 形式検証 |
| `update/password` | `{token, current_password, new_password, client_ip}` | `client_ip` 必須。再認証は login と同じロック・ゲージ・長さ上限 (§5 H) |
| `permissions/group/create` | `{token, group_id, name}` | 形式検証 |
| `permissions/group/delete` | `{token, group_id}` | level≠100 → A13 |
| `permissions/group/member/upsert` | `{token, group_id, user_id, level}` | bool 拒否、非 owner → A13 |
| `permissions/group/member/delete` | `{token, group_id, user_id}` | 非 owner → A13 |
| `permissions/group/auth` | `{token, group_id, pid}` | 自分 or メンバーのみ |
| `permissions/groups/mine` | `{token}` | 変更なし |
| `master/users/list` | `{token}` | is_master 判定、非 master → A13 |
| `master/users/deactivate` | `{token, target_user_id, login_password, client_ip}` | `master_password` → `login_password` (master 自身の login password)。`client_ip` 必須。再認証は login と同じロック・ゲージ (§5 M) |
| `master/users/activate` | `{token, target_user_id, login_password, client_ip}` | **新規** |

handler の処理順序 (固定) と共通応答:

1. **`allowed_clients` ガード** — `environ["REMOTE_ADDR"]` だけで判定する (`Request` はまだ作らない。XFF は見ない)。不通過 → 403 `{"ok": false, "error": "A13"}`
2. **`Request(environ)` 構築** — try 内。`ValueError` (不正な `CONTENT_LENGTH`、10 MB 超) → 400 `{"ok": false, "error": "A01", "field": "body"}`。その他の例外 (不正 Cookie ヘッダ等) → 下記 500 経路
3. **ルーティング + handler** — 以下の共通応答:
   - 成功: 各エンドポイントの JSON (status 200、signup は 201)
   - `NexomError` (Auth 系): `{"ok": false, "error": "<code>"}` + エラーが `field` 属性を持つ (A01 / A12) なら `"field": "<name>"`。status は `_status_for_auth_error`
   - `PathNotFoundError`: 404 `{"ok": false, "error": "NotFound"}`
   - body が JSON でない / 不正 JSON / JSON object 以外: 400 `{"ok": false, "error": "A01", "field": "body"}`
   - その他 `Exception` (2. の非 ValueError を含む): 500 `{"ok": false, "error": "InternalError"}`、traceback を `AuthLogger.event("INTERNAL_ERROR", subject=<PATH_INFO>, detail=<type(e).__name__>)` と `AppLogger` (雛形側) に

全経路で `JsonResponse` を返す (handler から例外は漏れない)。雛形 wsgi (§6.2) の `except Exception` は handler 自体のバグに対する最終防衛。

### 4.3 `AuthDBM(DatabaseManager)`

```python
class AuthDBM(DatabaseManager):
    SCHEMA_VERSION = 2
    def __init__(self, db_path: str, *, policy: AuthPolicy = AuthPolicy(), clock: Callable[[], int] = _now,
                 logger: AuthLogger | None = None) -> None: ...
    # 注意: DatabaseManager.__init__ が _init() を呼ぶので policy/clock/logger/_hash_log (ゲージの deque) は super().__init__ の前に代入する

    def signup(self, user_id: str, public_name: str, password: str, *, client_ip: str) -> None
    def login(self, user_id: str, password: str, *, client_ip: str, user_agent: str | None, ttl_sec: int) -> LocalSession
    def logout(self, token: str, *, client_ip: str | None = None) -> None
    def verify(self, token: str | None) -> LocalSession | None
    def ensure_master_user(self, *, user_id: str, login_password: str) -> None
    def update_public_name(self, *, uid: str, public_name: str) -> None
    def update_password(self, *, uid: str, current_password: str, new_password: str, client_ip: str) -> None
    def reauth(self, *, uid: str, password: str, client_ip: str) -> None   # 新規: パスワード再入力の照合。login と同じ順序 (長さ上限 → ロック確認 → ゲージ → 予約 → PBKDF2)。不一致は AuthInvalidCredentialsError、ロック中/ゲージ超過は AuthTooManyAttemptsError。update_password と master 操作が共用
    def activate_user(self, user_id: str) -> None                 # 新規
    def deactivate_user(self, user_id: str) -> None
    def is_master_uid(self, uid: str) -> bool                     # 新規: users.is_master=1
    # permissions: 既存メソッド名は維持。例外コードだけ §5 P のとおり変更
    # 内部
    def _migrate(self) -> None
    def _hash_password(self, password: str) -> str                # v2 形式を返す (salt は毎回 secrets.token_hex(16))
    def _verify_password(self, password: str, password_hash: str, password_salt: str) -> tuple[bool, bool]   # (ok, needs_rehash)
    def _issue_session_tx(self, *, uid: str, password: str, seen_hash: str, seen_salt: str, needs_rehash: bool,
                          ttl_sec: int, user_agent: str | None) -> LocalSession   # BEGIN IMMEDIATE → users 再読 → (seen_hash, seen_salt) と一致なら [再ハッシュ UPDATE] + sessions INSERT → COMMIT。不一致なら ROLLBACK して AuthInvalidCredentialsError (§3.2, L-18b)
    def _dummy_verify(self, password: str) -> None                # 未知ユーザー用。モジュール定数 _DUMMY_SALT (import 時 secrets.token_bytes(16)) で policy.pbkdf2_iterations 回
    def _gauge_check(self) -> None                                # 直近窓の hash 時間合計 > ratio × window なら AuthTooManyAttemptsError (DB 無変更)
    def _timed_hash(self, fn: Callable[[], T]) -> T               # perf_counter で測って deque に (end, duration) を積む。全 PBKDF2 呼び出しはこれを通す
    def _check_locked(self, key: str) -> None                     # locked_until > now なら AuthTooManyAttemptsError (DB 無変更)
    def _reserve(self, key: str, *, threshold: int, window_sec: int) -> int   # 試行枠の予約: 窓判定つき UPSERT で count+1 → SELECT count。返り値 > threshold なら呼び出し側が _release して A11
    def _release(self, key: str) -> None                          # count-1。count<=0 かつ locked_until IS NULL の行は DELETE
    def _lock(self, key: str, *, lock_sec: int) -> None           # locked_until = now + lock_sec
    def _reset(self, key: str) -> None                            # 行削除 (アカウント軸の成功時)
    def _sweep_attempts(self) -> None
    def _sweep_sessions(self, uid: str) -> None
```

### 4.4 ユーティリティ (モジュール関数、`nexom.app.auth`)

```python
def validate_user_id(user_id: str, policy: AuthPolicy) -> str          # strip 済みを返す。不一致 → AuthInvalidFieldError("user_id")
def validate_public_name(name: str, policy: AuthPolicy) -> str         # NFC + strip。空 → AuthMissingFieldError("public_name")、違反 → AuthInvalidFieldError("public_name")
def validate_password(password: str, policy: AuthPolicy, *, field: str = "password") -> str   # 違反 → AuthInvalidFieldError(field)
def validate_group_id(group_id: str, policy: AuthPolicy) -> str
def normalize_ip(value: str) -> str                                     # ipaddress.ip_address(value) を str 化。失敗 → AuthInvalidFieldError("client_ip")
def is_same_origin(request: Request) -> bool                            # §5 X
```

### 4.5 `AuthClient`

```python
class AuthClient:
    def __init__(self, auth_url: str, *, timeout: float = 3.0) -> None
    def signup(self, *, user_id: str, public_name: str, password: str, client_ip: str) -> None
    def login(self, *, user_id: str, password: str, client_ip: str, user_agent: str | None = None) -> Session
    def logout(self, *, token: str, client_ip: str | None = None) -> None
    def verify_token(self, token: str) -> Session | None
    def update_public_name(self, *, token: str, public_name: str) -> str
    def update_password(self, *, token: str, current_password: str, new_password: str, client_ip: str) -> None
    def convert_pid(self, *, token: str, user_id: str) -> str
    def convert_user_id(self, *, token: str, pid: str) -> str
    # 削除: resolve_pid
    def create_permission_group(self, *, token: str, group_id: str, name: str) -> str
    def delete_permission_group(self, *, token: str, group_id: str) -> None
    def permissions(self, group_id: str, *, token: str) -> Permissions
    def master_users_list(self, *, token: str) -> list[dict]
    def master_users_deactivate(self, *, token: str, target_user_id: str, login_password: str, client_ip: str) -> None   # master_password → login_password、client_ip 追加
    def master_users_activate(self, *, token: str, target_user_id: str, login_password: str, client_ip: str) -> None     # 新規
    def _post(self, url: str, body: dict) -> dict
    def _raise_from_error_code(self, code: str, field: str | None = None) -> NoReturn
```

`Session` dataclass は不変 (`user_agent: str | None`)。`Permissions` のメソッドは不変 (エラー変換のみ A11-13 追加)。

### 4.6 `templates/auth.py`

```python
class AuthPages(Path):
    def __init__(self, path: str, auth_server: str, *,
                 login_path: str = "login/", signup_path: str = "signup/", logout_path: str = "logout/",
                 client_ip: Callable[[Request], str] | None = None,
                 logger: AppLogger | None = None) -> None
    # client_ip=None → req.client_ip (http doc のプロキシ信頼契約)。テストや独自配線は callable を渡す
    # logger は LogoutPage に渡す (K-6b の `logout revoke failed: A09` warn 用)。None なら warn を出さない (他の挙動は不変)
class LoginPage(Path):  def __init__(self, path: str, auth_server: str, *, client_ip: Callable[[Request], str] | None = None)
class SignupPage(Path): 同上
class LogoutPage(Path): def __init__(self, path: str, auth_server: str, *, client_ip: Callable[[Request], str] | None = None,
                                     logger: AppLogger | None = None)
```

### 4.7 `core/error.py` Auth 節 (追加分)

```python
class AuthMissingFieldError(NexomError):      # 既存。self.field = key を追加
class AuthTooManyAttemptsError(NexomError):   # A11 "Too many attempts. Try again later."
class AuthInvalidFieldError(NexomError):      # A12 f"Invalid field. '{key}'"、self.field = key
class AuthForbiddenError(NexomError):         # A13 "Forbidden."
# _status_for_auth_error: "A11": 429, "A12": 400, "A13": 403 を追加。既定 400 は維持
```

### 4.8 `app/user.py`

```python
_PID_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")
class UserDatabaseManager(DatabaseManager):
    def __init__(self, users_dir: str, pid: str, auto_commit: bool = True) -> None
    # _PID_RE.fullmatch(pid) でなければ AuthInvalidFieldError("pid")
    # (Path(users_dir) / f"{pid}.db").resolve() が Path(users_dir).resolve() の配下 (is_relative_to) でなければ AuthInvalidFieldError("pid")
```

## 5. 挙動仕様

記法: 入力 → 期待 (status / body / DB / ログ)。`now` は `clock()`。全エンドポイントは `REMOTE_ADDR` が `allowed_clients` に含まれる前提 (G 系で別掲)。「現状」は 1.1.41 の実測。

### G. 呼び出し元ガード (AuthService.handler)

| # | 条件 | 期待 |
|---|---|---|
| G-1 | `environ["REMOTE_ADDR"]="127.0.0.1"`、既定 `allowed_clients` | ルーティングへ進む |
| G-2 | `REMOTE_ADDR="::1"` | 進む |
| G-3 | `REMOTE_ADDR="10.0.0.5"`、既定 | 403 `{"ok": false, "error": "A13"}`。ログ `FORBIDDEN_CLIENT subject=10.0.0.5`。DB 無変更 |
| G-4 | `REMOTE_ADDR` 無し | 403 A13 (fail-closed)。ログ subject=`-` |
| G-5 | `REMOTE_ADDR="not-an-ip"` | 403 A13 |
| G-6 | `allowed_clients=("10.0.0.5",)`、`REMOTE_ADDR="10.0.0.5"` | 進む。`"127.0.0.1"` は 403 (既定を上書きしたので loopback も明示が要る) |
| G-7 | `allowed_clients=None` | 全アドレス進む (ガード無効。コンテナ間通信向け opt-out) |
| G-8 | ガードは `prefix` の内外を問わず全パス (404 になるパスも) に先行して適用 | 未知パス + 外部 IP → 403 (404 でない) |

### L. login (`POST /login`)

前提フィクスチャ: `alice` (password `correct-horse-8`, v2 hash)、`legacy_bob` (1.1.x 形式: hex hash + salt、password `legacy-pass-9`)、`dave` (is_active=0, password `dave-pass-123`)。`client_ip="203.0.113.7"`。

| # | 入力 | 期待 |
|---|---|---|
| L-1 | `{"user_id":"alice","password":"correct-horse-8","client_ip":"203.0.113.7"}` | 200 `{"ok": true, "pid": <uid>, "user_id": "alice", "public_name": ..., "token": <43 文字 urlsafe>, "expires_at": now+ttl_sec, "user_agent": null}`。sessions に 1 行 (`created_at=now`, `revoked_at NULL`)。ログ `LOGIN_OK subject=alice ip=203.0.113.7`。`auth_attempts` の `login_user:alice` 行は存在しない (削除済) |
| L-2 | 同上 + `"user_agent":"Mozilla/5.0"` | `user_agent` が body の値で保存・応答。body に無く HTTP `User-Agent` ヘッダがあるときはヘッダ値 (現状と同じ) |
| L-3 | `client_ip` 欠落 | 400 `{"ok": false, "error": "A01", "field": "client_ip"}`。ハッシュ計算なし、DB 無変更。**現状**: client_ip という概念なし |
| L-4 | `client_ip="999.1.1.1"` | 400 A12 field=client_ip |
| L-5 | `user_id` 1025 文字 / `password` 1025 byte (既定 policy) | 400 A12 field=user_id / password。ハッシュ計算なし (安い拒否を先に)。失敗カウンタも加算しない。1024 文字 / 1024 byte はこの検査を通り DB 照合へ (未知なら L-6 と同じ A03)。規則: 上限は `max(1024, policy.user_id_max_len)` / `max(1024, policy.password_max_bytes)` — `AuthPolicy(password_max_bytes=2048)` なら 2048 byte まで照合へ進み、signup で登録できる値は必ず login も通る |
| L-5b | legacy 行 `big_user` (user_id 300 文字、password 300 byte、1.1.x 形式) で正しい pw | **200** (login は signup ポリシーの正規表現・最小長・256 byte を見ない)。再ハッシュも行われる (L-18)。`Big_User` (大文字) や `a b` (空白) の legacy ID も同様にログイン可 |
| L-6 | `user_id="nobody"` (存在しない)、password 任意 | 401 `{"ok": false, "error": "A03"}`。**ダミー PBKDF2 を 1 回計算** (ゲージに計上)。`login_user:nobody` と `login_ip:203.0.113.7` はハッシュ前に予約 (+1) され、失敗で確定 (そのまま残る)。ログ `LOGIN_NG subject=nobody ip=203.0.113.7 detail=reason=invalid`。**現状**: 0.0001 s で即 A03 (既知ユーザー誤 pw の 1/500) |
| L-7 | `user_id="alice"`, password 誤り | 401 A03。両カウンタ +1 (予約が確定)。L-6 と応答・所要時間が同等 (Reviewer: 20 回ずつ計測し中央値の比が 0.5〜2.0 の範囲であることを確認。絶対値は環境依存) |
| L-7b | `login_user:alice.count=4` の状態で、**同時に** 2 本の誤 pw login (テストでは 2 本目を 1 本目のハッシュ前に割り込ませる = `_timed_hash` を差し替えて同期) | 一方は予約 count=5 でハッシュ → 401 A03 + ロック設定、他方は予約 count=6 > 5 → `_release` して **429 A11、ハッシュしない**。窓内にハッシュまで到達する試行は閾値 5 回を厳密に超えない |
| L-8 | `user_id="dave"` (無効化済)、password **誤り** | 401 A03 (存在・停止を漏らさない)。**現状**: pw 不問で 403 A04 |
| L-9 | `user_id="dave"`、password 正しい | 403 A04。両カウンタ +1。ログ `LOGIN_NG subject=dave detail=reason=disabled` |
| L-10 | `alice` に誤 pw を 4 回 → 5 回目も誤り | 5 回目: 401 A03、`login_user:alice.count=5`、`locked_until=now+900`。ログ `LOCKOUT subject=login_user:alice detail=until=<epoch>` |
| L-11 | L-10 直後、`alice` 正しい pw | 429 `{"ok": false, "error": "A11"}`。ハッシュ計算なし、カウンタ不変 (ロック中の試行はロックを延長しない)。ログ `RATE_LIMITED subject=login_user:alice detail=reason=locked` |
| L-12 | L-10 から `clock` を +901 秒進めて正しい pw | 200。`login_user:alice` 行削除 |
| L-13 | 誤り 4 回 → `clock` +901 → 誤り 1 回 | count=1 (窓リセット)、ロックなし |
| L-14 | 誤り 4 回 → 正しい pw 成功 → 誤り 4 回 | 2 回目の 4 連続でもロックなし (成功でアカウントカウンタ削除) |
| L-15 | 同一 `client_ip` から異なる存在しない user_id で 30 回失敗 → 31 回目 (どの user_id でも) | 31 回目: 429 A11、`login_ip:203.0.113.7.locked_until=now+900`。ログ `LOCKOUT subject=login_ip:203.0.113.7`。別 IP `203.0.113.8` からの `alice` 正 pw は 200 |
| L-16 | 同一 IP から成功 100 回連続 | 全て 200 (成功は IP 軸に数えない)。`login_ip:` は予約 (+1) → 成功で `_release` (−1) → count 0 の行は削除されるので、終了時に行は残らない |
| L-17 | `policy=AuthPolicy(hash_busy_ratio=0.0)` の AuthService で、存在しない user 宛の失敗を 3 連続 (1 秒以内) | 1 回目 401 A03 (ハッシュ実行)、**2・3 回目 429 A11** (直近窓の hash 時間 > 0 なのでハッシュしない)。`auth_attempts` は 1 回目の予約分 (count=1) だけで 2・3 回目は行を触らない。ログ `RATE_LIMITED subject=gauge detail=reason=busy`。verify は同時に 200 で応答する (ゲージは PBKDF2 だけに掛かる)。`hash_window_sec` 経過後の 4 回目は 401 A03。前提: 起動時の master 作成ハッシュ (M-3) はゲージに計上しない — `AuthService.__init__` の末尾で計測ログ (`_hash_log`) をクリアする。これが無いと直後の 1 回目が 429 になる |
| L-17b | 既定 `hash_busy_ratio=0.5` で、ハッシュ 1 回が d ms の機械 (本機 d≈124) | 判定は「ハッシュ前に、直近窓の合計 > 500 ms なら拒否」なので、k 回目が通る条件は `(k-1)·d ≤ 500`。d=124 なら 1〜5 回目が通り (4 回で 496 ms)、6 回目 (合計 620 ms) で 429。Reviewer は自機の d を測って `floor(500/d)+1` 回目までが通り、その次が 429 になることを確認する |
| L-18 | `legacy_bob` 正しい pw | 200。`users.password_hash` が `pbkdf2_sha256$600000$…` に、`password_salt=''` に更新 (透過再ハッシュ)。更新とセッション INSERT は同一 `BEGIN IMMEDIATE` tx 内で、users 行を再読して照合時の値と一致した場合だけ (§3.2)。2 回目の login も 200 で hash 不変 |
| L-18b | `legacy_bob` の login が照合を終えた直後 (tx 前) に、別接続の `update/password` が新パスワード `brand-new-99` で完了する (テストでは `_timed_hash` 差し替えで割り込ませる) | tx 内の再読が照合時の値と**不一致** → ROLLBACK、**401 A03、セッションは発行されない** (sessions に行なし)、`password_hash` は `update/password` の値のまま。`auth_attempts` の `login_user:legacy_bob` は、login 側の「予約の失敗確定」と割り込んだ `update_password` 成功側の `_reset` (H-1 の規則) が同時に起きるため、**結果は行なし** (reset が後) **または count=1** (reset の後に失敗確定が走った場合) のどちらか。どちらも許容し、Reviewer はこの行を assert しない。その後 `legacy-pass-9` は 401 A03、`brand-new-99` は 200。**旧設計 (uid だけの UPDATE)**: 旧パスワードが復活 (RG01)。**中間案 (旧値条件 UPDATE のみ)**: 旧 pw の照合結果から token が発行され、update_password の全セッション失効をすり抜ける 1 セッションが残った (Codex 第 2 パス) |
| L-19 | `legacy_bob` 誤 pw | 401 A03、hash 不変 (legacy のまま) |
| L-20 | `alice` 21 回連続 login 成功 | sessions の alice 行は 20 (created_at 最古の 1 行が削除)。全 21 トークンのうち最初の 1 本は verify で `active: false` |
| L-21 | 事前に alice の期限切れセッション 3 行 + revoked 2 行がある状態で login | それら 5 行は DELETE される (他ユーザーの行は不変) |
| L-22 | body が `application/json` でない (form) | 400 A01 field=body |
| L-23 | 不正 JSON | 400 A01 field=body (**現状**: 500) |

**login の処理順序 (固定)**: ① method ② JSON ③ 必須フィールド (A01)・DoS 上限 `user_id` ≤ `login_user_id_max_len` (1024 文字) / `password` ≤ `login_password_max_bytes` (1024 byte) (A12)・`client_ip` 形式 (A12)。**signup ポリシー (正規表現・最小 8 文字・256 byte) は見ない** (DB 無変更) ④ `_check_locked(login_ip)`、`_check_locked(login_user)` (A11、DB 無変更) ⑤ `_gauge_check()` (A11、DB 無変更) ⑥ **予約** `n_user=_reserve(login_user)`, `n_ip=_reserve(login_ip)`; `n_user > 5` または `n_ip > 30` なら両方 `_release` → A11 (ハッシュしない) ⑦ PBKDF2 (実 or ダミー、`_timed_hash`) ⑧ 不一致 / 無効化 → `n_user >= 5` なら `_lock(login_user, 900)`、`n_ip >= 30` なら `_lock(login_ip, 900)`、A03/A04 ⑨ 一致 → セッション掃除 (L-21) → `_issue_session_tx` (BEGIN IMMEDIATE → users 再読 → 照合時の hash/salt と一致なら [`needs_rehash` の UPDATE] + sessions INSERT → COMMIT。不一致なら ROLLBACK して ⑧ と同じ失敗経路 = A03、予約は確定) → 成功なら `_reset(login_user)` (行削除)、`_release(login_ip)` (成功は IP 軸に数えない) ⑩ `_sweep_attempts`。

予約の規則 (`_reserve`): 行なし → `count=1, window_start=now`。行あり: `now >= window_start + window_sec` → `count=1, window_start=now`; それ以外 → `count += 1`。1 文の `INSERT … ON CONFLICT(key) DO UPDATE SET count = CASE … END, window_start = CASE … END` の後に `SELECT count` (db.py の `execute` は SELECT 以外を fetch しないため RETURNING は使わない)。`_release` は `UPDATE … SET count = count - 1` + `DELETE … WHERE key=? AND count <= 0 AND locked_until IS NULL`。予約とハッシュの間でプロセスが落ちた場合はその予約が失敗として残る (fail-closed)。`_sweep_attempts` は login/signup/reauth の最後に `DELETE FROM auth_attempts WHERE window_start + 3600 <= now AND (locked_until IS NULL OR locked_until <= now)`。

### S. signup (`POST /signup`)

`client_ip="203.0.113.7"`。

| # | 入力 | 期待 |
|---|---|---|
| S-1 | `{"user_id":"carol","public_name":"Carol","password":"carol-pass-1","client_ip":...}` | 201 `{"ok": true}`。users に 1 行 (`password_hash` v2、`password_salt=''`、`created_at` 非 NULL、`is_master=0`)。`signup_ip:203.0.113.7.count` +1。ログ `SIGNUP subject=carol`。ハッシュ 1 回 (ゲージ計上) |
| S-2 | `password="1"` | 400 `{"ok": false, "error": "A12", "field": "password"}`。`auth_attempts` 無変更 (形式不備は数えない)。**現状**: 201 |
| S-3 | `password` 7 文字 / 8 文字 | 400 A12 / 201 (境界: 8 文字が最小) |
| S-4 | `password` が 256 byte / 257 byte (UTF-8) | 201 / 400 A12。例: `"あ"*86` = 258 byte → A12、`"a"*256` → 201 |
| S-5 | `password="        "` (空白 8 文字) | 201 (NIST: 組成規則を課さない。strip しない) |
| S-6 | `user_id="<img src=x onerror=alert(1)>"` | 400 A12 field=user_id。**現状**: 201 |
| S-7 | `user_id` = `ab` (2 文字) / `abc` / `a`*32 / `a`*33 / `Alice` / `_al` / `al.i-ce_9` / `al ice` | A12 / 201 / 201 / A12 / A12 (大文字) / A12 (先頭 `_`) / 201 / A12 |
| S-8 | 既存 `alice` がいる状態で `user_id="alice"` | 409 A02 |
| S-9 | 既存 `Admin` (legacy、大文字) がいる状態で `user_id="admin"` | 409 A02 (`COLLATE NOCASE` で衝突)。**現状**: 201 で別ユーザー |
| S-10 | `public_name="<script>1</script>"` | 400 A12 field=public_name (`<` `>` 禁止)。**現状**: 201 |
| S-11 | `public_name` = `"山田 太郎"` / `"Tom & Jerry"` / `"a\u0000b"` / `"​x"` / `"x"*64` / `"x"*65` / `"  "` | 201 / 201 / A12 (Cc) / A12 (Cf) / 201 / A12 / 400 **A01** (strip 後空) |
| S-12 | `public_name="ｱｲｳ"` (半角カナ) | 201、保存値は NFC 正規化後 (`ｱｲｳ` は NFC で不変。NFKC は使わない — 全角英数を潰さない) |
| S-13 | 同一 IP から形式検証とゲージを通過した signup (201 または A02) 10 回 → 11 回目 (形式は正しい) | 10 回目で `signup_ip:203.0.113.7.count=10`、`locked_until=now+3600` (予約時に `count >= 10` でロック設定)、ログ `LOCKOUT subject=signup_ip:203.0.113.7`。11 回目: ④ のロック確認で 429 A11、`auth_attempts` 無変更。別 IP は 201 |
| S-13b | `count=9` の状態で同時に 2 本 (L-7b と同じ割り込み) | 一方は予約 count=10 → INSERT (201) + ロック、他方は count=11 > 10 → `_release` → 429 A11、users に行を作らない |
| S-14 | S-13 から `clock` +3601 | 201 |
| S-15 | `client_ip` 欠落 | 400 A01 field=client_ip (`auth_attempts` 無変更) |
| S-16 | ゲージ超過 (L-17 と同条件) | 429 A11、users / `auth_attempts` 無変更 |

**signup の処理順序 (固定)**: ① method ② JSON ③ `client_ip` 存在 → 正規化 (A01/A12) ④ `_check_locked(signup_ip)` (A11) ⑤ user_id / public_name / password の形式検証 (A01/A12) ⑥ `_gauge_check()` (A11) ⑦ **予約** `n=_reserve(signup_ip)`; `n > 10` なら `_release` → A11 ⑧ `n >= 10` なら `_lock(signup_ip, 3600)` ⑨ PBKDF2 (`_timed_hash`) ⑩ NOCASE 衝突 (A02、予約はそのまま残す = 列挙も数える) ⑪ INSERT (201) ⑫ `_sweep_attempts`。①〜⑥ で拒否された要求は `auth_attempts` に行を作らない。

### V. verify (`POST /verify`)

| # | 入力 | 期待 |
|---|---|---|
| V-1 | 有効 token | 200 `{"active": true, "pid", "user_id", "public_name", "expires_at", "user_agent"}` (変更なし) |
| V-2 | 未知 / 期限切れ / revoked token、空 token | 200 `{"active": false}`。**ログに書かない** (ページ閲覧ごとの期限切れ cookie でログが埋まるのを避ける)。ゲージ・カウンタ不使用 |
| V-3 | 有効 token だが所有者が `is_active=0` (deactivate を経ずに直接 UPDATE した場合) | `{"active": false}` (SQL に `AND u.is_active=1`) |
| V-4 | L-17 のゲージ超過中 | 200 で通常応答 (ゲージと独立。待ちは走っている 1 ハッシュ分まで) |

### O. logout (`POST /logout`、AuthService)

| # | 入力 | 期待 |
|---|---|---|
| O-1 | `{"token": <有効>}` | 200 `{"ok": true}`、`revoked_at=now`。ログ `LOGOUT subject=<user_id> ip=<client_ip or '-'>` |
| O-2 | 未知 token | 200 `{"ok": true}` (冪等、情報を漏らさない)。ログなし |
| O-3 | token 空 | 200 `{"ok": true}` (変更なし) |

### T. token 必須エンドポイント共通 / resolve

| # | 条件 | 期待 |
|---|---|---|
| T-1 | `POST /resolve/pid` (任意 body) | 404 `{"ok": false, "error": "NotFound"}`。**現状**: token 無しで pid を返す |
| T-2 | `convert/pid`, `convert/user-id`, `update/*`, `permissions/*`, `master/*` に無効 token | 401 A06。ログ `TOKEN_INVALID subject=<token 先頭 8 文字>... ip=-` |
| T-3 | 同、token 欠落 | 401 A05。ログなし |
| T-4 | `convert/pid` で未知 user_id | 401 A03 (変更なし。token 保持者には存在確認を許す — アプリの UX 要件) |

### H. パスワード変更・ハッシュ (`POST /update/password`, `update/public-name`)

| # | 入力 | 期待 |
|---|---|---|
| H-1 | `{token, current_password: 正しい, new_password: "new-pass-123", client_ip: "203.0.113.7"}` | 200。hash v2 で更新、全セッション revoked (変更なし)。ログ `PASSWORD_CHANGE subject=<user_id>`。ハッシュ 2 回 (照合 + 生成、両方ゲージ計上)。`login_user:<user_id>` は予約 → 一致で `_reset`、`login_ip` は予約 → `_release` |
| H-1b | `client_ip` 欠落 | 400 A01 field=client_ip (token 検証の前。**現状**: client_ip という概念なし) |
| H-2 | `new_password="short"` | 400 A12 field=new_password。current の照合より**前**に判定 (ハッシュ計算なし、`auth_attempts` 無変更) |
| H-2b | `current_password` が 1025 byte | 400 A12 field=current_password (ハッシュ計算なし)。1024 byte 以下は形式を見ずに照合へ (login と同じ DoS 上限のみ。`new_password` だけが signup ポリシーの対象) |
| H-3 | current 誤り | 401 A03。`login_user:<user_id>` と `login_ip:<client_ip>` が予約 → 失敗で確定 (+1、login と同じカウンタ・同じ閾値。5 回で L-10 と同じロック)。ログ `LOGIN_NG subject=<user_id> ip=<client_ip> detail=reason=reauth` |
| H-3b | `login_user:<user_id>` が L-10 でロック中 (login 由来) に `update/password` | **429 A11、current を照合しない** (ハッシュ 0 回、`auth_attempts` 無変更)。逆に H-3 を 5 回繰り返して付いたロックは login (L-11) も 429 にする (同一キー) |
| H-3c | `login_ip:<client_ip>` が L-15 でロック中 | 429 A11、照合しない |
| H-3d | ゲージ超過 (L-17 と同条件) | 429 A11、照合しない |
| H-4 | legacy ユーザーが current 正しい | 200、v2 に更新 (再ハッシュ経路と同じ結果) |
| H-5 | `update/public-name` に `"<b>x</b>"` | 400 A12 field=public_name |
| H-6 | `update/public-name` に `"  Carol  "` | 200 `{"ok": true, "public_name": "Carol"}` (strip 後を保存・返却)。ログ `PUBLIC_NAME_CHANGE subject=<user_id>` |

### P. permissions

| # | 条件 | 期待 |
|---|---|---|
| P-1 | owner が `group/create` `{group_id:"g1", name:"Group1"}` | 200、owner は level 100 (変更なし)。ログ `GROUP_CREATE subject=g1 detail=by=<owner user_id>` |
| P-2 | `group_id="g 1"` / `"-g"` / `"a"*65` / `"team:admin"` | A12 group_id / A12 / A12 / 200。`name` は public_name と同じ規則 (A12 name) |
| P-3 | `member/upsert` `level: true` | 400 A12 field=level。**現状**: level 1 で保存 |
| P-4 | `level: 101` / `-1` / `"7"` / `null` | 400 A12 field=level (いずれも)。**現状**: A01 (status は同じ 400) |
| P-5 | 非 owner の token で `member/upsert` / `member/delete` | 403 A13。**現状**: 401 A03 |
| P-6 | 存在しない group_id で upsert | 400 A12 field=group_id。**現状**: A03 |
| P-7 | `group/delete` を level 7 のメンバーが | 403 A13。**現状**: 401 A03。ログなし。level 100 なら 200 + ログ `GROUP_DELETE subject=g1 detail=by=<user_id>` |
| P-8 | `group/auth` 自分の pid を自分の token で (非メンバーでも) | 200 `level: 0` (非メンバー) / 実 level |
| P-9 | `group/auth` 他人の pid を、自分が level ≥ 1 のメンバーである group で | 200 実 level |
| P-10 | `group/auth` 他人の pid を、自分が非メンバー (level 0) の group で | 403 A13。**現状**: 200 で level を返す |
| P-11 | `group/auth` 存在しない group | 要求者 pid == 対象 pid なら 200 level 0、他人なら 403 A13 (存在を漏らさない) |
| P-12 | upsert 成功 | ログ `PERM_UPSERT subject=g1 detail=by=<owner> target=<user_id> level=<n>`。delete 成功 → `PERM_DELETE subject=g1 detail=by=<owner> target=<user_id>` |

### M. master

| # | 条件 | 期待 |
|---|---|---|
| M-1 | 起動 (`ensure_master_user`): master 行あり | `UPDATE users SET is_active=1, is_master=1 WHERE user_id=<master_user>`、`UPDATE users SET is_master=0 WHERE is_master=1 AND user_id != <master_user>`。パスワードは触らない |
| M-2 | 起動: master 行なし + `master_login_password=""` | `AuthServiceUnavailableError` (変更なし、fail-closed) |
| M-3 | 起動: master 行なし + password あり | `master_login_password` に `validate_password(policy, field="master_login_password")` を適用 (CLI 生成 `token_urlsafe(14)` = 19 文字は満たす)。違反なら `AuthInvalidFieldError("master_login_password")` で起動失敗 (fail-closed)。通れば列名指定 INSERT (`created_at` 非 NULL、`is_master=1`、v2 hash)。master の `update/password` も H 系と同じポリシー (例外なし) |
| M-4 | `master/users/list` を master token で | 200 `{"ok": true, "users": [...]}` (変更なし) |
| M-5 | `master/users/list` を一般ユーザー token で | 403 A13。**現状**: 401 A03 |
| M-6 | `master/users/deactivate` `{token: master, target_user_id: "carol", login_password: <master の login pw>, client_ip: "203.0.113.7"}` | 200。carol `is_active=0`、carol の sessions 全 revoked。ログ `MASTER_DEACTIVATE subject=carol detail=by=master_user`。ハッシュ 1 回 (ゲージ計上)。`login_user:master_user` 予約 → `_reset`、`login_ip` 予約 → `_release` |
| M-7 | 同、`login_password` 誤り | 401 A03。`login_user:master_user` と `login_ip:<client_ip>` が予約 → 確定 (+1、5 回でロック → 以降 master の login も 429)。ログ `LOGIN_NG subject=master_user ip=<client_ip> detail=reason=reauth` |
| M-7b | `login_user:master_user` ロック中 (login 由来でも M-7 由来でも) | **429 A11、照合しない** (ハッシュ 0 回)。`login_ip` ロック中・ゲージ超過も同じ |
| M-7c | `login_password` 1025 byte | 400 A12 field=login_password (照合しない)。1024 byte 以下は形式を見ずに照合へ (login と同じ DoS 上限のみ) |
| M-8 | 同、`master_password` キーで送る (1.1.x クライアント、`client_ip` も無い) | 400 A01 field=login_password (フィールド検査順: target_user_id → login_password → client_ip) |
| M-9 | `target_user_id = master_user` (自分) | 403 A13、DB 無変更。**現状**: 200 で自己無効化 → 回復不能 |
| M-10 | `target_user_id` 不明 | 400 A12 field=target_user_id。**現状**: A03 |
| M-11 | `master/users/activate` で M-6 の carol | 200、`is_active=1`。セッションは復活しない。ログ `MASTER_ACTIVATE subject=carol detail=by=master_user` |
| M-12 | `master/users/deactivate` を一般ユーザー token で (login_password は自分の正しい pw) | 403 A13 (is_master 判定が再認証より先。ハッシュ 0 回、`auth_attempts` 無変更) |
| M-13 | `AuthService(..., master_password="x")` | `TypeError` (引数削除) |

### C. AuthClient

| # | 条件 | 期待 |
|---|---|---|
| C-1 | サーバーが `{"ok": true}` だけ返す (pid 等欠落) を `login` | `AuthServiceUnavailableError` (A09)。**現状**: `KeyError` |
| C-2 | サーバーが JSON 配列 / 非 JSON / 空 body を返す | A09 |
| C-3 | サーバーが 302 → `/elsewhere` | A09 (追従しない。`HTTPRedirectHandler.redirect_request` が None を返す opener) |
| C-4 | `verify_token` 応答 `{"active": true, ..., "user_agent": null}` | `Session.user_agent is None` (`"None"` にしない) |
| C-5 | 応答 `{"ok": false, "error": "A12", "field": "password"}` | `AuthInvalidFieldError("password")` (`.field == "password"`)。A11 → `AuthTooManyAttemptsError`、A13 → `AuthForbiddenError` |
| C-6 | 未知コード `"A99"` / `"HTTP_502"` | A09 (変更なし) |
| C-7 | `client.resolve_pid` | `AttributeError` (削除) |
| C-8 | `client.login(user_id=, password=)` / `client.signup(...)` / `client.update_password(...)` / `client.master_users_deactivate(...)` を `client_ip` 無しで | `TypeError` (必須 keyword) |
| C-9 | timeout / 接続拒否 | A09 (変更なし、3.0 s) |

### K. AuthPages — cookie と login/signup ページ

`client_ip=lambda r: "203.0.113.7"` を渡した AuthPages。

| # | 条件 | 期待 |
|---|---|---|
| K-1 | `POST /user/login/` JSON 正しい資格情報 (Origin ヘッダ無し) | 200 `{"ok": true, "user_id": ..., "public_name": ..., "expires_at": ...}`。**`token` キー無し**。`Set-Cookie: _nxt=<token>; Max-Age=<expires_at-now>; Path=/; Secure; HttpOnly; SameSite=Lax` (属性の並びは Cookie 契約に従う。`Max-Age` は `604800` ± 1 を許容)。**現状**: `MaxAge=1761000000` + body に token |
| K-2 | `POST /user/logout/` with cookie `_nxt=<token>` (JSON、Origin 無し) | 200 `{"ok": true}`、`Set-Cookie` に `_nxt=; Max-Age=0; Path=/` (削除ヘルパの出力)。AuthService 側 revoked。**現状**: `MaxAge=0` (無効) |
| K-3 | 同、`Content-Type: application/x-www-form-urlencoded` (HTML form) | 302 `Location: /` + 削除 cookie。Referer は見ない (**現状**: Referer を Location に)。**form-encoded POST は cookie の有無・AuthService の成否に関わらず常に 302 `/` + 削除 cookie** (ブラウザに JSON を見せない)。JSON POST だけが JSON 応答 |
| K-4 | `GET /user/logout/` | 405 `{"ok": false, "error": "MethodNotAllowed"}` + ヘッダ `Allow: POST`。cookie 不変、AuthService 呼び出しなし。**現状**: GET でログアウト |
| K-5 | `POST /user/logout/` cookie 無し (JSON) | 200 `{"ok": true}` + 削除 cookie (冪等)。AuthService 呼び出しなし |
| K-5b | `POST /user/logout/` cookie 無し、`Content-Type: application/x-www-form-urlencoded` | **302 `Location: /` + 削除 cookie** (JSON を返さない)。AuthService 呼び出しなし。**旧 doc / 実装**: cookie 無しの form POST で `{"ok": true}` がブラウザに表示されていた |
| K-6 | `POST /user/logout/` (JSON) で AuthService が A09 | 503 `{"ok": false, "error": "A09"}` **かつ** 削除 cookie を付ける (ブラウザ側は確実に外す。サーバー側の revoke は失敗を正直に返す) |
| K-6b | 同、form-encoded POST で AuthService が A09 | 302 `Location: /` + 削除 cookie (K-3 の規則どおり JSON を返さない)。失敗はアプリ側 `AppLogger.warn` に `logout revoke failed: A09` を 1 行 (ユーザーには見せない) |
| K-7 | login POST で AuthService が A11 / A12(field=password) | 429 `{"ok": false, "error": "A11"}` / 400 `{"ok": false, "error": "A12", "field": "password"}` (field を透過) |
| K-8 | login POST が form (非 JSON) | 400 A01 field=body |
| K-9 | `GET /user/login/`, `GET /user/signup/` | 200 HTML (変更なし) |
| K-10 | `GET /user/unknown/` | `PathNotFoundError` を送出 (→ 雛形 wsgi が 404)。**現状**: `AttributeError` → 500 |
| K-11 | `POST /user/signup/` 正常 | 201 `{"ok": true}`。AuthClient.signup に `client_ip` を渡す |
| K-12 | `AuthPages` に `client_ip=None` で POST | `req.client_ip` を使う (http doc 契約)。属性が無ければ `AttributeError` → 500 (黙って 127.0.0.1 に落とさない) |

### X. 同一オリジン検査 `is_same_origin(req)` (login/signup/logout POST に適用。GET には適用しない)

| # | ヘッダ | 結果 |
|---|---|---|
| X-1 | `Sec-Fetch-Site: same-origin` / `same-site` / `none` | True (他ヘッダを見ない) |
| X-2 | `Sec-Fetch-Site: cross-site` | False → 403 `{"ok": false, "error": "A13"}`。ログなし (アプリ側) |
| X-3 | Sec-Fetch-Site 無し、`Origin: https://app.example` と `Host: app.example` | True (netloc を小文字で完全一致) |
| X-4 | `Origin: https://evil.example`、`Host: app.example` | False |
| X-5 | `Origin: null` | False |
| X-6 | Origin 無し、`Referer: https://app.example/user/login/`、`Host: app.example` | True。`Referer: https://evil.example/` → False |
| X-7 | Sec-Fetch-Site / Origin / Referer いずれも無し | True (非ブラウザクライアント。cookie は SameSite=Lax で越境送信されないのが主防御) |
| X-8 | `Host` ヘッダ無し + `Origin` あり | False |

nginx 雛形・aisaba の vhost は `proxy_set_header Host $host` を送っている (`assets/gateway/nginx_app.conf:13`、aisaba `services/gateway/aisaba_main.conf:18`) ので X-3 は本番で成立する。

### U. `UserDatabaseManager`

| # | pid | 期待 |
|---|---|---|
| U-1 | `secrets.token_urlsafe(24)` の値 (32 文字) | 従来どおり `<users_dir>/<pid>.db` を開く |
| U-2 | `"../../x"` / `"abc"` (15 文字以下) / `"a"*65` / `"abc/def…"` | `AuthInvalidFieldError("pid")`、ファイル作成なし |

### W. 雛形 `auth/wsgi.py`

| # | 条件 | 期待 |
|---|---|---|
| W-1 | `CONTENT_LENGTH=abc` (不正 Content-Length)、`REMOTE_ADDR=127.0.0.1` | 400 `{"ok": false, "error": "A01", "field": "body"}` が **`start_response` 経由で**返る (`Request` 構築の `ValueError` を handler が捕捉。**現状**: 500)。同じ要求を `REMOTE_ADDR=10.0.0.5` から送ると **403 A13 が先** (ガードは Request 構築より前)。handler 自体が例外を漏らした場合だけ雛形 wsgi が 500 `InternalError` を返し error.log に traceback (**現状**: `NameError` で gunicorn の素の 500) |
| W-2 | 正常リクエスト | access.log に `<ip> "POST /login" 200 <ms>ms "<ua>"` (形式変更なし) |
| W-3 | `REMOTE_ADDR=127.0.0.1`、`X-Forwarded-For: 1.2.3.4`、`TRUSTED_PROXY_COUNT=0` (auth 既定) | access.log の ip は `127.0.0.1` (XFF 無視)。`TRUSTED_PROXY_COUNT >= 1` のときの採用規則は http doc §9 / §17.5 X10〜X12 に従う (本 doc では再定義しない)。**現状**: 常に XFF 先頭 |

## 6. 生成雛形 (assets/auth, assets/auth_page)

### 6.1 `assets/auth/config.py`

```python
# ======== auth service ========
AUTH_DB: str = DATA_DIR + "/db/auth/auth.db"
MASTER_USER: str = "__master_user__"
# 接続を許可する呼び出し元 (REMOTE_ADDR)。アプリと同一ホストなら loopback だけでよい。
# コンテナ間で使う場合はアプリ側のアドレスを足す。None でガード無効。
ALLOWED_CLIENTS: tuple[str, ...] | None = ("127.0.0.1", "::1")
# 前段の信頼プロキシ段数 (http doc §14.6)。auth は非公開 (loopback 直結) なので既定 0 = X-Forwarded-For を見ない。
TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__
```

`MASTER_PASSWORD` 行は削除。他の行 (project / gunicorn / logger) は不変。`__g_trusted_proxies__` プレースホルダの置換 (`create-auth` / `start-project --auth-*` では既定 `0`) は http doc の `build.py` 変更に含まれる。

### 6.2 `assets/auth/wsgi.py` (全面書き直し、`assets/app/wsgi.py` と同構造)

```python
from nexom.app.request import Request, client_ip        # client_ip は http doc §14.6 のプロキシ信頼契約
from nexom.app.response import Response, JsonResponse
from nexom.core.log import AppLogger
from nexom.app.auth import AuthService
from auth.config import (AUTH_DB, INFO_LOG, WARN_LOG, ERR_LOG, ACES_LOG, AUTH_LOG,
                         MASTER_USER, ALLOWED_CLIENTS, TRUSTED_PROXY_COUNT)

logger = AppLogger(info=INFO_LOG, warn=WARN_LOG, error=ERR_LOG, access=ACES_LOG)
service = AuthService(AUTH_DB, AUTH_LOG, master_user=MASTER_USER, master_login_password="",
                      allowed_clients=ALLOWED_CLIENTS)

def app(environ, start_response):
    t0 = time.time()
    res: Response
    try:
        res = service.handler(environ)          # handler 内で ガード(403) → Request 構築(ValueError→400) → routing の順 (§4.2)。NexomError は JSON 化済み
    except Exception as e:
        logger.error(e)
        res = JsonResponse({"ok": False, "error": "InternalError"}, status=500)
    try:
        ... access ログ (現行と同じ 1 行形式、ip は client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT))
    except Exception:
        pass
    start_response(res.status_text, res.headers)
    return [res.body]
```

ローカルの `_ip()` は置かない (`assets/app/wsgi.py` と同じく http doc の `client_ip` を使う。採用規則は http doc §9 / §17.5 X10〜X12)。`gunicorn.conf.py` は不変。

### 6.3 `templates/auth.py` と `auth_page/*.html` のスロット表 (自動エスケープ契約)

| テンプレート | スロット | 供給元 | 分類 | 1.2.0 での扱い |
|---|---|---|---|---|
| `login.html` `<body data-page-path="/{{ page_path }}">` | `{{ page_path }}` (**通常テキスト属性の値位置**。先頭の `/` はテンプレート側のリテラル。旧 1.1.x は `<script>` 内 `const PAGE_PATH = "/{{ page_path }}"` だったが、http doc §4.1 の新規則「script/style 本文のスロットは読み込み時に OH06 で拒否」により 1.2.0 では import 時に落ちるため属性へ移す) | `req.path` (`lstrip("/")` 済み = `user/login/`。静的セグメント完全一致で `user/login` 以外は到達しない — B-http HTTP-01 付随) | ユーザ入力ではないが環境由来 | 既定エスケープを**そのまま受ける** (属性値位置なので `"` もエスケープされる。`/`・英数・`_` は不変)。`Markup` で包まない。属性値は `/user/login/` になり、JS は `const PAGE_PATH = document.body.dataset.pagePath` でそのまま使う (`/` の付与は不要) |
| `signup.html` `<body data-page-path="/{{ page_path }}">` | 同上 (属性値は `/user/signup/`) | 同上 | 同上 | 同上 |
| (login/signup) | その他のスロットなし | — | — | — |

`templates/auth.py` が HTML に埋める他の値は無い。エラーメッセージは JSON で返し、ページ側 JS が `textContent` で表示する (HTML 化しない、現行どおり)。雛形 `assets/app/pages/default.py` の `user_message` (`<i>{public_name}</i>`) は http doc の範囲。

### 6.4 `auth_page/login.html`, `signup.html` の変更点 (文言・属性・`page_path` の位置)

- **`page_path` スロットを `<script>` 内から `<body>` 属性へ移動** (両ファイル): `<body>` を `<body data-page-path="/{{ page_path }}">` (先頭 `/` はリテラル、`req.path` は `lstrip("/")` 済み) にし、`<script>` 冒頭の `const PAGE_PATH = "/{{ page_path }}"` を `const PAGE_PATH = document.body.dataset.pagePath` に置換 (値は既に `/user/login/` なので `/` の付与は不要)。`<script>` / `<style>` 本文に `{{ }}` を残さない (http doc §4.1 OH06)。`AUTH_BASE` 等の他の定数は変更なし
- `error_code_for_message` に追加:
  - `"A11": "試行回数が多すぎます。しばらく待ってから再度お試しください。"`
  - `"A12": "入力内容の形式が正しくありません。"` + field 別: `"A12.user_id": "ユーザーIDは半角小文字英数字で始まり、英数字・_ . - のみ、3〜32 文字です。"`, `"A12.public_name": "公開名は 1〜64 文字で、< > や制御文字は使えません。"`, `"A12.password": "パスワードは 8 文字以上 (256 バイト以内) にしてください。"`
  - `"A13": "この操作は許可されていません。ページを再読み込みしてください。"`
  - `getErrorMessage(code, field)`: `code === "A12" && field` なら `A12.<field>` を優先、無ければ `A12`
- `setError(code, field)` と呼び出し側 `setError(r.data.error, r.data.field)` に変更
- `signup.html` の input: `user_id` に `pattern="[a-z0-9][a-z0-9_.\-]{2,31}" minlength="3" maxlength="32"`、`public_name` に `maxlength="64"`、`password`/`password2` に `minlength="8"`。ラベル直下に補助文 `<p class="hint">半角小文字英数字と _ . -、3〜32 文字</p>` (user_id) / `8 文字以上` (password)。`.hint` は 11px (`.sub` の 12px より 1px 小) / `var(--muted)`
- `login.html` の input は属性を足さない (legacy ID のログインを塞がない)

## 7. UI/UX (最小)

- 変更は §6.4 の文言・属性のみ。レイアウト・遷移・状態管理は現行どおり (単一カード、`msg` 領域にエラー、成功で `/` へ)
- §7 チェック観点 (ui-ux-design-perspectives) との対応: 状態網羅 = error 状態に A11/A12/A13 の 3 文言を追加 (empty/loading は現行の `btn.disabled` のまま)。アクセシビリティ = `hint` は `label` の直後に置き、`aria-describedby` で input に結ぶ。token / 色 / サイズは既存 CSS 変数を流用し新規値を増やさない。dark 対応・ナビ構造は変更なし

## 8. 監査ログ (`AuthLogger`、`AUTH_LOG`)

全 `subject` / `detail` の可変部は `sanitize_log_field()` (storage doc) を通してから渡す。`ip` は `normalize_ip` 済みの値か `None`。

| ACTION | 契機 | subject | ip | detail |
|---|---|---|---|---|
| `LOGIN_OK` | L-1 | user_id | client_ip | — |
| `LOGIN_NG` | L-6/7/9, H-3, M-7 | user_id | client_ip (再認証時も body の `client_ip`) | `reason=invalid` / `disabled` / `reauth` |
| `LOCKOUT` | L-10, L-15, S-13, H-3 (5 回目), M-7 (5 回目) | key (`login_user:alice` 等) | client_ip | `until=<epoch>` |
| `RATE_LIMITED` | L-11, L-7b, L-17, S-13b, S-16, H-3b〜d, M-7b | key (ロック中 / 予約超過) または `gauge` (ゲージ超過) | client_ip | `reason=locked` / `reserved` / `busy` |
| `SIGNUP` | S-1 | user_id | client_ip | — |
| `SIGNUP_NG` | S-2〜S-11 の A12/A02 | user_id (空なら `-`) | client_ip | `reason=A12:<field>` / `A02` |
| `LOGOUT` | O-1 | user_id | client_ip or `-` | — |
| `TOKEN_INVALID` | T-2 | token 先頭 8 文字 + `...` (既存メソッド) | `-` | — |
| `PASSWORD_CHANGE` | H-1 | user_id | `-` | — |
| `PUBLIC_NAME_CHANGE` | H-6 | user_id | `-` | — |
| `GROUP_CREATE` / `GROUP_DELETE` | P-1 / P-7 | group_id | `-` | `by=<user_id>` |
| `PERM_UPSERT` / `PERM_DELETE` | P-12 | group_id | `-` | `by=<owner> target=<user_id> level=<n>` / `by=… target=…` |
| `MASTER_DEACTIVATE` / `MASTER_ACTIVATE` | M-6 / M-11 | target_user_id | `-` | `by=<master user_id>` |
| `FORBIDDEN_CLIENT` | G-3〜5 | REMOTE_ADDR or `-` | `-` | — |
| `INTERNAL_ERROR` | handler の `except Exception` | path | `-` | `<type(e).__name__>` |

書かないもの: verify の失敗 (V-2)、password / token 全文、request body。

## 9. テスト基盤

- フレームワーク: pytest。実行 `cd Muraki/projects/nexom; .venv/bin/python -m pytest -q`。ベースライン 32 passed / 1 xfailed (`known-failures.md`)
- 配置: `tests/test_auth_and_db.py` (AuthService / AuthDBM / AuthClient の挙動)、`tests/test_templates_and_buildtools.py` (AuthPages、雛形生成)。新規ファイルは作らず既存 2 本に追加
- 作法: `AuthService(str(db), str(log), master_login_password="master-login-pw", clock=fake_clock, policy=AuthPolicy(hash_busy_ratio=None))` で `fake_clock` は可変 int を返す closure。**ゲージは既定 (0.5) だと高速ループのテスト (L-20 の 21 回 login 等) が 429 になるので、ゲージ以外のテストは `hash_busy_ratio=None` で無効化**し、ゲージのテスト (L-17) だけ `0.0` を使う。予約の同時実行 (L-7b / S-13b) は `AuthDBM._timed_hash` を monkeypatch し、1 本目がハッシュに入った時点で 2 本目を同じ DB ファイルの別 `AuthService` インスタンスから走らせる (別 sqlite 接続 = 別 worker の再現)。AuthClient は `http.server` をスレッドで立てる (既存テストに前例なし → Reviewer が `conftest.py` に `serve_json(handler) -> url` を足してよい)。AuthPages の POST は `client_ip=lambda r: "203.0.113.7"` を渡す
- タイミング (L-7) は中央値比較のみ、CI の揺れで落ちないよう 0.5〜2.0 の比に留める
- legacy 行のフィクスチャ: `dbm.execute("INSERT INTO users(uid,user_id,public_name,password_hash,password_salt,is_active,is_master) VALUES(?,?,?,?,?,1,0)", ...)` で `hashlib.pbkdf2_hmac("sha256", pw, bytes.fromhex(salt), 200_000).hex()` を直接入れる

### 9.1 既存テストで変わるもの (grep 済み: `tests/` 内で該当するのは下記 2 ファイルのみ)

| ファイル:行 | 現在 | 1.2.0 |
|---|---|---|
| `test_auth_and_db.py` 全 signup ペイロード (21, 61, 88, 127, 137, 264, 295, 333) | `user_id="u1"` 等 2 文字、`password="pw"` 等 | user_id 3 文字以上小文字 (`"user1"`…)、password 8 文字以上 (`"password-1"`…) |
| 同 全 login ペイロード (28, 65, 92, 111, 116, 129, 139, 258, 285, 299, 335) | `{user_id, password}` | `+ "client_ip": "127.0.0.1"` |
| 同 48 `dbm.login("u2", "pw2", user_agent="ua", ttl_sec=60)` | | `dbm.login("user2", "password-2", client_ip="127.0.0.1", user_agent="ua", ttl_sec=60)` |
| 同 96-98 `update/password` ペイロード | `{token, current_password, new_password}` | `+ "client_ip": "127.0.0.1"` |
| 同 全 `AuthService(...)` 生成 (18, 59, 86, 124, 249, 293, 331) | policy 既定 | `policy=AuthPolicy(hash_busy_ratio=None)` を付ける (test_permissions_group_flow は 1 秒内に 4 ハッシュ、機械次第で 5 回目が 429) |
| 同 254 `master_password="NexomWebFramework"` | | 削除 (TypeError になる) |
| 同 276 `"master_password": "NexomWebFramework"` | | `"login_password": "master_login_pw"` |
| 同 319-325 `/resolve/pid` → 200 | | 404 `error == "NotFound"` |
| 同 228 non-100 delete → 401 | | 403 |
| `conftest.py` `make_environ` | REMOTE_ADDR なし | `"REMOTE_ADDR": "127.0.0.1"` を既定に追加。REMOTE_ADDR 無しを前提にするテストは `env.pop("REMOTE_ADDR")` で明示的に外す: 本 doc の G-4、および `tests/test_http_hardening.py` の Q19 / X09 / X12 (http doc 側のテスト。追加キーで落ちるので同じ pop を入れる) |
| `test_templates_and_buildtools.py:43` | `'MASTER_PASSWORD: str = "NexomWebFramework"' in cfg` | `"MASTER_PASSWORD" not in cfg` と `'ALLOWED_CLIENTS: tuple[str, ...] | None = ("127.0.0.1", "::1")' in cfg` と `"TRUSTED_PROXY_COUNT: int = 0" in cfg` |
| 同 24-30 `test_auth_pages_login_get` | GET のみ、`HtmlResponse` と 200 を assert | 通る (`_OHTML` の import 時に OH06 が出ないことの確認でもある)。期待を 1 行足す: `GET /user/login/` の body に `data-page-path="/user/login/"` が含まれ、`{{` と `const PAGE_PATH = "/{{` が含まれない (signup も同様に `data-page-path="/user/signup/"`) |

`test_core.py` / `test_request_response.py` / `test_router_static_middleware.py` は auth コードを参照しない (grep 済み)。

## 10. 移行ガイド (1.1.x → 1.2.0)

### 10.1 互換性マトリクスと順序

| AuthService | AuthClient / AuthPages | 結果 |
|---|---|---|
| 1.1.x | 1.2.0 | **動く** (`client_ip` は未知フィールドとして無視される。`master_users_deactivate` だけ A01 になる) |
| 1.2.0 | 1.1.x | login / signup が 400 A01 (client_ip 欠落) → **ログイン不能** |

→ **アプリ側 (AuthClient 利用側) を先に 1.2.0 へ上げ、最後に auth サービスを上げる。** 同一 venv を共有している場合は同時再起動でよい (aisaba は `nexom@<service>` 単位の venv)。

### 10.2 aisaba の auth サービス (`services/auth`、127.0.0.1:7070)

実体: `services/auth/wsgi.py` は `AuthService(AUTH_DB, AUTH_LOG)` (GitHub `ait913/AisabaPlatform` 72d2648、`config.py` は gitignore)。

1. バックアップ: `sqlite3 <DATA_DIR>/db/auth/auth.db ".backup auth-pre-1.2.0.db"` (WAL を含めて 1 ファイルに)
2. `pip install -U nexom==1.2.0` (venv)
3. `wsgi.py` を §6.2 の形に差し替える (最低限: `except Exception as e` と `start_response` の修正。`AuthService(AUTH_DB, AUTH_LOG)` は引数既定値で 1.2.0 でもそのまま動く — `allowed_clients` 既定 loopback、アプリは `http://127.0.0.1:7070` で接続するので通る)
4. `config.py` に `MASTER_PASSWORD` があれば削除 (残っていても未参照で害はない)。`ALLOWED_CLIENTS` / `TRUSTED_PROXY_COUNT` は任意 (未定義なら wsgi.py 側で import しない形にする。`TRUSTED_PROXY_COUNT` 未定義時は `client_ip(environ)` の既定 0)
5. `systemctl restart nexom@auth` → 初回起動で schema v2 へ自動移行 (§3.3)、master 行に `is_master=1, is_active=1`
6. 確認: `curl -s -X POST http://127.0.0.1:7070/verify -H 'content-type: application/json' -d '{"token":"x"}'` → `{"active": false}`。別ホストから同じ要求 → 接続不可 (bind) または 403 A13
7. 既存ユーザー: そのままログイン可、初回成功時に 600k へ再ハッシュ。signup ポリシー (正規表現・最小 8 文字・256 byte) は新規登録と変更時だけで、login / 再認証は DoS 上限 (`user_id` 1024 文字、`password` 1024 byte) しか見ない (L-5b)。**例外**: 1024 を超える ID / パスワードの既存行は 1.2.0 でログイン時に A12 になる (事前に `sqlite3 auth.db "SELECT user_id FROM users WHERE length(user_id) > 1024"` で 0 件を確認。該当すれば master が `deactivate` → 本人が再登録)
8. 無効化操作をスクリプト等で行っていた場合: `master_password=<定数>` → `login_password=<master の login password>` に書き換え

### 10.3 aisaba のアプリ側 (`aisaba_main` 等、AuthPages / AuthClient 利用)

1. `pip install -U nexom==1.2.0`、`systemctl restart nexom@<service>`
2. `AuthPages("user/", AUTH_SERVER)` は無修正で動く。ただし `Request.client_ip` (http doc) が無い版と組み合わせると POST が 500 になる → nexom 全体を 1.2.0 に揃える
3. ログアウト UI を持つなら `<a href="/user/logout/">` を `<form method="post" action="/user/logout/"><button>ログアウト</button></form>` に (GET は 405)。aisaba_main 現行コードに logout リンクは無い (grep 済み)
4. 独自に `AuthClient.login/signup/update_password/master_users_*` を呼ぶコード: `client_ip=req.client_ip` を追加。`resolve_pid` 利用箇所は `convert_pid(token=...)` へ (aisaba に利用箇所なし、grep 済み)
5. login 応答 body の `token` を読む SPA があれば cookie 認証へ (aisaba に該当なし)
6. 既存ブラウザの `_nxt` cookie (1.1.x 発行、Max-Age 無し) は有効なまま。再ログイン強制は無い

### 10.4 Bloom 等の新規アプリ

`nexom start-project` の生成物が 1.2.0 既定。**推奨は同一ホストの loopback に限定** (`ALLOWED_CLIENTS` 既定のまま)。別ホスト/コンテナに分ける場合は、(a) ネットワークを private に閉じる、**かつ** (b) auth の前に TLS 終端 (nginx 等の reverse proxy) を置いてアプリ側 `AUTH_SERVER` を `https://` にする — AuthClient は `urllib` なので `https://` をそのまま扱える。この構成では `ALLOWED_CLIENTS` に proxy のアドレス、`TRUSTED_PROXY_COUNT` に proxy の段数 (1 段なら `1`) を設定する。平文 HTTP を private network だけに頼って別ホストへ流す構成は採らない。

## 11. 不採用案

| # | 案 | 却下理由 |
|---|---|---|
| N-1 | 雛形生成時に `secrets.token_urlsafe(32)` を `MASTER_PASSWORD` として config に書く (Researcher 修正案 a / DATA-09) | 秘密が 1 つ増え、既存 aisaba config の手動差し替えが必須になる。master の login password の再入力で同じ防御 (盗まれた master token 単独では破壊操作不可) が得られ、新しい秘密も移行手順も要らない。Touri の設計言語 (明示的・ミニマル) に合う |
| N-2 | `MASTER_PASSWORD` を環境変数必須に | 同上 + systemd unit に秘密を置く運用が増える |
| N-3 | CSRF トークン (synchronizer / double-submit) | cookie が `SameSite=Lax` で越境送信されず、login/signup/logout は JSON のみ受理 (form 送信不可) なので主防御が二重。トークン方式はテンプレート注入点とセッション状態の追加が必要で、ObjectHTML の既定エスケープ化と同時に入れると移行コストが二重になる。`is_same_origin` (Origin/Referer/Sec-Fetch-Site) を補助に置く |
| N-4 | app→auth の共有秘密 (`X-Nexom-Auth-Key`) | AUTH-07 の修正案 (3)。loopback 限定 + `allowed_clients` で同一ホスト外は塞がる。同一ホスト内の別プロセスからの到達は aisaba の信頼境界 (1 ホスト複数アプリ) として受容。コンテナ化のときに再検討 |
| N-5 | ロックのキーを `(user_id, ip)` の組にする | ローテーション IP からの credential stuffing では永久に発火しない。アカウント単位ロック (15 分) の DoS 面は受容し、IP 軸は失敗だけ数えて NAT の正規利用者を巻き込まない |
| N-6 | permission group の作成を master 限定 / owner 名前空間強制 (AUTH-08) | 既存 group_id の移行が要り、aisaba の permissions アプリの作法が不明 (リポジトリに無い)。先取りは「本物を後から作る側が A10 で気付く」fail-closed なので、`group/auth` の情報漏えい遮断 (P-10) と形式検証だけ入れる |
| N-7 | verify を別 gunicorn プロセス/ポートに分離 | 運用物が 2 つになる。プロセス内の時間ベース PBKDF2 ゲージ (§4.1、L-17) で login が各 worker の 50% 超を占有できず、verify の待ちは 1 ハッシュ分に有界なので単一プロセスで足りる |
| N-7b | PBKDF2 予算を回数ベースの token bucket (4 hash/s、容量 8) にする | 「4 回」は本機の 123.7 ms × 4 ≈ 50% から割った値で、遅い機械では 50% を超え、速い機械では絞り過ぎる。実測 wall time の比率 (`hash_busy_ratio`) なら機械が変わっても verify に残す割合が不変 |
| N-8 | AuthClient 側の verify 結果キャッシュ (30 s) | revoke / パスワード変更の即時性が落ちる。ゲージで verify の応答性を守る方を採る |
| N-15 | 失敗カウンタを「ハッシュ後に加算」する (予約なし) | ロック確認 → ハッシュ → 加算 の間に別 worker の試行が割り込むと、閾値 5 回を超えて 6 回・7 回目のハッシュまで走る。ハッシュ前に予約し成功で戻す方式なら閾値が厳密上限になる (L-7b / S-13b) |
| N-16 | login の透過再ハッシュを `WHERE uid=?` だけで UPDATE する / 旧値条件 UPDATE (0 行なら無視) だけで済ませる | 前者は照合後・UPDATE 前に別接続の `update_password` が完了すると旧パスワードが復活する (RG01)。後者は復活は防ぐが、旧 pw の照合結果からセッションが発行され `update_password` の全セッション失効をすり抜ける 1 本が残る (Codex 第 2 パス)。**採用**: 照合は tx 外で終え、`BEGIN IMMEDIATE` tx 内で users 行を再読 → 照合時の値と一致する場合だけ再ハッシュ UPDATE + sessions INSERT、不一致は A03 (§3.2, L-18b)。tx が DB を握るのは SELECT + UPDATE + INSERT の間だけで、PBKDF2 (≈125 ms) は含まない |
| N-17 | AuthPages の `_json_body` / `_auth_error` (JSON 本文の取り出しと NexomError → JSON 整形) を `AuthService._body` / handler のエラー整形と共通化する | code-review で重複として指摘されたが、1.2.0 では見送り (リリース後の品質改善)。両者は `field` 透過と status 決定の規則が同じなので共通ヘルパ 1 つに寄せられる。今回はリリース範囲を広げないため記録のみ |
| N-9 | `verify` 失敗を `TOKEN_INVALID` でログ | 期限切れ cookie を持つ閲覧者のページビューごとに 1 行書く = ログ DoS 面。意図的な認証付き API 呼び出し (T-2) だけ記録 |
| N-10 | `user_id` を NFKC + 小文字化して保存 | 既存 ID と衝突規則が変わる。新規は正規表現で小文字のみに制限し、衝突検査は `COLLATE NOCASE` で済ませる (保存値は入力そのまま) |
| N-11 | `public_name` から `<` `>` を許し表示側エスケープに全面依存 | エスケープは http doc で既定化するが、`Markup` の誤用 1 箇所で stored XSS が全アプリに伝播する供給源を auth 層で絶てる。正規名で `<>` を使う例は無視できる |
| N-12 | logout を GET のまま確認ページを挟む | 2 画面増え、`<img src>` による CSRF は確認ページでは止まるが UX が悪い。POST 一本 (form でも fetch でも) |
| N-13 | `sessions` の revoked 行を保持 (監査) | 監査は `LOGOUT` ログで足りる。行を残すと AUTH-17 の掃除と二重管理 |
| N-14 | 1.1.x との互換のため `master_password=` を受理して無視 | セキュリティ引数を黙って捨てるのは「明示的」に反する。TypeError で起動時に気付かせる |

## 12. 他 doc への要求 (Leader が突合)

1. **http doc**: `Request.client_ip: str` — プロキシ信頼設定に基づく末端クライアント IP。AuthPages の既定経路 (K-12) と `assets/app` 側で AuthClient を呼ぶコードが使う。無い場合 AuthPages のレート制限 IP 軸が成立しない
2. **http doc**: Cookie 削除ヘルパの確定名。本 doc は `Cookie.delete(name, *, path="/", domain=None) -> Cookie` と仮称 (K-2)
3. **http doc**: `Request._parse_cookies` の `CookieError` 耐性 (W-1 は本 doc 側で 500 JSON に揃えるが、アプリ側で全ページ 500 になる現状は request.py の話)
4. **storage doc**: `AuthLogger.event(action, *, subject, ip=None, detail=None)` の追加と `sanitize_log_field` の公開 (`nexom.core.log`)。既存 4 メソッドは維持
5. **storage doc**: `pyproject.toml` version 1.2.0、`src/nexom/__init__.py` の `__version__` を揃えるか否か

## 13. 残存リスク (1.2.0 で閉じないもの)

- 分散 IP からの低速 credential stuffing: アカウント軸 5 回/15 分で 1 アカウント当たり 480 回/日まで。パスワード最小 8 文字 + 600k PBKDF2 で許容
- アカウントロックによる嫌がらせ (15 分): 受容 (N-5)。回復は時間経過のみ (master による unlock は未実装)
- legacy ユーザーの初回ログインまで 200k ハッシュ (タイミングで「legacy かつ存在」が推定可能): 全員が 1 回ログインすれば消える
- `auth_attempts` の行増加: 行が増えるのは予約 (⑥/⑦) に到達した要求だけで、その前段のロック確認・形式検証・ゲージで拒否された要求は行を作らない。予約に到達する要求はゲージで worker あたり ≤ 500 ms/s のハッシュ = 本機 (124 ms) で ≤ 4 回/s + 超過 1 回 ≈ 5 行/s/worker、既定 4 worker で ≤ 20 行/s (新規 user_id を毎回変える攻撃者が `login_user:` 行を作る最悪形。`login_ip:` は IP 数ぶんだけ)。`_sweep_attempts` が窓開始から 1 時間で消すので最悪 ≈ 20 × 3600 = 72k 行 (1 行 ≈ 100 byte → 約 7 MB)。許容
- app ↔ auth の平文 HTTP: loopback 限定が前提。別ホスト運用は private network **かつ** TLS 終端 reverse proxy が条件 (§10.4)
