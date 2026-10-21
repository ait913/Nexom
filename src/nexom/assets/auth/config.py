"""Config template for generated auth app."""

# ======== project ========
PROJECT_DIR: str = "__prj_dir__"
APP_DIR: str = "__app_dir__"
TEMPLATES_DIR: str = "__app_dir__/templates"

DATA_DIR: str = "__prj_dir__/data"

# ======== gunicorn ========
ADDRESS: str = "__g_address__"
PORT: int = __g_port__
WORKERS: int = __g_workers__
RELOAD: bool = __g_reload__

# ======== auth service ========
AUTH_DB: str = DATA_DIR + "/db/auth/auth.db"
MASTER_USER: str = "__master_user__"
# 接続を許可する呼び出し元 (REMOTE_ADDR)。同一ホストでは loopback のみ。
# コンテナ間ではアプリ側のアドレスを追加する。None でガード無効。
ALLOWED_CLIENTS: tuple[str, ...] | None = ("127.0.0.1", "::1")
# 信頼するリバースプロキシの段数。auth は非公開なので既定は直結の 0。
TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__

# ======== logger ========
INFO_LOG: str = "__prj_dir__/data/log/__app_name__/info.log"
WARN_LOG: str = "__prj_dir__/data/log/__app_name__/warning.log"
ERR_LOG: str = "__prj_dir__/data/log/__app_name__/error.log"
ACES_LOG: str = "__prj_dir__/data/log/__app_name__/access.log"
AUTH_LOG: str = "__prj_dir__/data/log/__app_name__/auth.log"
