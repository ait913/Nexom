"""Config template for generated app."""

# ======== project ========
APP_NAME: str = "__app_name__"

PROJECT_DIR: str = "__prj_dir__"
APP_DIR: str = "__app_dir__"
TEMPLATES_DIR: str = "__app_dir__/templates"

DATA_DIR: str = "__prj_dir__/data"

# ======== gunicorn ========
ADDRESS: str = "__g_address__"
PORT: int = __g_port__
WORKERS: int = __g_workers__
RELOAD: bool = __g_reload__

# ======== request ========
MAX_BODY_SIZE: int = 10 * 1024 * 1024   # bytes; shared by body, json, form, and files (multipart)

# ======== proxy ========
# Reverse proxies in front of gunicorn. 0 trusts only REMOTE_ADDR.
# Use 1 for the nginx/apache gateway, or 2 for Cloudflare -> nginx.
TRUSTED_PROXY_COUNT: int = __g_trusted_proxies__

# ======== auth ========
AUTH_SERVER: str = "http://127.0.0.1:7070"

# ======== logger ========
INFO_LOG: str = "__prj_dir__/data/log/__app_name__/info.log"
WARN_LOG: str = "__prj_dir__/data/log/__app_name__/warning.log"
ERR_LOG: str = "__prj_dir__/data/log/__app_name__/error.log"
ACES_LOG: str = "__prj_dir__/data/log/__app_name__/access.log"