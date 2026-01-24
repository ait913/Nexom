from __app_name__.config import ADDRESS, PORT, WORKERS, RELOAD  # noqa: E402

bind = f"{ADDRESS}:{PORT}"
workers = int(WORKERS)
reload = bool(RELOAD)