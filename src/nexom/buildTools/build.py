from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module, resources
from pathlib import Path
import re
import shutil


@dataclass(frozen=True)
class AppBuildOptions:
    """Options used to fill generated config.py."""
    address: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    reload: bool = False


_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


class AppBuildError(RuntimeError):
    """Raised when project generation fails for any reason."""


def _copy_from_package(pkg: str, filename: str, dest: Path) -> None:
    """Copy a file from a package resource into the destination path."""
    dest.parent.mkdir(parents=True, exist_ok=True)

    module = import_module(pkg)
    with resources.files(module).joinpath(filename).open("rb") as src, dest.open("wb") as dst:
        shutil.copyfileobj(src, dst)


def _replace_many(text: str, repl: dict[str, str]) -> str:
    """Apply multiple literal replacements and ensure no placeholders remain."""
    out = text
    for k, v in repl.items():
        out = out.replace(k, v)

    # Placeholder leak detection (generic message; detailed info should be logged elsewhere)
    unresolved = [k for k in repl.keys() if k in out]
    if unresolved:
        raise AppBuildError("Build template placeholder was not resolved.")
    return out


def create_app(
    project_dir: str | Path,
    app_name: str,
    *,
    options: AppBuildOptions | None = None,
) -> Path:
    """
    Generate a Nexom server app under:
        <project_dir>/<app_name>/

    The generated directory includes:
        pages/, templates/, static/, config.py, gunicorn.conf.py, router.py, wsgi.py

    Args:
        project_dir: Project root directory where "apps/" will be created/used.
        app_name: Application directory name (must match [A-Za-z0-9_]+).
        options: Defaults for generated config.py values.

    Returns:
        Absolute path to the generated app directory (<project_dir>/<app_name>).

    Raises:
        ValueError: If app_name is invalid.
        FileExistsError: If target app directory already exists (or is non-empty).
        AppBuildError: If bundled assets are missing or placeholders cannot be resolved.
    """
    if not _NAME_RE.match(app_name):
        raise ValueError("app_name must match [A-Za-z0-9_]+ (no dots, slashes, or hyphens).")

    options = options or AppBuildOptions()

    project_root = Path(project_dir).expanduser().resolve()
    project_root.mkdir(parents=True, exist_ok=True)

    app_root = project_root / app_name
    if app_root.exists():
        # refuse overwrite (both file and dir)
        raise FileExistsError(f"Target app already exists: {app_root}")
    app_root.mkdir(parents=True, exist_ok=False)

    # create data directory
    data_dir = project_root / "data"
    db_dir = data_dir / "db"
    log_dir = data_dir / "log"

    data_dir.mkdir(exist_ok=True)
    db_dir.mkdir(exist_ok=True)
    log_dir.mkdir(exist_ok=True)

    # refuse generating into a non-empty directory (extra safety)
    if any(app_root.iterdir()):
        raise FileExistsError(f"Target app directory is not empty: {app_root}")

    pages_dir = app_root / "pages"
    templates_dir = app_root / "templates"
    static_dir = app_root / "static"

    pages_dir.mkdir()
    templates_dir.mkdir()
    static_dir.mkdir()

    # ---- Copy pages ----
    pages_pkg = "nexom.assets.app.pages"
    for fn in ("__init__.py", "_templates.py", "default.py", "document.py"):
        _copy_from_package(pages_pkg, fn, pages_dir / fn)

    # ---- Copy templates ----
    templates_pkg = "nexom.assets.app.templates"
    for fn in ("base.html", "header.html", "footer.html", "default.html", "document.html"):
        _copy_from_package(templates_pkg, fn, templates_dir / fn)

    # ---- Copy static ----
    static_pkg = "nexom.assets.app.static"
    for fn in ("dog.jpeg", "style.css"):
        _copy_from_package(static_pkg, fn, static_dir / fn)

    # ---- Copy app files ----
    app_pkg = "nexom.assets.app"
    for fn in ("__init__.py", "gunicorn.conf.py", "router.py", "wsgi.py", "config.py"):
        _copy_from_package(app_pkg, fn, app_root / fn)

    # ---- Enable settings (replace config.py) ----
    config_path = app_root / "config.py"
    config_text = config_path.read_text(encoding="utf-8")
    config_enabled = _replace_many(
        config_text,
        {
            "__prj_dir__": str(project_root),
            "__app_name__": str(app_name),
            "__app_dir__": str(app_root),
            "__g_address__": options.address,
            "__g_port__": str(options.port),
            "__g_workers__": str(options.workers),
            "__g_reload__": "True" if options.reload else "False",
        },
    )
    config_path.write_text(config_enabled, encoding="utf-8")

    # ---- Enable settings (replace gunicorn.conf.py) ----
    gunicorn_conf_path = app_root / "gunicorn.conf.py"
    gunicorn_conf_text = gunicorn_conf_path.read_text(encoding="utf-8")
    gunicorn_conf_enabled = _replace_many(gunicorn_conf_text, {"__app_name__": app_name})
    gunicorn_conf_path.write_text(gunicorn_conf_enabled, encoding="utf-8")

    # ---- Enable settings (replace wsgi.py) ----
    wsgi_path = app_root / "wsgi.py"
    wsgi_text = wsgi_path.read_text(encoding="utf-8")
    wsgi_enabled = _replace_many(wsgi_text, {"__app_name__": app_name})
    wsgi_path.write_text(wsgi_enabled, encoding="utf-8")

    # ---- Enable settings (replace pages/_templates.py) ----
    pages_templates_path = pages_dir / "_templates.py"
    pages_templates_text = pages_templates_path.read_text(encoding="utf-8")
    pages_templates_enabled = _replace_many(pages_templates_text, {"__app_name__": app_name})
    pages_templates_path.write_text(pages_templates_enabled, encoding="utf-8")

    return app_root

def create_auth(
    project_dir: str | Path,
    *,
    options: AppBuildOptions | None = None,
) -> Path:
    """
    Generate a Nexom auth server app under:
        <project_dir>/auth/
    """
    options = options or AppBuildOptions(port=7070)  # authのデフォルトだけ変える

    project_root = Path(project_dir).expanduser().resolve()
    project_root.mkdir(parents=True, exist_ok=True)

    app_root = project_root / "auth"
    if app_root.exists():
        raise FileExistsError(f"Target app already exists: {app_root}")
    app_root.mkdir(parents=True, exist_ok=False)

    # create data directory
    data_dir = project_root / "data"
    db_dir = data_dir / "db"
    log_dir = data_dir / "log"

    data_dir.mkdir(exist_ok=True)
    db_dir.mkdir(exist_ok=True)
    log_dir.mkdir(exist_ok=True)

    if any(app_root.iterdir()):
        raise FileExistsError(f"Target app directory is not empty: {app_root}")

    # ---- Copy app files ----
    app_pkg = "nexom.assets.auth"
    for fn in ("__init__.py", "gunicorn.conf.py", "wsgi.py", "config.py"):
        _copy_from_package(app_pkg, fn, app_root / fn)

    # ---- Enable settings (replace config.py) ----
    config_path = app_root / "config.py"
    config_text = config_path.read_text(encoding="utf-8")
    config_enabled = _replace_many(
        config_text,
        {
            "__prj_dir__": str(project_root),
            "__app_name__": "auth",
            "__app_dir__": str(app_root),
            "__g_address__": options.address,
            "__g_port__": str(options.port),
            "__g_workers__": str(options.workers),
            "__g_reload__": "True" if options.reload else "False",
        },
    )
    config_path.write_text(config_enabled, encoding="utf-8")

    # ---- Enable settings (replace gunicorn.conf.py) ----
    gunicorn_conf_path = app_root / "gunicorn.conf.py"
    gunicorn_conf_text = gunicorn_conf_path.read_text(encoding="utf-8")
    gunicorn_conf_enabled = _replace_many(gunicorn_conf_text, {"__app_name__": "auth"})
    gunicorn_conf_path.write_text(gunicorn_conf_enabled, encoding="utf-8")

    return app_root