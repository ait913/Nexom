from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module, resources
from pathlib import Path
import re
import shutil


@dataclass(frozen=True)
class AppBuildOptions:
    address: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    reload: bool = False


_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


class AppBuildError(RuntimeError):
    """Raised when project generation fails for any reason."""


def _copy_from_package(pkg: str, filename: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    module = import_module(pkg)
    with resources.files(module).joinpath(filename).open("rb") as src, dest.open("wb") as dst:
        shutil.copyfileobj(src, dst)


def _read_text_from_package(pkg: str, filename: str) -> str:
    module = import_module(pkg)
    return resources.files(module).joinpath(filename).read_text(encoding="utf-8")


def _replace_many(text: str, repl: dict[str, str]) -> str:
    out = text
    for k, v in repl.items():
        out = out.replace(k, v)

    unresolved = [k for k in repl.keys() if k in out]
    if unresolved:
        raise AppBuildError("Build template placeholder was not resolved.")
    return out


def _validate_app_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise ValueError("name must match [A-Za-z0-9_]+ (no dots, slashes, hyphens).")


def _write_gateway_config(
    gateway_dir: Path,
    *,
    kind: str,  # "nginx" | "apache"
    app_name: str,
    app_port: int,
    domain: str,
) -> Path:
    if kind not in ("nginx", "apache"):
        raise ValueError("kind must be nginx or apache.")

    # domain placeholder
    dom = domain.strip() or "YOUR_DOMAIN_HERE  # set --domain example.com"

    # wsgi import path (project root is PYTHONPATH in naxom run)
    wsgi_target = f"{app_name}.wsgi:app"

    pkg = "nexom.assets.gateway"
    filename = "nginx_app.conf" if kind == "nginx" else "apache_app.conf"

    text = _read_text_from_package(pkg, filename)
    out = _replace_many(
        text,
        {
            "__DOMAIN__": dom,
            "__APP_PORT__": str(app_port),
            "__APP_WSGI__": wsgi_target,
            "__APP_NAME__": app_name,
        },
    )

    gateway_dir.mkdir(parents=True, exist_ok=True)
    out_path = gateway_dir / f"{app_name}.{kind}.conf"
    out_path.write_text(out, encoding="utf-8")
    return out_path


def create_app(
    project_dir: str | Path,
    app_name: str,
    *,
    options: AppBuildOptions | None = None,
    gateway_config: str | None = None,
    domain: str = "",
) -> Path:
    _validate_app_name(app_name)
    options = options or AppBuildOptions()

    project_root = Path(project_dir).expanduser().resolve()
    project_root.mkdir(parents=True, exist_ok=True)

    app_root = project_root / app_name
    if app_root.exists():
        raise FileExistsError(f"Target app already exists: {app_root}")
    app_root.mkdir(parents=True, exist_ok=False)

    pages_dir = app_root / "pages"
    templates_dir = app_root / "templates"
    static_dir = app_root / "static"
    pages_dir.mkdir()
    templates_dir.mkdir()
    static_dir.mkdir()

    # pages
    pages_pkg = "nexom.assets.app.pages"
    for fn in ("__init__.py", "_templates.py", "default.py", "document.py"):
        _copy_from_package(pages_pkg, fn, pages_dir / fn)

    # templates
    templates_pkg = "nexom.assets.app.templates"
    for fn in ("base.html", "header.html", "footer.html", "default.html", "document.html"):
        _copy_from_package(templates_pkg, fn, templates_dir / fn)

    # static
    static_pkg = "nexom.assets.app.static"
    for fn in ("dog.jpeg", "github.png", "style.css"):
        _copy_from_package(static_pkg, fn, static_dir / fn)

    # app files
    app_pkg = "nexom.assets.app"
    for fn in ("__init__.py", "gunicorn.conf.py", "router.py", "wsgi.py", "config.py"):
        _copy_from_package(app_pkg, fn, app_root / fn)

    # config.py
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

    # gunicorn.conf.py
    gunicorn_conf_path = app_root / "gunicorn.conf.py"
    gunicorn_conf_text = gunicorn_conf_path.read_text(encoding="utf-8")
    gunicorn_conf_enabled = _replace_many(gunicorn_conf_text, {"__app_name__": app_name})
    gunicorn_conf_path.write_text(gunicorn_conf_enabled, encoding="utf-8")

    # wsgi.py
    wsgi_path = app_root / "wsgi.py"
    wsgi_text = wsgi_path.read_text(encoding="utf-8")
    wsgi_enabled = _replace_many(wsgi_text, {"__app_name__": app_name})
    wsgi_path.write_text(wsgi_enabled, encoding="utf-8")

    # pages/_templates.py
    pages_templates_path = pages_dir / "_templates.py"
    pages_templates_text = pages_templates_path.read_text(encoding="utf-8")
    pages_templates_enabled = _replace_many(pages_templates_text, {"__app_name__": app_name})
    pages_templates_path.write_text(pages_templates_enabled, encoding="utf-8")

    # pages/_templates.py
    pages_templates_path = pages_dir / "default.py"
    pages_templates_text = pages_templates_path.read_text(encoding="utf-8")
    pages_templates_enabled = _replace_many(pages_templates_text, {"__app_name__": app_name})
    pages_templates_path.write_text(pages_templates_enabled, encoding="utf-8")

    # gateway config (optional; only if gateway/ exists OR gateway_config explicitly given)
    if gateway_config:
        gw = project_root / "gateway"
        if not gw.exists() or not gw.is_dir():
            # ここは勝手に作らない（start-projectの責務に寄せる）
            raise AppBuildError("gateway/ does not exist. Run start-project --gateway ... first.")
        _write_gateway_config(
            gw,
            kind=gateway_config,
            app_name=app_name,
            app_port=options.port,
            domain=domain,
        )

    return app_root


def create_auth(
    project_dir: str | Path,
    *,
    options: AppBuildOptions | None = None,
) -> Path:
    options = options or AppBuildOptions(port=7070)

    project_root = Path(project_dir).expanduser().resolve()
    project_root.mkdir(parents=True, exist_ok=True)

    app_root = project_root / "auth"
    if app_root.exists():
        raise FileExistsError(f"Target auth app already exists: {app_root}")
    app_root.mkdir(parents=True, exist_ok=False)

    app_pkg = "nexom.assets.auth"
    for fn in ("__init__.py", "gunicorn.conf.py", "wsgi.py", "config.py"):
        _copy_from_package(app_pkg, fn, app_root / fn)

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

    gunicorn_conf_path = app_root / "gunicorn.conf.py"
    gunicorn_conf_text = gunicorn_conf_path.read_text(encoding="utf-8")
    gunicorn_conf_enabled = _replace_many(gunicorn_conf_text, {"__app_name__": "auth"})
    gunicorn_conf_path.write_text(gunicorn_conf_enabled, encoding="utf-8")

    return app_root


def start_project(
    *,
    project_root: Path,
    main_name: str = "app",
    auth_name: str = "auth",
    main_options: AppBuildOptions | None = None,
    auth_options: AppBuildOptions | None = None,
    gateway: str = "none",  # none|nginx|apache
    domain: str = "",
) -> Path:
    """
    Assumption: user already created the project directory and cd'ed into it.
    So we DO NOT create the project directory itself; we only populate inside.
    """
    _validate_app_name(main_name)
    _validate_app_name(auth_name)

    root = project_root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise AppBuildError("Project root must be an existing directory.")

    # data/
    data_dir = root / "data"
    log_dir = data_dir / "log"
    db_dir = data_dir / "db"
    data_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    # main app + auth app
    main_opt = main_options or AppBuildOptions()
    auth_opt = auth_options or AppBuildOptions(port=7070)

    # auth is usually fixed folder name "auth", but you asked folder name selectable.
    # create_auth creates "auth" fixed, so we generate via create_app then remove extras?
    # ここは仕様を守って assets/app の auth用テンプレを “auth_name” に生成する。
    # => create_app を使ってから不要物を消す、よりは “auth専用生成” を auth_name 対応にする。
    # なので start_project 内で auth側を “auth_name” に生成する専用処理を持つ。

    # main
    create_app(root, main_name, options=main_opt, gateway_config=None)

    # auth (auth_name)
    auth_root = root / auth_name
    if auth_root.exists():
        raise FileExistsError(f"Target app already exists: {auth_root}")
    auth_root.mkdir(parents=True, exist_ok=False)

    app_pkg = "nexom.assets.auth"
    for fn in ("__init__.py", "gunicorn.conf.py", "wsgi.py", "config.py"):
        _copy_from_package(app_pkg, fn, auth_root / fn)

    # config.py
    config_path = auth_root / "config.py"
    config_text = config_path.read_text(encoding="utf-8")
    config_enabled = _replace_many(
        config_text,
        {
            "__prj_dir__": str(root),
            "__app_name__": "auth",
            "__app_dir__": str(auth_root),
            "__g_address__": auth_opt.address,
            "__g_port__": str(auth_opt.port),
            "__g_workers__": str(auth_opt.workers),
            "__g_reload__": "True" if auth_opt.reload else "False",
        },
    )
    config_path.write_text(config_enabled, encoding="utf-8")

    # gunicorn.conf.py
    gunicorn_conf_path = auth_root / "gunicorn.conf.py"
    gunicorn_conf_text = gunicorn_conf_path.read_text(encoding="utf-8")
    gunicorn_conf_enabled = _replace_many(gunicorn_conf_text, {"__app_name__": auth_name})
    gunicorn_conf_path.write_text(gunicorn_conf_enabled, encoding="utf-8")

    # gateway/
    if gateway != "none":
        gw = root / "gateway"
        gw.mkdir(parents=True, exist_ok=True)

        _write_gateway_config(
            gw,
            kind=gateway,
            app_name=main_name,
            app_port=main_opt.port,
            domain=domain,
        )

    return root