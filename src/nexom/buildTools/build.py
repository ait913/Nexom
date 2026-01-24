from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
import shutil


@dataclass(frozen=True)
class ServerBuildOptions:
    """Options used to fill generated config.py."""
    address: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    reload: bool = False


def _copy_from_package(pkg: str, filename: str, dest: Path) -> None:
    """
    Copy a file from a package resource into the destination path.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    with resources.files(pkg).joinpath(filename).open("rb") as src, dest.open("wb") as dst:
        shutil.copyfileobj(src, dst)


def server(work_dir: str | Path, name: str, *, options: ServerBuildOptions | None = None) -> Path:
    """
    Generate a Nexom server project into `work_dir`.

    This function copies template files bundled in the package (assets) and
    writes a ready-to-run config.py.

    Args:
        work_dir: Output directory where project files are created.
        name: Project name (reserved for future use; currently not used).
        options: Config defaults for generated config.py.

    Returns:
        The absolute path to the generated project directory.

    Raises:
        FileExistsError: If target directories/files already exist.
        ModuleNotFoundError / FileNotFoundError: If bundled assets are missing.
    """
    _ = name  # reserved (keep signature stable for future)
    options = options or ServerBuildOptions()

    out_dir = Path(work_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    pages_dir = out_dir / "pages"
    templates_dir = out_dir / "templates"
    static_dir = out_dir / "static"

    # Make sure we don't accidentally overwrite a project
    for d in (pages_dir, templates_dir, static_dir):
        if d.exists():
            raise FileExistsError(f"Already exists: {d}")

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
    for fn in ("gunicorn.conf.py", "router.py", "wsgi.py", "config.py"):
        _copy_from_package(app_pkg, fn, out_dir / fn)

    # ---- Enable settings (format config.py) ----
    config_path = out_dir / "config.py"
    config_text = config_path.read_text(encoding="utf-8")

    # NOTE: pwd_dir should be the generated project directory, not current cwd.
    enabled = config_text.format(
        pwd_dir=str(out_dir),
        g_address=options.address,
        g_port=options.port,
        g_workers=options.workers,
        g_reload=options.reload,
    )
    config_path.write_text(enabled, encoding="utf-8")

    return out_dir