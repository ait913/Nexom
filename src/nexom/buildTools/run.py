from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class DetectedApp:
    name: str
    dir: Path
    wsgi: Path
    gunicorn_conf: Path


class RunError(RuntimeError):
    """Raised when naxom run fails."""


def _is_windows() -> bool:
    return os.name == "nt" or platform.system().lower() == "windows"


def _detect_apps(project_root: Path) -> list[DetectedApp]:
    root = project_root.resolve()
    if not root.exists() or not root.is_dir():
        raise RunError("Project root is not a directory.")

    apps: list[DetectedApp] = []
    for p in root.iterdir():
        if not p.is_dir():
            continue
        wsgi = p / "wsgi.py"
        conf = p / "gunicorn.conf.py"
        if wsgi.exists() and conf.exists():
            apps.append(
                DetectedApp(
                    name=p.name,
                    dir=p,
                    wsgi=wsgi,
                    gunicorn_conf=conf,
                )
            )
    return sorted(apps, key=lambda a: a.name)


def _require_gunicorn() -> str:
    gunicorn = shutil.which("gunicorn")
    if not gunicorn:
        raise RunError("gunicorn not found in PATH. Install it (pip install gunicorn).")
    return gunicorn


def _build_cmd(gunicorn_bin: str, app: DetectedApp) -> list[str]:
    # project root を PYTHONPATH に入れて、"appdir.wsgi:app" が import できる前提
    target = f"{app.name}.wsgi:app"
    return [gunicorn_bin, target, "--config", str(app.gunicorn_conf)]


def run_project(
    project_root: Path,
    app_names: list[str] | None = None,
    *,
    dry_run: bool = False,
) -> None:
    """
    Run WSGI apps in a Nexom project directory.

    - Detect apps: directories that contain both wsgi.py and gunicorn.conf.py.
    - If app_names is empty -> run all detected apps.
    - Else -> run only the specified ones.

    Notes:
    - Uses subprocess to start gunicorn (stable + predictable).
    - On Windows: gunicorn isn't supported (POSIX only) -> raise clear error.
    """
    if _is_windows():
        raise RunError("naxom run is not supported on Windows (gunicorn is POSIX-only).")

    root = project_root.resolve()
    apps = _detect_apps(root)
    if not apps:
        raise RunError("No runnable apps found. (Need <app>/wsgi.py and <app>/gunicorn.conf.py)")

    app_map = {a.name: a for a in apps}

    selected: list[DetectedApp]
    if not app_names:
        selected = apps
    else:
        missing = [n for n in app_names if n not in app_map]
        if missing:
            raise RunError(f"App not found: {', '.join(missing)}")
        selected = [app_map[n] for n in app_names]

    gunicorn = _require_gunicorn()

    # 重要: project root を import 解決に使う
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    procs: list[subprocess.Popen[bytes]] = []
    cmds: list[tuple[str, list[str]]] = []

    for app in selected:
        cmd = _build_cmd(gunicorn, app)
        cmds.append((app.name, cmd))

    if dry_run:
        for name, cmd in cmds:
            print(f"[dry-run] {name}: {' '.join(cmd)}")
        return

    # 起動
    for name, cmd in cmds:
        print(f"[run] starting {name}")
        # 新しいプロセスグループにして、まとめて止めやすくする（POSIX）
        p = subprocess.Popen(
            cmd,
            cwd=str(root),
            env=env,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr.buffer,
            start_new_session=True,
        )
        procs.append(p)

    def _terminate_all(sig: int) -> None:
        # まず優しく
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except Exception:
                    try:
                        p.terminate()
                    except Exception:
                        pass

        # 少し待つ
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if all(p.poll() is not None for p in procs):
                return
            time.sleep(0.05)

        # 最後は強制
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass

    # 親が落ちる/止まる時にまとめて止める
    def _handle_signal(_signum: int, _frame) -> None:
        _terminate_all(_signum)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # どれか1つ死んだら全体止める（中途半端が一番事故る）
    try:
        while True:
            for p in procs:
                code = p.poll()
                if code is not None:
                    raise RunError(f"Process exited (pid={p.pid}, code={code})")
            time.sleep(0.2)
    except KeyboardInterrupt:
        _terminate_all(signal.SIGINT)
    except Exception:
        _terminate_all(signal.SIGTERM)
        raise