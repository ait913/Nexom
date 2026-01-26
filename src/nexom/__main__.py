from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nexom.buildTools.build import (
    create_app,
    create_auth,
    start_project,
    AppBuildOptions,
)
from nexom.buildTools.run import run_project


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="naxom",
        description="Nexom Web Framework CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # test
    subparsers.add_parser("test", help="Test Nexom installation")

    # run
    pr = subparsers.add_parser("run", help="Run WSGI apps found in the current project directory")
    pr.add_argument("apps", nargs="*", help="App directory names to run (default: all detected apps)")
    pr.add_argument("--root", default=".", help="Project root directory (default: .)")
    pr.add_argument("--dry-run", action="store_true", help="Print commands only (do not start processes)")

    # start-project
    sp = subparsers.add_parser(
        "start-project",
        help="Initialize a Nexom project in the current directory (creates app/auth/data[/gateway])",
    )
    sp.add_argument("--root", default=".", help="Project root directory (default: .)")
    sp.add_argument("--main-name", default="app", help="Main app directory name (default: app)")
    sp.add_argument("--auth-name", default="auth", help="Auth app directory name (default: auth)")
    sp.add_argument(
        "--gateway",
        choices=["none", "nginx", "apache"],
        default="none",
        help="Create gateway/ and put a template config (default: none)",
    )
    sp.add_argument("--domain", default="", help="Domain for gateway template (default: placeholder text)")

    # ports etc (main)
    sp.add_argument("--address", default="0.0.0.0", help="Bind address for main app (default: 0.0.0.0)")
    sp.add_argument("--port", type=int, default=8080, help="Bind port for main app (default: 8080)")
    sp.add_argument("--workers", type=int, default=4, help="Gunicorn workers for main app (default: 4)")
    sp.add_argument("--reload", action="store_true", help="Enable auto-reload for main app (development)")

    # ports etc (auth)
    sp.add_argument("--auth-address", default="127.0.0.1", help="Bind address for auth app (default: 0.0.0.0)")
    sp.add_argument("--auth-port", type=int, default=7070, help="Bind port for auth app (default: 7070)")
    sp.add_argument("--auth-workers", type=int, default=4, help="Gunicorn workers for auth app (default: 4)")
    sp.add_argument("--auth-reload", action="store_true", help="Enable auto-reload for auth app (development)")

    # create-auth
    pa = subparsers.add_parser("create-auth", help="Create a Nexom auth app project")
    pa.add_argument("--out", default=".", help="Output directory (default: current directory)")
    pa.add_argument("--address", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    pa.add_argument("--port", type=int, default=7070, help="Bind port (default: 7070)")
    pa.add_argument("--workers", type=int, default=4, help="Gunicorn workers (default: 4)")
    pa.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")

    # create-app
    p = subparsers.add_parser("create-app", help="Create a Nexom app project")
    p.add_argument("app_name", help="App project name")
    p.add_argument("--out", default=".", help="Output directory (default: current directory)")
    p.add_argument("--address", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    p.add_argument("--workers", type=int, default=4, help="Gunicorn workers (default: 4)")
    p.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    p.add_argument(
        "--gateway-config",
        choices=["nginx", "apache"],
        default="",
        help="If gateway/ exists, write a config template for this app (nginx/apache)",
    )
    p.add_argument("--domain", default="", help="Domain for gateway template (default: placeholder text)")

    args = parser.parse_args(argv)

    if args.command == "test":
        print("Hello Nexom Web Framework!")
        return

    if args.command == "run":
        run_project(Path(args.root), list(args.apps), dry_run=bool(args.dry_run))
        return

    if args.command == "start-project":
        main_opt = AppBuildOptions(
            address=args.address,
            port=args.port,
            workers=args.workers,
            reload=args.reload,
        )
        auth_opt = AppBuildOptions(
            address=args.auth_address,
            port=args.auth_port,
            workers=args.auth_workers,
            reload=args.auth_reload,
        )
        out = start_project(
            project_root=Path(args.root),
            main_name=args.main_name,
            auth_name=args.auth_name,
            main_options=main_opt,
            auth_options=auth_opt,
            gateway=args.gateway,
            domain=args.domain,
        )
        print(f"Initialized Nexom project at: {out}")
        return

    if args.command == "create-app":
        options = AppBuildOptions(
            address=args.address,
            port=args.port,
            workers=args.workers,
            reload=args.reload,
        )
        out_dir = create_app(
            Path(args.out),
            args.app_name,
            options=options,
            gateway_config=(args.gateway_config or None),
            domain=args.domain,
        )
        print(f"Created Nexom app project at: {out_dir}")
        return

    if args.command == "create-auth":
        options = AppBuildOptions(
            address=args.address,
            port=args.port,
            workers=args.workers,
            reload=args.reload,
        )
        out_dir = create_auth(Path(args.out), options=options)
        print(f"Created Nexom auth app project at: {out_dir}")
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)