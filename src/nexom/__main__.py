from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nexom.buildTools.build import server as build_app
from nexom.buildTools.build import ServerBuildOptions


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nexom",
        description="Nexom Web Framework CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # test
    subparsers.add_parser("test", help="Test Nexom installation")

    # build-app
    p = subparsers.add_parser(
        "build-app",
        help="Create a Nexom app project",
    )
    p.add_argument("app_name", help="App project name")
    p.add_argument(
        "--out",
        default=".",
        help="Output directory (default: current directory)",
    )
    p.add_argument("--address", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    p.add_argument("--workers", type=int, default=4, help="Gunicorn workers (default: 4)")
    p.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")

    args = parser.parse_args(argv)

    if args.command == "test":
        print("Hello Nexom Web Framework!")
        return

    if args.command == "build-app":
        options = ServerBuildOptions(
            address=args.address,
            port=args.port,
            workers=args.workers,
            reload=args.reload,
        )
        out_dir = build_app(Path(args.out), args.app_name, options=options)
        print(f"Created Nexom app project at: {out_dir}")
        return


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # CLI では stacktrace よりまずメッセージ優先（必要なら後で --verbose とか足す）
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)