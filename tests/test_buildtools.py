from __future__ import annotations

from pathlib import Path
import pytest


def test_build_server_creates_structure_and_formats_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    buildTools.server() が
    - pages/templates/static ディレクトリを作る
    - config.py を format して書き込む
    を確認する（assets依存は monkeypatch で切る）
    """
    # import できること（これがまず大事）
    import nexom.buildTools.build as build

    # build.server が存在すること
    assert hasattr(build, "server")
    server = build.server

    # build.ServerBuildOptions があるなら使う（ない実装でも通るようにする）
    options = None
    if hasattr(build, "ServerBuildOptions"):
        options = build.ServerBuildOptions(address="127.0.0.1", port=9001, workers=2, reload=True)

    # assetsコピー部分を潰して、代わりにダミーファイルを書き出す
    def fake_copy(pkg: str, filename: str, dest: Path) -> None:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)

        # config.py は format 対象なのでテンプレ文字列を入れる
        if dest.name == "config.py":
            dest.write_text(
                "\n".join(
                    [
                        "# dummy config template",
                        'directory = "{pwd_dir}"',
                        "_address = \"{g_address}\"",
                        "_port = {g_port}",
                        "_workers = {g_workers}",
                        "_reload = {g_reload}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            return

        # それ以外は空でもOK（存在確認用）
        if dest.suffix in (".py", ".html"):
            dest.write_text("# dummy\n", encoding="utf-8")
        else:
            dest.write_bytes(b"dummy")

    # refactor版だと module-level に _copy_from_package がある想定
    if hasattr(build, "_copy_from_package"):
        monkeypatch.setattr(build, "_copy_from_package", fake_copy)
    else:
        # 旧版（関数内に _copy がある）だと monkeypatch が難しいので skip
        pytest.skip("build._copy_from_package not found (old build.py). Please adopt refactored build.py for testing.")

    out_dir = tmp_path / "out"

    # 実行
    if options is not None:
        result = server(out_dir, "myapp", options=options)
    else:
        result = server(out_dir, "myapp")

    # 戻り値が Path ならそれを採用（実装差吸収）
    project_dir = Path(result) if result is not None else out_dir

    # ディレクトリができてる
    assert (project_dir / "pages").exists()
    assert (project_dir / "templates").exists()
    assert (project_dir / "static").exists()

    # config が生成されて、format が反映されてる
    cfg = (project_dir / "config.py").read_text(encoding="utf-8")
    assert str(project_dir) in cfg  # directory = "{pwd_dir}" が埋まる
    assert "_port = 9001" in cfg if options is not None else "_port" in cfg


def test_build_server_raises_if_target_exists(tmp_path: Path):
    import nexom.buildTools.build as build

    # 既に pages がある状態を作る
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "pages").mkdir()

    with pytest.raises(FileExistsError):
        # options 引数がある/ない両対応
        if hasattr(build, "ServerBuildOptions"):
            opts = build.ServerBuildOptions()
            build.server(out_dir, "x", options=opts)
        else:
            build.server(out_dir, "x")