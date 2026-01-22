from pathlib import Path

from nexom.web.path import Static
from nexom.web.request import Request
from nexom.core.error import PathNotFoundError

def test_static_serves_file(tmp_path: Path, make_environ):
    # tmp_path/static/hello.txt を作る
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "hello.txt").write_bytes(b"hi")

    s = Static("static/", str(static_dir), "Static")

    req = Request(make_environ(path="/static/hello.txt"))
    res = s.call_handler(req)

    assert res.body == b"hi"


def test_static_blocks_traversal(tmp_path: Path, make_environ):
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (tmp_path / "secret.txt").write_bytes(b"nope")

    s = Static("static/", str(static_dir), "Static")

    # ../secret.txt を狙う
    req = Request(make_environ(path="/static/../secret.txt"))
    try:
        s.call_handler(req)
        assert False, "should raise"
    except PathNotFoundError:
        assert True