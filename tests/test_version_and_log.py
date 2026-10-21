"""Nexom 1.2.0 -- LOG / DB / VER (設計 doc §6 LOG, DB, VER/DEP) から生成。"""
from __future__ import annotations

import os
import re
import stat
from datetime import datetime, timezone
from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest

import nexom
from nexom.app.db import DatabaseManager
from nexom.core import log as nexom_log
from nexom.core.error import PathNotFoundError
from nexom.core.log import AppLogger, AuthLogger, sanitize_log_field

ROOT = Path(__file__).resolve().parent.parent


def _mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def _lines(p: Path) -> list[str]:
    return p.read_text(encoding="utf-8").splitlines()


def _bracket_lines(p: Path) -> list[str]:
    return [l for l in _lines(p) if l.startswith("[")]


# --------------------------------------------------------------------------
# sanitize_log_field (L-1..L-6, L-16d)
# --------------------------------------------------------------------------
def test_L01_newlines_collapsed():
    assert sanitize_log_field("a\nb\rc") == "a\\nb\\rc"
    assert "\n" not in sanitize_log_field("a\nb\rc")


def test_L02_control_chars():
    assert sanitize_log_field("\x00\x1b[31m\x7f") == "\\x00\\x1b[31m\\x7f"


def test_L03_tab():
    assert sanitize_log_field("tab\there") == "tab\\there"


def test_L04_unicode_preserved():
    s = "日本語 🙂 /path?q=1"
    assert sanitize_log_field(s) == s


def test_L05_unicode_line_separators_and_c1():
    assert sanitize_log_field(" \u0085") == "\\u2028\\u0085"
    assert sanitize_log_field(" ") == "\\u2029"
    assert sanitize_log_field("\u009f") == "\\u009f"


def test_L06_none_and_non_str():
    assert sanitize_log_field(None) == "-"
    assert sanitize_log_field(123) == "123"


def test_L06b_backslash_not_double_escaped():
    assert sanitize_log_field("a\\nb") == "a\\nb"


def test_L16d_exported():
    assert "sanitize_log_field" in nexom_log.__all__
    assert {"AppLogger", "AuthLogger"} <= set(nexom_log.__all__)


# --------------------------------------------------------------------------
# AppLogger (L-7..L-14, L-17)
# --------------------------------------------------------------------------
def test_L07_warn_injection_single_line(tmp_path: Path):
    p = tmp_path / "warn.log"
    AppLogger(warn=str(p)).warn("GET /\n[2026-01-01 00:00:00] [INFO] fake")
    lines = _lines(p)
    assert len(lines) == 1
    assert len(_bracket_lines(p)) == 1
    assert lines[0].endswith("[WARN] GET /\\n[2026-01-01 00:00:00] [INFO] fake")


def test_L08_access_line_passthrough(tmp_path: Path):
    p = tmp_path / "access.log"
    msg = '1.2.3.4 "GET /a%0a" 200 1ms "UA"'
    AppLogger(access=str(p)).access(msg)
    lines = _lines(p)
    assert len(lines) == 1 and "%0a" in lines[0] and lines[0].endswith(msg)


def test_L09_error_traceback_indented(tmp_path: Path):
    p = tmp_path / "error.log"
    logger = AppLogger(error=str(p))
    try:
        raise PathNotFoundError("/x\n[INFO] fake")
    except PathNotFoundError as e:
        logger.error(e)
    lines = _lines(p)
    assert re.match(r"^\[[^\]]+\] \[ERROR\] ", lines[0])
    assert lines[0].endswith("P01 -> This path is not found. '/x\\n[INFO] fake'")
    assert len(_bracket_lines(p)) == 1
    assert all(l.startswith("    ") for l in lines[1:]), lines
    assert any(l == "    Traceback (most recent call last):" for l in lines[1:])


def test_L10_error_plain_string(tmp_path: Path):
    p = tmp_path / "error.log"
    AppLogger(error=str(p)).error("plain")
    lines = _lines(p)
    assert len(lines) == 1 and lines[0].endswith("[ERROR] plain")


def test_L11_timestamp_format_and_utc(tmp_path: Path):
    p = tmp_path / "info.log"
    AppLogger(info=str(p)).info("hi")
    line = _lines(p)[0]
    m = re.match(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] ", line)
    assert m
    ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - ts).total_seconds()) < 10
    assert "[INFO] hi" in line


def test_L12_rotation(tmp_path: Path):
    p = tmp_path / "info.log"
    logger = AppLogger(info=str(p), max_bytes=1000, backup_count=2)
    for i in range(50):
        logger.info("x" * 100)
    assert p.exists()
    assert p.stat().st_size <= 1000 + 300
    assert Path(str(p) + ".1").exists() and Path(str(p) + ".2").exists()
    assert not Path(str(p) + ".3").exists()


def test_L13_max_bytes_zero_no_rotation(tmp_path: Path):
    p = tmp_path / "info.log"
    logger = AppLogger(info=str(p), max_bytes=0, backup_count=2)
    for i in range(50):
        logger.info("x" * 100)
    assert len(_lines(p)) == 50
    assert not Path(str(p) + ".1").exists()


def test_L14_no_paths_is_noop():
    lg = AppLogger()
    lg.info("a")
    lg.warn("b")
    lg.error("c")
    lg.error(ValueError("d"))
    lg.access("e")


def test_L17_two_instances_same_path_no_duplicate(tmp_path: Path):
    p = tmp_path / "info.log"
    AppLogger(info=str(p)).info("one")
    AppLogger(info=str(p)).info("two")
    lines = _lines(p)
    assert len(lines) == 2
    assert lines[0].endswith("one") and lines[1].endswith("two")


def test_L18_path_object_accepted(tmp_path: Path):
    p = tmp_path / "w.log"
    AppLogger(warn=p).warn("x")
    assert len(_lines(p)) == 1


# --------------------------------------------------------------------------
# AuthLogger (L-15, L-16*)
# --------------------------------------------------------------------------
def test_L15_login_failed_injection(tmp_path: Path):
    p = tmp_path / "auth.log"
    AuthLogger(p).login_failed(user_id="bob\n[LOGIN_OK] subject=admin", ip="1.1.1.1\r")
    lines = _lines(p)
    assert len(lines) == 1 and len(_bracket_lines(p)) == 1
    assert "subject=bob\\n[LOGIN_OK] subject=admin ip=1.1.1.1\\r" in lines[0]


def test_L16_token_invalid_truncates(tmp_path: Path):
    p = tmp_path / "auth.log"
    AuthLogger(p).token_invalid(token="abcdefghijkl", ip=None)
    assert "subject=abcdefgh... ip=-" in _lines(p)[0]


def test_L16a_event_line_format(tmp_path: Path):
    p = tmp_path / "auth.log"
    AuthLogger(p).event("MASTER_DEACTIVATE", subject="bob", ip="10.0.0.1", detail="by=admin")
    lines = _lines(p)
    assert len(lines) == 1
    assert re.match(
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[MASTER_DEACTIVATE\] "
        r"subject=bob ip=10\.0\.0\.1 detail=by=admin$",
        lines[0],
    )


def test_L16b_event_defaults(tmp_path: Path):
    p = tmp_path / "auth.log"
    AuthLogger(p).event("X", subject="s")
    assert re.search(r"\] \[X\] subject=s ip=- detail=-$", _lines(p)[0])


def test_L16c_event_all_fields_escaped(tmp_path: Path):
    p = tmp_path / "auth.log"
    AuthLogger(p).event("A\n[LOGIN_OK]", subject="s\r", ip="1\n", detail="d\x00")
    lines = _lines(p)
    assert len(lines) == 1 and len(_bracket_lines(p)) == 1
    assert lines[0].endswith("[A\\n[LOGIN_OK]] subject=s\\r ip=1\\n detail=d\\x00")


def test_L19_authlogger_rotation_kwargs(tmp_path: Path):
    p = tmp_path / "auth.log"
    lg = AuthLogger(p, max_bytes=500, backup_count=1)
    for _ in range(40):
        lg.event("E", subject="s" * 50)
    assert Path(str(p) + ".1").exists() and not Path(str(p) + ".2").exists()


# --------------------------------------------------------------------------
# DatabaseManager (DB-1..DB-7)
# --------------------------------------------------------------------------
def test_DB01_default_mode_0600_incl_wal(tmp_path: Path):
    p = tmp_path / "a.db"
    dbm = DatabaseManager(str(p))
    dbm.execute("CREATE TABLE t(x)")
    dbm.execute("INSERT INTO t VALUES (1)")
    assert _mode(p) == 0o600
    for suffix in ("-wal", "-shm"):
        side = Path(str(p) + suffix)
        if side.exists():
            assert _mode(side) == 0o600


def test_DB02_file_mode_none_leaves_umask(tmp_path: Path):
    old = os.umask(0o022)
    try:
        p = tmp_path / "a.db"
        DatabaseManager(str(p), file_mode=None)
        assert _mode(p) == 0o644
    finally:
        os.umask(old)


def test_DB03_custom_mode(tmp_path: Path):
    p = tmp_path / "a.db"
    DatabaseManager(str(p), file_mode=0o640)
    assert _mode(p) == 0o640


def test_DB04_memory_ok():
    DatabaseManager(":memory:")


def test_DB05_pragma_returns_rows(tmp_path: Path):
    dbm = DatabaseManager(str(tmp_path / "a.db"))
    assert [tuple(r) for r in dbm.execute("PRAGMA user_version")] == [(0,)]


def test_DB06_with_cte_returns_rows(tmp_path: Path):
    dbm = DatabaseManager(str(tmp_path / "a.db"))
    assert [tuple(r) for r in dbm.execute("WITH a AS (SELECT 1) SELECT * FROM a")] == [(1,)]


def test_DB07_dml_returns_none(tmp_path: Path):
    dbm = DatabaseManager(str(tmp_path / "a.db"))
    assert dbm.execute("CREATE TABLE t(x)") is None
    assert dbm.execute("INSERT INTO t VALUES (1)") is None
    assert [tuple(r) for r in dbm.execute("SELECT x FROM t")] == [(1,)]


# --------------------------------------------------------------------------
# VER / DEP
# --------------------------------------------------------------------------
def _pyproject() -> str:
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_V01_version_from_metadata():
    assert nexom.__version__ == pkg_version("nexom")
    assert re.match(r"^\d+\.\d+\.\d+", nexom.__version__)
    assert nexom.__version__ != "1.1.0"
    assert "__version__" in nexom.__all__


def test_V02_version_matches_pyproject_1_2_0():
    m = re.search(r'^version\s*=\s*"([^"]+)"', _pyproject(), re.M)
    assert m and m.group(1) == "1.2.0"
    assert nexom.__version__ == m.group(1)


def test_V03_dependency_floors():
    t = _pyproject()
    for dep in ('"gunicorn>=22.0.0"', '"multipart>=1.3.1,<3"', '"Pillow>=12.3.0"'):
        assert dep in t
    for old in ("gunicorn>=21.2", "multipart>=1.3.0", "Pillow>=10.0"):
        assert old not in t


def test_V04_requires_python_unchanged():
    assert re.search(r'^requires-python\s*=\s*">=3\.10"', _pyproject(), re.M)


def test_V05_no_naxom_typo_in_run():
    assert "naxom" not in (ROOT / "src" / "nexom" / "buildTools" / "run.py").read_text(encoding="utf-8")
