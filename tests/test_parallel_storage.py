"""ParallelStorage 1.2.0 (storage-deps-hardening) -- 設計 doc §6 PS-A..F から生成。

実装コードは参照せず、doc の公開 API のみに依拠する。テスト名の ID は doc §6 の行 ID。
"""
from __future__ import annotations

import hashlib
import math
import os
import shutil
import sqlite3
import stat
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from nexom.app.parallel_storage import (
    DEFAULT_MAX_IMAGE_PIXELS,
    IMAGE_QUALITY_STEPS,
    IMAGE_SIZE_STEPS,
    Classification,
    FileMeta,
    GcReport,
    MultiPartUploader,
    ParallelStorage,
    ParallelStorageDBM,
    classify_file,
    expected_chunk_size,
    format_psc_filename,
    normalize_image_variant,
    psc_response_headers,
)
from nexom.core.error import (
    NexomError,
    PsArgmentsError,
    PsChunkEntityTooLargeError,
    PsChunkHashMismatchError,
    PsChunkSizeMismatchError,
    PsContentsIDInvalidError,
    PsDataCorruotedError,
    PsFileStatusInvalidError,
    PsFileTypesError,
    PsImageTooLargeError,
    PsPathEscapeError,
    PsPermissionError,
    PsPublicIDInvalidError,
    PsStatusTypesError,
    PsSuffixInvalidError,
    PsTooManyActiveUploadsError,
    PsUploadTooLargeError,
)

MIB = 1024 * 1024


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _img_bytes(fmt: str, size=(10, 10), color=(255, 0, 0), mode="RGB", **kw) -> bytes:
    buf = BytesIO()
    Image.new(mode, size, color).save(buf, format=fmt, **kw)
    return buf.getvalue()


def _bomb_png(side: int) -> bytes:
    buf = BytesIO()
    Image.new("1", (side, side), 1).save(buf, format="PNG")
    return buf.getvalue()


def _mode(p: Path) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def _split(data: bytes, total: int) -> list[bytes]:
    chunk = math.ceil(len(data) / total)
    return [data[i * chunk:(i + 1) * chunk] for i in range(total)]


def _upload(up, pid, filename, data, total_chunks=1, commit=True):
    """register -> 全チャンク -> (commit)。commit=True なら FileMeta、False なら public_id。"""
    pub = up.register(filename, len(data), pid, total_chunks, _sha(data))
    for i, part in enumerate(_split(data, total_chunks)):
        up.parts_upload(pid, pub, i, part, _sha(part))
    if commit:
        return up.commit(pid, pub)
    return pub


@pytest.fixture
def env(tmp_path: Path):
    db = tmp_path / "ps.db"
    workers = tmp_path / "workers"
    contents = tmp_path / "contents"
    up = MultiPartUploader(str(db), str(workers), str(contents), min_chunk_size=1)
    ps = ParallelStorage(str(db), str(contents), str(workers))
    return SimpleNamespace(
        tmp=tmp_path, db=db, workers=workers, contents=contents, up=up, ps=ps
    )


def _sql(env, sql, *args):
    con = sqlite3.connect(str(env.db))
    try:
        cur = con.execute(sql, args)
        rows = cur.fetchall()
        con.commit()
        return rows
    finally:
        con.close()


def _committed(env, pid="A", filename="a.txt", data=b"hello"):
    meta = _upload(env.up, pid, filename, data)
    return meta


def _contents_files(env):
    return sorted(p.name for p in env.contents.iterdir()) if env.contents.exists() else []


# --------------------------------------------------------------------------
# 既存テスト移行 (B-5 / E-9,10,19 / B-3 / format_public_id)
# --------------------------------------------------------------------------
def test_B05_format_psc_filename_order():
    assert format_psc_filename("cid", ".txt", b=2, a=1, z=None) == "cid__PSC_a-1_b-2.txt"


def test_E19_multipart_upload_and_commit(env):
    data = b"hello-world-012345"
    pub = env.up.register("file.txt", len(data), "pid", 2, _sha(data))
    c1, c2 = data[:9], data[9:]
    env.up.parts_upload("pid", pub, 0, c1, _sha(c1))
    env.up.parts_upload("pid", pub, 1, c2, _sha(c2))
    meta = env.up.commit("pid", pub)
    dest = env.contents / format_psc_filename(meta.contents_id, meta.suffix)
    assert meta.status == "COMMITTED"
    assert dest.exists()
    assert dest.read_bytes() == data
    assert not (env.workers / pub).exists()


def test_B03_update_suffix_lowercases_and_sets_original(env):
    pub = env.up.register("file.txt", 1, "pid", 1, _sha(b"x"))
    env.ps.update_suffix("pid", pub, ".BIN")
    meta = env.ps.getMeta("pid", pub)
    assert meta.suffix == ".bin"
    assert meta.original_suffix == ".bin"


def test_format_public_id_existing_expectation(env):
    meta = _committed(env, "pid", "file.txt", b"x")
    path = env.ps.format_psc_public_id(None, meta.public_id, v=1, a=2)
    assert path.name.endswith("__PSC_a-2_v-1.txt")


# --------------------------------------------------------------------------
# PS-A 認可
# --------------------------------------------------------------------------
def test_A01_delete_by_other_pid_denied_row_and_file_remain(env):
    m = _committed(env)
    with pytest.raises(PsPermissionError):
        env.ps.delete("B", m.public_id)
    assert env.ps.getMeta(None, m.public_id).contents_id == m.contents_id
    assert any("__PSC_" in n for n in _contents_files(env))


def test_A02_dbm_remove_by_other_pid_denied_row_remains(env):
    m = _committed(env)
    with pytest.raises(PsPermissionError):
        env.ps._PSDBM.remove("B", public_id=m.public_id)
    assert env.ps.getMeta(None, m.public_id).pid == "A"


def test_A02b_dbm_remove_by_contents_id_other_pid_denied(env):
    m = _committed(env)
    with pytest.raises(PsPermissionError):
        env.ps._PSDBM.remove("B", contents_id=m.contents_id)
    assert env.ps.getMeta(None, m.public_id).pid == "A"


def test_A02c_dbm_remove_pid_none_not_allowed(env):
    m = _committed(env)
    with pytest.raises((PsPermissionError, PsArgmentsError, TypeError)):
        env.ps._PSDBM.remove(None, public_id=m.public_id)
    assert env.ps.getMeta(None, m.public_id).pid == "A"


def test_A03_dbm_remove_by_owner_ok(env):
    m = _committed(env)
    env.ps._PSDBM.remove("A", public_id=m.public_id)
    with pytest.raises(PsPublicIDInvalidError):
        env.ps.getMeta(None, m.public_id)


def test_A04_dbm_remove_force_by_other_pid(env):
    m = _committed(env)
    env.ps._PSDBM.remove("B", public_id=m.public_id, force=True)
    with pytest.raises(PsPublicIDInvalidError):
        env.ps.getMeta(None, m.public_id)


def test_A05_delete_force_removes_row_file_and_workdir(env):
    m = _committed(env)
    env.ps.delete("B", m.public_id, force=True)
    with pytest.raises(PsPublicIDInvalidError):
        env.ps.getMeta(None, m.public_id)
    assert not any("__PSC_" in n for n in _contents_files(env))
    # 作業ディレクトリ
    pub = env.up.register("w.bin", 10, "A", 1, _sha(b"0123456789"))
    assert (env.workers / pub).is_dir()
    env.ps.delete("B", pub, force=True)
    assert not (env.workers / pub).exists()


def test_A06_A07_A08_getMeta_capability_model_both_directions(env):
    m = _committed(env)
    with pytest.raises(PsPermissionError):
        env.ps.getMeta("B", m.public_id)
    # 負のコントロール: None 明示の参照は通る / 所有者も通る
    assert isinstance(env.ps.getMeta(None, m.public_id), FileMeta)
    assert env.ps.getMeta("A", m.public_id).public_id == m.public_id


def test_A09_format_and_comp_img_other_pid_denied_no_cache(env):
    m = _upload(env.up, "A", "i.png", _img_bytes("PNG"))
    before = _contents_files(env)
    with pytest.raises(PsPermissionError):
        env.ps.format_psc_public_id("B", m.public_id)
    with pytest.raises(PsPermissionError):
        env.ps.comp_img("B", m.public_id, 64, None, None)
    assert _contents_files(env) == before
    # 負のコントロール: None / 所有者は通る
    env.ps.format_psc_public_id(None, m.public_id)
    env.ps.comp_img("A", m.public_id, 64, None, None)


def test_A10_update_suffix_other_pid_denied(env):
    pub = env.up.register("f.txt", 1, "A", 1, _sha(b"x"))
    with pytest.raises(PsPermissionError):
        env.ps.update_suffix("B", pub, ".md")
    assert env.ps.getMeta(None, pub).suffix == ".txt"
    # 負のコントロール: 所有者は通る
    env.ps.update_suffix("A", pub, ".md")
    assert env.ps.getMeta(None, pub).suffix == ".md"


def test_A10b_update_suffix_pid_none_rejected(env):
    pub = env.up.register("f.txt", 1, "A", 1, _sha(b"x"))
    with pytest.raises((PsPermissionError, PsArgmentsError, TypeError)):
        env.ps.update_suffix(None, pub, ".md")
    assert env.ps.getMeta(None, pub).suffix == ".txt"


def test_A11_dbm_mutators_other_pid_denied_row_unchanged(env):
    pub = env.up.register("f.txt", 1, "A", 1, _sha(b"x"))
    dbm = env.ps._PSDBM
    row = dbm.getMeta(public_id=pub)
    cid = row.contents_id
    calls = [
        lambda: dbm.status_change("B", cid, "ABORTED"),
        lambda: dbm.update_types("B", cid, "Binary"),
        lambda: dbm.update_suffix("B", cid, ".txt"),
        lambda: dbm.update_public_id("B", cid),
        lambda: dbm.finalize_commit("B", cid, types="Binary", suffix=".bin"),
    ]
    for c in calls:
        with pytest.raises(PsPermissionError):
            c()
    assert dbm.getMeta(public_id=pub) == row


def test_A11b_dbm_owner_mutators_work_and_force_overrides(env):
    pub = env.up.register("f.txt", 1, "A", 1, _sha(b"x"))
    dbm = env.ps._PSDBM
    cid = dbm.getMeta(public_id=pub).contents_id
    dbm.status_change("A", cid, "ERROR")  # ERROR が許容リストに在る (§4.3)
    assert dbm.getMeta(contents_id=cid).status == "ERROR"
    dbm.status_change("B", cid, "ABORTED", force=True)
    assert dbm.getMeta(contents_id=cid).status == "ABORTED"
    new_pub = dbm.update_public_id("A", cid)
    assert new_pub != pub
    assert dbm.getMeta(contents_id=cid).public_id == new_pub
    with pytest.raises(PsStatusTypesError):
        dbm.status_change("A", cid, "BOGUS")


def test_A11c_dbm_getMeta_pid_filter(env):
    pub = env.up.register("f.txt", 1, "A", 1, _sha(b"x"))
    dbm = env.ps._PSDBM
    with pytest.raises(PsPermissionError):
        dbm.getMeta(public_id=pub, pid="B")
    assert dbm.getMeta(public_id=pub, pid="A").pid == "A"
    assert dbm.getMeta(public_id=pub).pid == "A"


def test_A12_parts_upload_other_pid_denied_nothing_written(env):
    data = b"0123456789"
    pub = env.up.register("f.bin", len(data), "A", 1, _sha(data))
    with pytest.raises(PsPermissionError):
        env.up.parts_upload("B", pub, 0, data, _sha(data))
    assert env.ps.getMeta(None, pub).status == "INIT"


def test_A13_commit_other_pid_denied_state_unchanged(env):
    data = b"0123456789"
    pub = _upload(env.up, "A", "f.bin", data, commit=False)
    with pytest.raises(PsPermissionError):
        env.up.commit("B", pub)
    assert (env.workers / pub).is_dir()
    assert env.ps.getMeta(None, pub).status == "READY"


def test_A14_unknown_but_wellformed_public_id(env):
    with pytest.raises(PsPublicIDInvalidError):
        env.ps.getMeta(None, "a" * 32)


BAD_IDS = ["../x", "", "a" * 15, "a" * 65, "a b", "../../etc/passwd" + "x" * 20]


@pytest.mark.parametrize("bad", BAD_IDS)
def test_A15_malformed_public_id_rejected_everywhere(env, bad):
    data = b"0123456789"
    sha = _sha(data)
    calls = [
        lambda: env.ps.getMeta(None, bad),
        lambda: env.ps.format_psc_public_id(None, bad),
        lambda: env.ps.comp_img(None, bad, 64, None, None),
        lambda: env.ps.update_suffix("A", bad, ".txt"),
        lambda: env.ps.delete("A", bad),
        lambda: env.up.parts_upload("A", bad, 0, data, sha),
        lambda: env.up.commit("A", bad),
    ]
    for c in calls:
        with pytest.raises(PsPublicIDInvalidError):
            c()


@pytest.mark.parametrize("pid", ["", None])
def test_A16_register_requires_pid(env, pid):
    with pytest.raises(PsArgmentsError) as ei:
        env.up.register("f.bin", 10, pid, 1, _sha(b"x"))
    assert "pid" in str(ei.value)
    assert env.ps._PSDBM.count_active("A") == 0


def test_A17_dbm_register_has_no_permission_id(env):
    with pytest.raises(TypeError):
        env.ps._PSDBM.register("f", ".txt", 1, "A", original_suffix=None, permission_id=None)


def test_A17b_uploader_register_old_six_arg_call_is_typeerror(env):
    with pytest.raises(TypeError):
        env.up.register("f.txt", 1, "A", None, 1, _sha(b"x"))


def test_A18_update_status_removed(env):
    assert not hasattr(env.ps, "update_status")


# --------------------------------------------------------------------------
# PS-B 拡張子・パス
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad", ["./../../evil", ".tar.gz", ".x y", ".\x00", "bin", "", "." + "a" * 17]
)
def test_B01_B02_update_suffix_rejects_bad_suffix(env, bad):
    pub = env.up.register("f.txt", 1, "A", 1, _sha(b"x"))
    with pytest.raises(PsSuffixInvalidError):
        env.ps.update_suffix("A", pub, bad)
    assert env.ps.getMeta(None, pub).suffix == ".txt"


def test_B04_update_suffix_on_committed_rejected(env):
    m = _committed(env)
    with pytest.raises(PsFileStatusInvalidError):
        env.ps.update_suffix("A", m.public_id, ".md")
    assert env.ps.getMeta(None, m.public_id).suffix == ".txt"


@pytest.mark.parametrize("kw", [{"w": "../x"}, {"a/b": 1}])
def test_B06_format_psc_filename_rejects_bad_kwargs(kw):
    with pytest.raises(PsArgmentsError):
        format_psc_filename("cid", ".txt", **kw)


def test_B07_format_psc_filename_rejects_bad_cid_and_suffix():
    with pytest.raises(PsArgmentsError) as ei:
        format_psc_filename("../cid", ".txt")
    assert "contents_id" in str(ei.value)
    with pytest.raises(PsSuffixInvalidError):
        format_psc_filename("cid", "../x")


def test_B08_format_psc_public_id_is_direct_child_of_contents(env):
    m = _committed(env)
    p = env.ps.format_psc_public_id(None, m.public_id)
    assert p.parent == env.contents.resolve()


def test_B09_tampered_db_suffix_is_caught(env):
    m = _committed(env)
    _sql(env, "UPDATE parallel_storage SET suffix=? WHERE public_id=?", "./../../evil", m.public_id)
    with pytest.raises((PsSuffixInvalidError, PsPathEscapeError)) as ei:
        env.ps.format_psc_public_id(None, m.public_id)
    assert isinstance(ei.value, PsSuffixInvalidError)  # doc B-9 は PsSuffixInvalidError


def test_B10_register_path_traversal_filename(env):
    pub = env.up.register("../../etc/passwd", 1, "A", 1, _sha(b"x"))
    meta = env.ps.getMeta(None, pub)
    assert meta.filename == "passwd"
    assert meta.suffix == ".bin"
    assert meta.original_suffix is None


def test_B11_register_uppercase_suffix_lowercased(env):
    pub = env.up.register("a.PNG", 1, "A", 1, _sha(b"x"))
    meta = env.ps.getMeta(None, pub)
    assert meta.suffix == ".png"
    assert meta.original_suffix == ".png"


def test_B12_register_nul_suffix(env):
    pub = env.up.register("x.\x00", 1, "A", 1, _sha(b"x"))
    meta = env.ps.getMeta(None, pub)
    assert meta.suffix == ".bin"
    assert meta.original_suffix is None


# --------------------------------------------------------------------------
# PS-C 分類
# --------------------------------------------------------------------------
GIF = _img_bytes("GIF", mode="P", color=1)
POLY = GIF + b"<script>alert(1)</script>"


def test_C01_polyglot_html_becomes_gif(env):
    m = _upload(env.up, "A", "poly.html", POLY)
    assert (m.types, m.suffix, m.original_suffix) == ("Images", ".gif", ".html")
    names = _contents_files(env)
    assert names == [f"{m.contents_id}__PSC_.gif"]


def test_C02_polyglot_svg_becomes_gif(env):
    m = _upload(env.up, "A", "poly.svg", POLY)
    assert (m.types, m.suffix) == ("Images", ".gif")
    assert _contents_files(env) == [f"{m.contents_id}__PSC_.gif"]


def test_C03_plain_svg_is_binary_bin(env):
    m = _upload(env.up, "A", "a.svg", b"<svg onload=alert(1)></svg>")
    assert (m.types, m.suffix, m.original_suffix) == ("Binary", ".bin", ".svg")
    assert _contents_files(env) == [f"{m.contents_id}__PSC_.bin"]


def test_C04_html_is_binary_bin(env):
    m = _upload(env.up, "A", "a.html", b"<html><script>1</script></html>")
    assert (m.types, m.suffix) == ("Binary", ".bin")
    assert _contents_files(env) == [f"{m.contents_id}__PSC_.bin"]


def test_C05_jpeg_bytes_png_name(env):
    m = _upload(env.up, "A", "a.png", _img_bytes("JPEG"))
    assert (m.types, m.suffix, m.original_suffix) == ("Images", ".jpg", ".png")
    assert _contents_files(env) == [f"{m.contents_id}__PSC_.jpg"]


def test_C06_png_bytes_jpeg_name(env):
    m = _upload(env.up, "A", "a.jpeg", _img_bytes("PNG"))
    assert m.suffix == ".png"


def test_C06b_webp_bytes_gets_webp(env):
    m = _upload(env.up, "A", "a.dat", _img_bytes("WEBP"))
    assert (m.types, m.suffix) == ("Images", ".webp")


def test_C07_text_document(env):
    m = _upload(env.up, "A", "a.txt", b"hello")
    assert (m.types, m.suffix) == ("Documents", ".txt")
    assert _contents_files(env) == [f"{m.contents_id}__PSC_.txt"]


def test_C08_exe_is_dangerous_bin(env):
    m = _upload(env.up, "A", "a.exe", b"hello")
    assert (m.types, m.suffix) == ("Dangerous", ".bin")
    assert _contents_files(env) == [f"{m.contents_id}__PSC_.bin"]


def test_C09_bmp_is_binary_bin(env):
    m = _upload(env.up, "A", "a.bmp", _img_bytes("BMP"))
    assert (m.types, m.suffix) == ("Binary", ".bin")


def test_C10_pixel_bomb_rejected_status_error_cleanup(env):
    data = _bomb_png(12000)
    pub = _upload(env.up, "A", "bomb.png", data, commit=False)
    with pytest.raises(PsImageTooLargeError):
        env.up.commit("A", pub)
    assert env.ps.getMeta(None, pub).status == "ERROR"
    assert not (env.workers / pub).exists()
    assert _contents_files(env) == []


def test_C11_just_under_limit_accepted(env):
    m = _upload(env.up, "A", "ok.png", _bomb_png(7000))
    assert (m.types, m.suffix, m.status) == ("Images", ".png", "COMMITTED")


def test_C12_custom_max_image_pixels(env):
    up = MultiPartUploader(
        str(env.db), str(env.workers), str(env.contents), min_chunk_size=1, max_image_pixels=1_000
    )
    pub = _upload(up, "A", "a.png", _img_bytes("PNG", size=(40, 40)), commit=False)
    with pytest.raises(PsImageTooLargeError):
        up.commit("A", pub)
    assert env.ps.getMeta(None, pub).status == "ERROR"


def test_C13_headers_for_images(env):
    m = _upload(env.up, "A", "a.png", _img_bytes("JPEG"))
    assert psc_response_headers(m) == {
        "Content-Type": "image/jpeg",
        "Content-Disposition": "inline",
        "X-Content-Type-Options": "nosniff",
    }


def test_C14_headers_for_documents(env):
    m = _upload(env.up, "A", "report.txt", b"hello")
    assert psc_response_headers(m) == {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="report.txt"',
        "X-Content-Type-Options": "nosniff",
    }


def test_C14b_headers_filename_sanitized_and_suffix_fallback():
    meta = FileMeta(
        contents_id="cid", public_id="p" * 32, types="Documents", size=1, pid="A",
        filename='re"po rt/\r\nx', suffix=".txt", original_suffix=None, status="COMMITTED",
        creation_date="", last_access="",
    )
    h = psc_response_headers(meta)
    assert h["Content-Disposition"] == 'attachment; filename="re_po_rt___x.txt"'
    assert "\n" not in h["Content-Disposition"] and "\r" not in h["Content-Disposition"]


def test_C15_classify_file_direct(tmp_path: Path):
    p = tmp_path / "x"
    p.write_bytes(_img_bytes("PNG", size=(4, 6)))
    cls = classify_file(p, ".txt", max_image_pixels=DEFAULT_MAX_IMAGE_PIXELS)
    assert isinstance(cls, Classification)
    assert (cls.types, cls.suffix, cls.image_format, cls.width, cls.height) == (
        "Images", ".png", "PNG", 4, 6,
    )
    p.write_bytes(b"hello")
    cls = classify_file(p, ".PDF", max_image_pixels=DEFAULT_MAX_IMAGE_PIXELS)
    assert (cls.types, cls.suffix, cls.image_format, cls.width, cls.height) == (
        "Documents", ".pdf", None, None, None,
    )
    cls = classify_file(p, ".zip", max_image_pixels=10)
    assert (cls.types, cls.suffix) == ("Binary", ".zip")
    cls = classify_file(p, ".mp3", max_image_pixels=10)
    assert (cls.types, cls.suffix) == ("Media", ".mp3")
    cls = classify_file(p, "../evil", max_image_pixels=10)
    assert (cls.types, cls.suffix) == ("Binary", ".bin")
    with pytest.raises(PsImageTooLargeError):
        p.write_bytes(_img_bytes("PNG", size=(40, 40)))
        classify_file(p, ".png", max_image_pixels=100)


# --------------------------------------------------------------------------
# PS-D 画像変換
# --------------------------------------------------------------------------
def _png_commit(env, size=(10, 10), name="i.png"):
    return _upload(env.up, "A", name, _img_bytes("PNG", size=size))


def test_D01_comp_img_webp_normal_case(env):
    m = _png_commit(env)
    out = env.ps.comp_img("A", m.public_id, 8, 8, 80)
    assert out.exists() and out.suffix == ".webp"
    assert out.name == f"{m.contents_id}__PSC_height-64_quality-85_width-64.webp"
    with Image.open(out) as im:
        assert im.size == (10, 10)
        assert im.format == "WEBP"


def test_D02_cache_reused_no_regeneration(env):
    m = _png_commit(env)
    a = env.ps.comp_img("A", m.public_id, 8, 8, 80)
    t = os.stat(a).st_mtime_ns
    os.utime(a, ns=(t - 5_000_000_000, t - 5_000_000_000))
    t = os.stat(a).st_mtime_ns
    b = env.ps.comp_img("A", m.public_id, 8, 8, 80)
    assert a == b and os.stat(b).st_mtime_ns == t


def test_D03_D04_rounding_and_format_agree(env):
    m = _png_commit(env)
    out = env.ps.comp_img("A", m.public_id, 300, None, None)
    assert "width-384" in out.name and "quality-70" in out.name and "height-" not in out.name
    assert env.ps.format_psc_public_id(None, m.public_id, width=300) == out


def test_D05_contain_keeps_aspect(env):
    m = _png_commit(env, size=(400, 200))
    out = env.ps.comp_img("A", m.public_id, 100, 100, None)
    assert out.name.endswith("height-128_quality-70_width-128.webp")
    with Image.open(out) as im:
        assert im.size == (128, 64)


def test_D05b_single_dimension_scales_proportionally(env):
    m = _png_commit(env, size=(400, 200))
    out = env.ps.comp_img("A", m.public_id, 100, None, None)  # -> width 128
    with Image.open(out) as im:
        assert im.size == (128, 64)
    out2 = env.ps.comp_img("A", m.public_id, None, 100, None)  # -> height 128 (>=? 200 -> 128 shrink)
    with Image.open(out2) as im:
        assert im.size == (256, 128)


def test_D06_oversize_width_rejected_no_file(env):
    m = _png_commit(env)
    before = _contents_files(env)
    with pytest.raises(PsArgmentsError) as ei:
        env.ps.comp_img("A", m.public_id, 20000, 20000, None)
    assert "width" in str(ei.value)
    assert _contents_files(env) == before


@pytest.mark.parametrize(
    "args,name",
    [
        ((0, None, None), "width"),
        ((None, -1, None), "height"),
        ((None, None, 0), "quality"),
        ((None, None, 101), "quality"),
        ((True, None, None), "width"),
    ],
)
def test_D07_invalid_variant_args(env, args, name):
    m = _png_commit(env)
    before = _contents_files(env)
    with pytest.raises(PsArgmentsError) as ei:
        env.ps.comp_img("A", m.public_id, *args)
    assert name in str(ei.value)
    assert _contents_files(env) == before


def test_D08_no_args_default_quality(env):
    m = _png_commit(env)
    out = env.ps.comp_img("A", m.public_id, None, None, None)
    assert out.name == f"{m.contents_id}__PSC_quality-70.webp"
    with Image.open(out) as im:
        assert im.size == (10, 10)


def test_D09_non_image_row(env):
    m = _committed(env)
    before = _contents_files(env)
    with pytest.raises(PsFileTypesError):
        env.ps.comp_img("A", m.public_id, 64, None, None)
    assert _contents_files(env) == before


def test_D10_init_row_status_checked_first(env):
    pub = env.up.register("i.png", 10, "A", 1, _sha(b"0123456789"))
    with pytest.raises(PsFileStatusInvalidError):
        env.ps.comp_img("A", pub, 64, None, None)


def test_D11_original_swapped_for_bomb(env):
    m = _png_commit(env)
    orig = env.contents / f"{m.contents_id}__PSC_.png"
    bomb = _bomb_png(12000)
    orig.write_bytes(bomb)
    with pytest.raises(PsImageTooLargeError):
        env.ps.comp_img("A", m.public_id, 64, None, None)
    assert _contents_files(env) == [orig.name]
    assert orig.read_bytes() == bomb


def test_D12_broken_exif_jpeg_still_converts(env):
    exif = b"Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x05\x01\x12"  # IFD 5 entries, truncated
    buf = BytesIO()
    Image.new("RGB", (20, 10), (0, 255, 0)).save(buf, format="JPEG", exif=exif)
    m = _upload(env.up, "A", "e.jpg", buf.getvalue())
    out = env.ps.comp_img("A", m.public_id, 64, None, None)
    with Image.open(out) as im:
        assert im.format == "WEBP"


def test_D13_missing_original(env):
    m = _png_commit(env)
    (env.contents / f"{m.contents_id}__PSC_.png").unlink()
    with pytest.raises(PsDataCorruotedError):
        env.ps.comp_img("A", m.public_id, 64, None, None)


def test_D14_ps_level_pixel_limit(env):
    m = _png_commit(env)
    ps2 = ParallelStorage(str(env.db), str(env.contents), str(env.workers), max_image_pixels=50)
    with pytest.raises(PsImageTooLargeError):
        ps2.comp_img("A", m.public_id, 64, None, None)


def test_D15_normalize_image_variant_table():
    assert normalize_image_variant(None, None, None) == (None, None, 70)
    assert normalize_image_variant(1, 65, 96) == (64, 128, 95)
    assert normalize_image_variant(4096, None, 100) == (4096, None, 95)
    assert normalize_image_variant(None, 4096, 1) == (None, 4096, 50)
    for q in range(1, 101):
        _, _, r = normalize_image_variant(None, None, q)
        assert r in IMAGE_QUALITY_STEPS and (r >= q or q > 95)
    for v in range(1, IMAGE_SIZE_STEPS[-1] + 1, 37):
        r, _, _ = normalize_image_variant(v, None, None)
        assert r in IMAGE_SIZE_STEPS and r >= v
        assert not any(v <= s < r for s in IMAGE_SIZE_STEPS)
    with pytest.raises(PsArgmentsError):
        normalize_image_variant(4097, None, None)
    with pytest.raises(PsArgmentsError):
        normalize_image_variant(None, True, None)


def test_D16_variant_count_is_bounded(env):
    m = _png_commit(env)
    for w in range(1, 400, 7):
        env.ps.comp_img("A", m.public_id, w, None, None)
    # 1..399 -> 64,128,256,384,512 のうち 64..512 の 5 種のみ
    webps = [n for n in _contents_files(env) if n.endswith(".webp")]
    assert len(webps) <= 5


# --------------------------------------------------------------------------
# PS-E アップロード上限・チャンク・GC
# --------------------------------------------------------------------------
def _workdir_count(env):
    return len(list(env.workers.iterdir())) if env.workers.exists() else 0


def test_E00_expected_chunk_size():
    assert expected_chunk_size(18, 2, 0) == 9
    assert expected_chunk_size(18, 2, 1) == 9
    assert expected_chunk_size(10, 3, 0) == 4
    assert expected_chunk_size(10, 3, 1) == 4
    assert expected_chunk_size(10, 3, 2) == 2
    assert expected_chunk_size(5, 1, 0) == 5


def test_E01_size_over_limit(env):
    up = MultiPartUploader(str(env.db), str(env.workers), str(env.contents))
    with pytest.raises(PsUploadTooLargeError):
        up.register("f.bin", 10**9 + 1, "A", 1, _sha(b"x"))
    assert env.ps._PSDBM.count_active("A") == 0
    assert _workdir_count(env) == 0


def test_E02_absurd_total_chunks(env):
    with pytest.raises(PsArgmentsError) as ei:
        env.up.register("f.bin", 100, "A", 10**9, _sha(b"x"))
    assert "total_chunks" in str(ei.value)
    assert env.ps._PSDBM.count_active("A") == 0


def test_E03_chunk_exceeds_chunk_max(env):
    up = MultiPartUploader(str(env.db), str(env.workers), str(env.contents), min_chunk_size=1)
    with pytest.raises(PsArgmentsError) as ei:
        up.register("f.bin", 30 * MIB, "A", 2, _sha(b"x"))
    assert "total_chunks" in str(ei.value)


def test_E04_default_min_chunk_size(env):
    up = MultiPartUploader(str(env.db), str(env.workers), str(env.contents))
    with pytest.raises(PsArgmentsError) as ei:
        up.register("f.bin", 1000, "A", 2, _sha(b"x"))
    assert "total_chunks" in str(ei.value)
    up.register("f.bin", 1000, "A", 1, _sha(b"x"))  # 1 チャンクは常に可


def test_E05_register_ok_and_permissions(env):
    pub = env.up.register("f.bin", 18, "A", 2, _sha(b"x" * 18))
    import re
    assert re.fullmatch(r"[A-Za-z0-9_-]{16,64}", pub) and len(pub) == 32
    assert _mode(env.workers / pub) == 0o700
    assert _mode(env.workers / pub / "meta.json") == 0o600


@pytest.mark.parametrize("sha", ["xyz", "a" * 63, "a" * 65, "g" * 64, ""])
def test_E06_bad_sha256(env, sha):
    with pytest.raises(PsArgmentsError) as ei:
        env.up.register("f.bin", 18, "A", 2, sha)
    assert "sha256" in str(ei.value)


def test_E06b_bad_size_and_total_chunks(env):
    for size in (0, -1, True, "10", 1.5):
        with pytest.raises(PsArgmentsError) as ei:
            env.up.register("f.bin", size, "A", 1, _sha(b"x"))
        assert "size" in str(ei.value)
    for tc in (0, -1, None, "1"):  # True は doc が bool 不可と明記していない (total_chunks のみ)
        with pytest.raises(PsArgmentsError) as ei:
            env.up.register("f.bin", 10, "A", tc, _sha(b"x"))
        assert "total_chunks" in str(ei.value)


def test_E07_active_upload_limit_default_and_custom(env):
    for _ in range(8):
        env.up.register("f.bin", 10, "A", 1, _sha(b"x"))
    with pytest.raises(PsTooManyActiveUploadsError):
        env.up.register("f.bin", 10, "A", 1, _sha(b"x"))
    env.up.register("f.bin", 10, "B", 1, _sha(b"x"))  # pid 別

    db2 = env.tmp / "two.db"
    up2 = MultiPartUploader(
        str(db2), str(env.tmp / "w2"), str(env.tmp / "c2"),
        min_chunk_size=1, max_active_uploads_per_pid=2,
    )
    up2.register("f.bin", 10, "A", 1, _sha(b"x"))
    up2.register("f.bin", 10, "A", 1, _sha(b"x"))
    with pytest.raises(PsTooManyActiveUploadsError):
        up2.register("f.bin", 10, "A", 1, _sha(b"x"))


def test_E08_slot_freed_by_delete_and_commit_not_counted(env):
    up = MultiPartUploader(
        str(env.db), str(env.workers), str(env.contents), min_chunk_size=1,
        max_active_uploads_per_pid=2,
    )
    a = up.register("f.bin", 10, "A", 1, _sha(b"x"))
    up.register("f.bin", 10, "A", 1, _sha(b"x"))
    with pytest.raises(PsTooManyActiveUploadsError):
        up.register("f.bin", 10, "A", 1, _sha(b"x"))
    env.ps.delete("A", a)
    c = up.register("f.bin", 10, "A", 1, _sha(b"x"))
    # 1 件 commit -> COMMITTED は active に数えない
    data = b"0123456789"
    env.ps.delete("A", c)
    pub = _upload(up, "A", "ok.bin", data, commit=False)
    assert env.ps._PSDBM.count_active("A") == 2
    up.commit("A", pub)
    assert env.ps._PSDBM.count_active("A") == 1
    up.register("f.bin", 10, "A", 1, _sha(b"x"))


def test_E09_chunk_size_mismatch(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    with pytest.raises(PsChunkSizeMismatchError):
        env.up.parts_upload("A", pub, 0, data[:8], _sha(data[:8]))
    assert env.ps.getMeta(None, pub).status == "INIT"


def test_E10_chunk_flow_statuses_and_modes(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    env.up.parts_upload("A", pub, 0, data[:9], _sha(data[:9]))
    assert env.ps.getMeta(None, pub).status == "UPLOADING"
    env.up.parts_upload("A", pub, 1, data[9:], _sha(data[9:]))
    assert env.ps.getMeta(None, pub).status == "READY"
    for i in (0, 1):
        assert _mode(env.workers / pub / f"chunk{i}.parts") == 0o600


def test_E11_reverse_order_reaches_ready(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    env.up.parts_upload("A", pub, 1, data[9:], _sha(data[9:]))
    assert env.ps.getMeta(None, pub).status == "UPLOADING"
    env.up.parts_upload("A", pub, 0, data[:9], _sha(data[:9]))
    assert env.ps.getMeta(None, pub).status == "READY"
    assert env.up.commit("A", pub).status == "COMMITTED"


def test_E11b_chunk_resend_allowed(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    env.up.parts_upload("A", pub, 0, data[:9], _sha(data[:9]))
    env.up.parts_upload("A", pub, 0, data[:9], _sha(data[:9]))
    assert env.ps.getMeta(None, pub).status == "UPLOADING"


@pytest.mark.parametrize("count", [999999, -1, "0", True, None, 2])
def test_E12_bad_count(env, count):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    with pytest.raises(PsArgmentsError) as ei:
        env.up.parts_upload("A", pub, count, data[:9], _sha(data[:9]))
    assert "count" in str(ei.value)
    assert list((env.workers / pub).glob("chunk*.parts")) == []


def test_E12b_bad_blob_type(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    with pytest.raises(PsArgmentsError) as ei:
        env.up.parts_upload("A", pub, 0, "x" * 9, _sha(data[:9]))
    assert "blob" in str(ei.value)


def test_E13_chunk_over_max(env):
    size = 20 * MIB
    pub = env.up.register("f.bin", size, "A", 2, _sha(b"x"))
    blob = b"\x00" * (10 * MIB + 1)
    with pytest.raises(PsChunkEntityTooLargeError):
        env.up.parts_upload("A", pub, 0, blob, _sha(blob))


def test_E14_E15_wrong_chunk_sha_keeps_workdir_and_resend_recovers(env):
    # Leader ruling (storage doc E-14 / E-14a / E-15): a chunk sha mismatch is PS17,
    # status is unchanged and the working directory survives; resending the chunk recovers.
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    with pytest.raises(PsChunkHashMismatchError) as ei:  # E-14a: INIT stays INIT
        env.up.parts_upload("A", pub, 0, data[:9], _sha(b"wrong"))
    assert ei.value.code == "PS17" and ei.value.count == 0
    assert env.ps.getMeta(None, pub).status == "INIT"
    assert (env.workers / pub / "meta.json").exists()
    assert not (env.workers / pub / "chunk0.parts").exists()
    env.up.parts_upload("A", pub, 0, data[:9], _sha(data[:9]))
    with pytest.raises(PsChunkHashMismatchError):  # E-14: UPLOADING stays UPLOADING, chunk0 kept
        env.up.parts_upload("A", pub, 1, data[9:], _sha(b"wrong"))
    assert env.ps.getMeta(None, pub).status == "UPLOADING"
    assert (env.workers / pub / "chunk0.parts").exists()
    assert not (env.workers / pub / "chunk1.parts").exists()
    env.up.parts_upload("A", pub, 1, data[9:], _sha(data[9:]))  # E-15: resend same count
    assert env.ps.getMeta(None, pub).status == "READY"
    assert env.up.commit("A", pub).status == "COMMITTED"


def test_E16_commit_before_all_chunks(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(data))
    env.up.parts_upload("A", pub, 0, data[:9], _sha(data[:9]))
    with pytest.raises(PsFileStatusInvalidError):
        env.up.commit("A", pub)
    assert (env.workers / pub).is_dir()
    assert env.ps.getMeta(None, pub).status == "UPLOADING"


def test_E17_wrong_total_sha_commit_fails_and_cleans(env):
    data = b"hello-world-012345"
    pub = env.up.register("f.txt", len(data), "A", 2, _sha(b"different"))
    for i, part in enumerate(_split(data, 2)):
        env.up.parts_upload("A", pub, i, part, _sha(part))
    with pytest.raises(PsDataCorruotedError):
        env.up.commit("A", pub)
    assert env.ps.getMeta(None, pub).status == "ERROR"
    assert not (env.workers / pub).exists()
    assert _contents_files(env) == []


def test_E18_double_commit(env):
    m = _committed(env)
    with pytest.raises(PsFileStatusInvalidError):
        env.up.commit("A", m.public_id)


def test_E19b_stored_file_matches_and_no_workdir(env):
    data = b"payload-bytes"
    m = _upload(env.up, "A", "f.txt", data, total_chunks=3)
    assert m.status == "COMMITTED" and m.size == len(data)
    f = env.contents / f"{m.contents_id}__PSC_{m.suffix}"
    assert f.read_bytes() == data
    assert not (env.workers / m.public_id).exists()


def _age_all(env, days=2):
    _sql(env, f"UPDATE parallel_storage SET creation_date = datetime('now', '-{days} days')")


def test_E20_gc_removes_stale_unfinished_only(env):
    p1 = env.up.register("a.bin", 10, "A", 1, _sha(b"x"))
    p2 = env.up.register("b.bin", 10, "B", 1, _sha(b"x"))
    m = _committed(env, "A")
    _age_all(env)
    report = env.up.gc()
    assert report == GcReport(removed_rows=2, removed_dirs=0)
    assert not (env.workers / p1).exists() and not (env.workers / p2).exists()
    assert env.ps.getMeta(None, m.public_id).status == "COMMITTED"
    for p in (p1, p2):
        with pytest.raises(PsPublicIDInvalidError):
            env.ps.getMeta(None, p)


def test_E21_gc_removes_orphan_dir(env):
    env.up.register("a.bin", 10, "A", 1, _sha(b"x"))  # workers を作る
    orphan = env.workers / ("o" * 32)
    orphan.mkdir()
    (orphan / "junk").write_bytes(b"z")
    old = orphan.stat().st_mtime - 2 * 86400
    os.utime(orphan, (old, old))
    report = env.up.gc()
    assert report.removed_dirs == 1 and report.removed_rows == 0
    assert not orphan.exists()


def test_E21b_gc_ignores_non_id_names_and_young_orphans(env):
    env.up.register("a.bin", 10, "A", 1, _sha(b"x"))
    odd = env.workers / "short"
    odd.mkdir()
    young = env.workers / ("y" * 32)
    young.mkdir()
    old = odd.stat().st_mtime - 2 * 86400
    os.utime(odd, (old, old))
    report = env.up.gc()
    assert report.removed_dirs == 0
    assert odd.exists() and young.exists()


def test_E22_gc_keeps_recent(env):
    pub = env.up.register("a.bin", 10, "A", 1, _sha(b"x"))
    assert env.up.gc().removed_rows == 0
    assert (env.workers / pub).is_dir()
    assert env.ps.getMeta(None, pub).status == "INIT"


def test_E23_dbm_list_stale_and_count_active(env):
    p = env.up.register("a.bin", 10, "A", 1, _sha(b"x"))
    dbm = env.ps._PSDBM
    assert dbm.count_active("A") == 1
    assert dbm.list_stale(86400) == []
    _age_all(env)
    stale = dbm.list_stale(86400)
    assert [s.public_id for s in stale] == [p]


# --------------------------------------------------------------------------
# PS-F permission_id / FileMeta / migration
# --------------------------------------------------------------------------
def test_F01_filemeta_has_no_permission_id(env):
    m = _committed(env)
    assert not hasattr(m, "permission_id")
    assert hasattr(m, "original_suffix")


def test_F02_permission_id_column_exists_and_null(env):
    m = _committed(env)
    rows = _sql(env, "SELECT permission_id FROM parallel_storage WHERE public_id=?", m.public_id)
    assert rows == [(None,)]


OLD_DDL = """
CREATE TABLE parallel_storage (
    contents_id TEXT PRIMARY KEY,
    public_id TEXT UNIQUE,
    types TEXT DEFAULT 'Binary',
    size INT NOT NULL,
    pid TEXT NOT NULL,
    filename TEXT NOT NULL,
    suffix TEXT NOT NULL,
    status TEXT DEFAULT 'INIT',
    permission_id TEXT DEFAULT NULL,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


def _make_old_db(path: Path):
    con = sqlite3.connect(str(path))
    con.execute(OLD_DDL)
    rows = [
        ("c1", "p1" + "a" * 30, "Images", 1, "A", "x", ".svg", "COMMITTED"),
        ("c2", "p2" + "a" * 30, "Images", 1, "A", "y", ".png", "COMMITTED"),
        ("c3", "p3" + "a" * 30, "Documents", 1, "A", "z", ".html", "COMMITTED"),
    ]
    for r in rows:
        con.execute(
            "INSERT INTO parallel_storage (contents_id, public_id, types, size, pid, filename, suffix, status)"
            " VALUES (?,?,?,?,?,?,?,?)", r,
        )
    con.commit()
    con.close()


def _types(path: Path):
    con = sqlite3.connect(str(path))
    try:
        return dict(con.execute("SELECT contents_id, types FROM parallel_storage").fetchall())
    finally:
        con.close()


def test_F03_F04_migration_from_1_1_41_schema_idempotent(tmp_path: Path):
    db = tmp_path / "old.db"
    _make_old_db(db)
    dbm = ParallelStorageDBM(str(db))
    con = sqlite3.connect(str(db))
    cols = [r[1] for r in con.execute("PRAGMA table_info(parallel_storage)")]
    assert "original_suffix" in cols and "permission_id" in cols
    assert con.execute(
        "SELECT value FROM parallel_storage_meta WHERE key='schema_version'"
    ).fetchall() == [("1",)]
    con.close()
    assert _types(db) == {"c1": "Binary", "c2": "Images", "c3": "Documents"}
    assert dbm.getMeta(contents_id="c2").original_suffix is None

    # 再オープン (冪等): 手で types を戻しても二度目の migration は走らない (v>=1)
    con = sqlite3.connect(str(db))
    con.execute("UPDATE parallel_storage SET types='Images' WHERE contents_id='c1'")
    con.commit()
    con.close()
    dbm2 = ParallelStorageDBM(str(db))
    assert _types(db) == {"c1": "Images", "c2": "Images", "c3": "Documents"}
    assert dbm2.getMeta(contents_id="c1").original_suffix is None
    con = sqlite3.connect(str(db))
    assert con.execute("SELECT count(*) FROM parallel_storage_meta").fetchone() == (1,)
    con.close()


def test_F05_new_db_has_schema_version_and_0600(env):
    rows = _sql(env, "SELECT value FROM parallel_storage_meta WHERE key='schema_version'")
    assert rows == [("1",)]
    assert _mode(env.db) == 0o600


def test_F06_migrated_old_db_with_working_ops(tmp_path: Path):
    db = tmp_path / "old.db"
    _make_old_db(db)
    ps = ParallelStorage(str(db), str(tmp_path / "contents"), str(tmp_path / "workers"))
    assert ps.getMeta(None, "p3" + "a" * 30).types == "Documents"
    ps.delete("A", "p3" + "a" * 30, force=True)
    with pytest.raises(PsPublicIDInvalidError):
        ps.getMeta(None, "p3" + "a" * 30)


def test_nexom_errors_are_nexom_errors():
    for exc in (
        PsSuffixInvalidError(".x"), PsPathEscapeError(), PsImageTooLargeError(),
        PsImageTooLargeError(5), PsUploadTooLargeError(2, 1), PsChunkSizeMismatchError(2, 1),
        PsTooManyActiveUploadsError(8), PsFileTypesError(), PsFileTypesError("x"),
        PsFileStatusInvalidError(), PsPermissionError(), PsChunkEntityTooLargeError(),
        PsContentsIDInvalidError(),
    ):
        assert isinstance(exc, NexomError)
    assert "pid" in str(PsPermissionError()).lower()
