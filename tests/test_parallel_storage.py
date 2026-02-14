from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexom.app.parallel_storage import (
    MultiPartUploader,
    ParallelStorage,
    format_psc_filename,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_format_psc_filename_order():
    out = format_psc_filename("cid", ".txt", b=2, a=1, z=None)
    assert out == "cid__PSC_a-1_b-2.txt"


def test_multipart_upload_and_commit(tmp_path: Path):
    db = tmp_path / "ps.db"
    workers = tmp_path / "workers"
    contents = tmp_path / "contents"

    uploader = MultiPartUploader(str(db), str(workers), str(contents))

    data = b"hello-world-012345"
    chunk1 = data[:8]
    chunk2 = data[8:]

    public_id = uploader.register(
        filename="file.txt",
        size=len(data),
        pid="pid",
        permission_id=None,
        total_chunks=2,
        sha256=_sha256(data),
    )

    uploader.parts_upload("pid", public_id, 0, chunk1, _sha256(chunk1))
    uploader.parts_upload("pid", public_id, 1, chunk2, _sha256(chunk2))

    meta = uploader.commit("pid", public_id)
    dest = contents / format_psc_filename(meta.contents_id, meta.suffix)

    assert dest.exists()
    assert dest.read_bytes() == data
    assert not (workers / public_id).exists()


def test_parallel_storage_update_suffix(tmp_path: Path):
    db = tmp_path / "ps.db"
    contents = tmp_path / "contents"

    ps = ParallelStorage(str(db), str(contents))
    uploader = MultiPartUploader(str(db), str(tmp_path / "workers"), str(contents))

    public_id = uploader.register(
        filename="file.txt",
        size=1,
        pid="pid",
        permission_id=None,
        total_chunks=1,
        sha256=_sha256(b"x"),
    )

    ps.update_suffix(public_id, ".bin")
    meta = ps._PSDBM.getMeta(public_id=public_id)
    assert meta.suffix == ".bin"


def test_parallel_storage_format_public_id(tmp_path: Path):
    db = tmp_path / "ps.db"
    contents = tmp_path / "contents"

    ps = ParallelStorage(str(db), str(contents))
    uploader = MultiPartUploader(str(db), str(tmp_path / "workers"), str(contents))

    public_id = uploader.register(
        filename="file.txt",
        size=1,
        pid="pid",
        permission_id=None,
        total_chunks=1,
        sha256=_sha256(b"x"),
    )

    path = ps.format_psc_public_id(public_id, v=1, a=2)
    assert path.name.endswith("__PSC_a-2_v-1.txt")


@pytest.mark.xfail(reason="comp_img currently calls missing format_psc_contents_id")
def test_comp_img_webp(tmp_path: Path):
    PIL = pytest.importorskip("PIL")
    from PIL import Image

    db = tmp_path / "ps.db"
    contents = tmp_path / "contents"

    ps = ParallelStorage(str(db), str(contents))
    uploader = MultiPartUploader(str(db), str(tmp_path / "workers"), str(contents))

    public_id = uploader.register(
        filename="img.png",
        size=1,
        pid="pid",
        permission_id=None,
        total_chunks=1,
        sha256=_sha256(b"x"),
    )

    meta = ps._PSDBM.getMeta(public_id=public_id)
    original = contents / format_psc_filename(meta.contents_id, meta.suffix)
    contents.mkdir(parents=True, exist_ok=True)

    img = Image.new("RGB", (10, 10), color=(255, 0, 0))
    img.save(original)

    out = ps.comp_img(public_id, 8, 8, 80)
    assert out.exists()
    assert out.suffix == ".webp"
