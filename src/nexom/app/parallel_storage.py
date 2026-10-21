"""Parallel storage and multipart upload."""

from typing import Literal
from pathlib import Path
from dataclasses import dataclass
import shutil
import hashlib
import secrets
import re
import os
import time

from json.decoder import JSONDecodeError
import json

from .db import DatabaseManager

from ..core.error import PsStatusTypesError, PsFileStatusInvalidError, PsArgmentsError, PsPublicIDInvalidError, PsContentsIDInvalidError, PsDataCorruotedError, PsChunkEntityTooLargeError, PsPermissionError, PsFileTypesError, PsSuffixInvalidError, PsImageTooLargeError, PsPathEscapeError, PsUploadTooLargeError, PsChunkSizeMismatchError, PsTooManyActiveUploadsError

DEFAULT_CHUNK_MAX_SIZE = 10 * 1024 * 1024
DEFAULT_MIN_CHUNK_SIZE = 256 * 1024
DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024
DEFAULT_MAX_ACTIVE_UPLOADS_PER_PID = 8
DEFAULT_MAX_IMAGE_PIXELS = 50_000_000
chunk_max_size = DEFAULT_CHUNK_MAX_SIZE
IMAGE_SIZE_STEPS = (64, 128, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096)
IMAGE_QUALITY_STEPS = (50, 70, 85, 95)
DEFAULT_IMAGE_QUALITY = 70
IMAGE_FORMATS: dict[str, str] = {"JPEG": ".jpg", "PNG": ".png", "GIF": ".gif", "WEBP": ".webp"}
IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp"})
DOCUMENT_SUFFIXES = frozenset({".pdf", ".txt", ".md", ".csv", ".json"})
MEDIA_SUFFIXES = frozenset({".mp3", ".m4a", ".wav", ".ogg", ".mp4", ".mov", ".webm"})
BINARY_SUFFIXES = frozenset({".zip", ".bin"})
DANGEROUS_SUFFIXES = frozenset({".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".msi", ".app", ".dylib", ".so", ".jar"})
FALLBACK_SUFFIX = ".bin"
SUFFIX_RE = re.compile(r"^\.[A-Za-z0-9]{1,16}$")
ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
CID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KWARG_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IMAGE_CONTENT_TYPES = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp"}

FileTypes = Literal["Documents", "Images", "Binary", "Media", "Dangerous"]
FileStatus = Literal["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED", "ERROR"]
def _FileStatusTypesCheck(status: FileStatus) -> None:
    if not (status in ["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED", "ERROR"]): raise PsStatusTypesError(status)
    
def _rand(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)

def _sha256_hex_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(1024 * 1024)  # 1MBずつ
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def format_psc_filename(contents_id: str, suffix: str, **kwargs) -> str:
    """Build a validated PSC filename with alphabetically sorted variants."""
    if not isinstance(contents_id, str) or not CID_RE.fullmatch(contents_id):
        raise PsArgmentsError("contents_id")
    if not isinstance(suffix, str) or not SUFFIX_RE.fullmatch(suffix):
        raise PsSuffixInvalidError(suffix)
    items = []
    for key in sorted(kwargs):
        value = kwargs[key]
        if value is None:
            continue
        if not KWARG_RE.fullmatch(key) or not KWARG_RE.fullmatch(str(value)):
            raise PsArgmentsError(key)
        items.append(f"{key}-{value}")
    return f"{contents_id}__PSC_{'_'.join(items)}{suffix}"


@dataclass(frozen=True)
class FileMeta:
    """Immutable metadata for a stored file."""
    contents_id: str
    public_id: str
    types: str
    size: int
    pid: str
    filename: str
    suffix: str
    original_suffix: str | None
    status: str
    creation_date: str
    last_access: str
    
    def isTypes(self, types: FileTypes) -> bool:
        """Return True if the stored type matches the given FileTypes value."""
        if types not in ("Documents", "Images", "Binary", "Media", "Dangerous"):
            raise PsFileTypesError(types)
        return types == self.types


@dataclass(frozen=True)
class Classification:
    types: FileTypes
    suffix: str
    image_format: str | None
    width: int | None
    height: int | None


@dataclass(frozen=True)
class GcReport:
    removed_rows: int
    removed_dirs: int


def classify_file(path: Path, declared_suffix: str, *, max_image_pixels: int) -> Classification:
    """Classify verified allowlisted images, then fall back to safe suffixes."""
    from PIL import Image

    try:
        with Image.open(path, formats=list(IMAGE_FORMATS)) as im:
            width, height = im.size
            if width * height > max_image_pixels:
                raise PsImageTooLargeError(width * height)
            image_format = im.format
            im.verify()
            return Classification("Images", IMAGE_FORMATS[image_format], image_format, width, height)
    except Image.DecompressionBombError as e:
        raise PsImageTooLargeError(None) from e
    except PsImageTooLargeError:
        raise
    except Exception:
        pass

    suffix = declared_suffix.lower()
    if not SUFFIX_RE.fullmatch(suffix):
        suffix = ""
    for types, suffixes in (("Documents", DOCUMENT_SUFFIXES),
                            ("Media", MEDIA_SUFFIXES), ("Binary", BINARY_SUFFIXES)):
        if suffix in suffixes:
            return Classification(types, suffix, None, None, None)
    types = "Dangerous" if suffix in DANGEROUS_SUFFIXES else "Binary"
    return Classification(types, FALLBACK_SUFFIX, None, None, None)


def normalize_image_variant(width: int | None, height: int | None,
                            quality: int | None) -> tuple[int | None, int | None, int]:
    """Validate variant parameters and round up to bounded presets."""
    dimensions = []
    for name, value in (("width", width), ("height", height)):
        if value is None:
            dimensions.append(None)
            continue
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= IMAGE_SIZE_STEPS[-1]:
            raise PsArgmentsError(name)
        dimensions.append(next(step for step in IMAGE_SIZE_STEPS if step >= value))
    if quality is None:
        quality = DEFAULT_IMAGE_QUALITY
    if isinstance(quality, bool) or not isinstance(quality, int) or not 1 <= quality <= 100:
        raise PsArgmentsError("quality")
    rounded_quality = next((step for step in IMAGE_QUALITY_STEPS if step >= quality), IMAGE_QUALITY_STEPS[-1])
    return dimensions[0], dimensions[1], rounded_quality


def psc_response_headers(meta: FileMeta) -> dict[str, str]:
    """Return recommended headers for safely serving a stored object."""
    headers = {"X-Content-Type-Options": "nosniff"}
    if meta.types == "Images" and meta.suffix in IMAGE_CONTENT_TYPES:
        headers["Content-Type"] = IMAGE_CONTENT_TYPES[meta.suffix]
        headers["Content-Disposition"] = "inline"
    else:
        suffix = meta.original_suffix if meta.original_suffix is not None else meta.suffix
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", meta.filename + suffix)
        headers["Content-Type"] = "application/octet-stream"
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return headers


def expected_chunk_size(size: int, total_chunks: int, count: int) -> int:
    """Return the expected length of a chunk, including the final remainder."""
    chunk = (size + total_chunks - 1) // total_chunks
    return chunk if count < total_chunks - 1 else size - chunk * (total_chunks - 1)


class ParallelStorage:
    """Owner-aware storage access and cached image conversion."""

    def __init__(self, db_file: str, contents_dir: str,
                 working_dir: str | None = None, *,
                 max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS) -> None:
        self.contents_dir = Path(contents_dir)
        self.working_dir = Path(working_dir) if working_dir is not None else None
        self.max_image_pixels = max_image_pixels
        self._PSDBM = ParallelStorageDBM(db_file)

    def getMeta(self, pid: str | None, public_id: str) -> FileMeta:
        """Read metadata, enforcing ownership when pid is provided."""
        if not isinstance(public_id, str) or not ID_RE.fullmatch(public_id):
            raise PsPublicIDInvalidError()
        return self._PSDBM.getMeta(public_id=public_id, pid=pid)

    def format_psc_public_id(self, pid: str | None, public_id: str, **kwargs) -> Path:
        """Resolve an original or normalized variant directly inside contents."""
        meta = self.getMeta(pid, public_id)
        suffix = meta.suffix
        if meta.types == "Images" and any(key in kwargs for key in ("width", "height", "quality")):
            width, height, quality = normalize_image_variant(
                kwargs.get("width"), kwargs.get("height"), kwargs.get("quality"))
            kwargs.update(width=width, height=height, quality=quality)
            suffix = ".webp"
        name = format_psc_filename(meta.contents_id, suffix, **kwargs)
        path = (self.contents_dir / name).resolve()
        if path.parent != self.contents_dir.resolve():
            raise PsPathEscapeError()
        return path

    def comp_img(self, pid: str | None, public_id: str, width: int | None,
                 height: int | None, quality: int | None) -> Path:
        """Generate a bounded WebP variant, reusing an existing cache file."""
        meta = self.getMeta(pid, public_id)
        if meta.status != "COMMITTED":
            raise PsFileStatusInvalidError()
        if meta.types != "Images":
            raise PsFileTypesError(meta.types)
        bw, bh, q = normalize_image_variant(width, height, quality)
        cache_path = self.format_psc_public_id(pid, public_id, width=bw, height=bh, quality=q)
        if cache_path.exists():
            return cache_path
        original = self.format_psc_public_id(pid, public_id)
        if not original.exists():
            raise PsDataCorruotedError()

        from PIL import Image, ImageOps

        try:
            source = Image.open(original, formats=list(IMAGE_FORMATS))
        except Image.DecompressionBombError as exc:
            raise PsImageTooLargeError(None) from exc
        with source as im:
            w, h = im.size
            if w * h > self.max_image_pixels:
                raise PsImageTooLargeError(w * h)
            try:
                ImageOps.exif_transpose(im, in_place=True)
            except Exception:
                pass
            with im.convert("RGB") as rgb:
                ow, oh = rgb.size
                scale = min(bw / ow if bw is not None else 1,
                            bh / oh if bh is not None else 1)
                target = (max(1, round(ow * scale)), max(1, round(oh * scale)))
                output = rgb.resize(target, Image.Resampling.LANCZOS) if scale < 1 else rgb
                tmp = cache_path.with_name(cache_path.name + ".tmp-" + _rand(8))
                try:
                    output.save(tmp, format="WEBP", quality=q, method=6)
                    os.replace(tmp, cache_path)
                except Exception:
                    tmp.unlink(missing_ok=True)
                    raise
                finally:
                    if output is not rgb:
                        output.close()
        return cache_path

    def update_suffix(self, pid: str, public_id: str, suffix: str) -> None:
        """Override the declared suffix before commit."""
        meta = self.getMeta(pid, public_id)
        self._PSDBM.update_suffix(pid, meta.contents_id, suffix)

    def delete(self, pid: str, public_id: str, *, force: bool = False) -> None:
        """Delete the row, content variants, and upload working directory."""
        meta = self.getMeta(None, public_id)
        if not force and meta.pid != pid:
            raise PsPermissionError()
        for path in self.contents_dir.glob(f"{meta.contents_id}__PSC_*"):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
        if self.working_dir is not None:
            shutil.rmtree(self.working_dir / public_id, ignore_errors=True)
        self._PSDBM.remove(pid, public_id=public_id, force=force)


class ParallelStorageDBM(DatabaseManager):
    """Storage metadata with versioned migration and owner-checked mutations."""

    _META_COLUMNS = (
        "contents_id", "public_id", "types", "size", "pid", "filename",
        "suffix", "original_suffix", "status", "creation_date", "last_access",
    )
    _META_SELECT = "SELECT " + ", ".join(_META_COLUMNS) + " FROM parallel_storage"

    def __init__(self, db_file: str):
        super().__init__(db_file, auto_commit=False)

    def _init(self) -> None:
        """Create or idempotently migrate storage metadata to schema version 1."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS parallel_storage (
                contents_id TEXT PRIMARY KEY,
                public_id TEXT UNIQUE,
                types TEXT DEFAULT 'Binary',
                size INT NOT NULL,
                pid TEXT NOT NULL,
                filename TEXT NOT NULL,
                suffix TEXT NOT NULL,
                original_suffix TEXT DEFAULT NULL,
                status TEXT DEFAULT 'INIT',
                permission_id TEXT DEFAULT NULL,
                creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS parallel_storage_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        rows = self.execute("SELECT value FROM parallel_storage_meta WHERE key = 'schema_version'")
        version = int(rows[0][0]) if rows else 0
        if version < 1:
            columns = self.execute("PRAGMA table_info(parallel_storage)")
            if "original_suffix" not in {column[1] for column in columns}:
                self.execute("ALTER TABLE parallel_storage ADD COLUMN original_suffix TEXT DEFAULT NULL")
            self.execute("""
                UPDATE parallel_storage SET types = 'Binary'
                WHERE types = 'Images' AND lower(suffix) NOT IN ('.jpg', '.jpeg', '.png', '.gif', '.webp')
            """)
            self.execute("INSERT OR REPLACE INTO parallel_storage_meta (key, value) VALUES ('schema_version', '1')")
        self.commit()

    def _get_by_public_id(self, public_id: str) -> tuple:
        if not isinstance(public_id, str) or not ID_RE.fullmatch(public_id):
            raise PsPublicIDInvalidError()
        rows = self.execute(self._META_SELECT + " WHERE public_id = ?", public_id)
        if not rows:
            raise PsPublicIDInvalidError()
        return rows[0]

    def _get_by_contents_id(self, contents_id: str) -> tuple:
        rows = self.execute(self._META_SELECT + " WHERE contents_id = ?", contents_id)
        if not rows:
            raise PsContentsIDInvalidError()
        return rows[0]

    def getMeta(self, *, contents_id: str | None = None,
                public_id: str | None = None, pid: str | None = None) -> FileMeta:
        """Read metadata, optionally enforcing ownership."""
        if public_id is not None and (not isinstance(public_id, str) or not ID_RE.fullmatch(public_id)):
            raise PsPublicIDInvalidError()
        if (contents_id is None) == (public_id is None):
            raise PsArgmentsError()
        record = (self._get_by_contents_id(contents_id) if contents_id is not None
                  else self._get_by_public_id(public_id))
        meta = FileMeta(**dict(zip(self._META_COLUMNS, record)))
        if pid is not None and meta.pid != pid:
            raise PsPermissionError()
        return meta

    @staticmethod
    def _check_owner(meta: FileMeta, pid: str, *, force: bool = False) -> None:
        if not isinstance(pid, str) or not pid:
            raise PsArgmentsError("pid")
        if not force and meta.pid != pid:
            raise PsPermissionError()

    @staticmethod
    def _checked_suffix(suffix: str) -> str:
        if not isinstance(suffix, str) or not SUFFIX_RE.fullmatch(suffix):
            raise PsSuffixInvalidError(suffix)
        return suffix.lower()

    def register(self, filename: str, suffix: str, size: int, pid: str,
                 *, original_suffix: str | None) -> str:
        """Register a declaration without writing the retired permission column."""
        if not isinstance(pid, str) or not pid:
            raise PsArgmentsError("pid")
        suffix = self._checked_suffix(suffix)
        original_suffix = (original_suffix.lower()
                           if isinstance(original_suffix, str) and SUFFIX_RE.fullmatch(original_suffix)
                           else None)
        public_id = _rand()
        self.execute("""
            INSERT INTO parallel_storage
                (contents_id, public_id, filename, suffix, size, pid, original_suffix)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, _rand(), public_id, filename, suffix, size, pid, original_suffix)
        self.commit()
        return public_id

    def status_change(self, pid: str, contents_id: str, status: FileStatus,
                      *, force: bool = False) -> None:
        meta = self.getMeta(contents_id=contents_id)
        self._check_owner(meta, pid, force=force)
        _FileStatusTypesCheck(status)
        if force:
            self.execute("UPDATE parallel_storage SET status = ? WHERE contents_id = ?", status, meta.contents_id)
        else:
            self.execute("UPDATE parallel_storage SET status = ? WHERE contents_id = ? AND pid = ?", status, meta.contents_id, pid)
        self.commit()

    def update_public_id(self, pid: str, contents_id: str) -> str:
        meta = self.getMeta(contents_id=contents_id)
        self._check_owner(meta, pid)
        public_id = _rand()
        self.execute("UPDATE parallel_storage SET public_id = ? WHERE contents_id = ? AND pid = ?", public_id, meta.contents_id, pid)
        self.commit()
        return public_id

    def update_types(self, pid: str, contents_id: str, types: FileTypes) -> None:
        meta = self.getMeta(contents_id=contents_id)
        self._check_owner(meta, pid)
        meta.isTypes(types)
        self.execute("UPDATE parallel_storage SET types = ? WHERE contents_id = ? AND pid = ?", types, meta.contents_id, pid)
        self.commit()

    def update_suffix(self, pid: str, contents_id: str, suffix: str) -> None:
        meta = self.getMeta(contents_id=contents_id)
        self._check_owner(meta, pid)
        suffix = self._checked_suffix(suffix)
        if meta.status == "COMMITTED":
            raise PsFileStatusInvalidError()
        self.execute("""
            UPDATE parallel_storage SET suffix = ?, original_suffix = ?
            WHERE contents_id = ? AND pid = ?
        """, suffix, suffix, meta.contents_id, pid)
        self.commit()

    def finalize_commit(self, pid: str, contents_id: str, *, types: FileTypes, suffix: str) -> None:
        meta = self.getMeta(contents_id=contents_id)
        self._check_owner(meta, pid)
        meta.isTypes(types)
        suffix = self._checked_suffix(suffix)
        self.execute("""
            UPDATE parallel_storage SET types = ?, suffix = ?, status = 'COMMITTED'
            WHERE contents_id = ? AND pid = ?
        """, types, suffix, meta.contents_id, pid)
        self.commit()

    def remove(self, pid: str, *, contents_id: str | None = None,
               public_id: str | None = None, force: bool = False) -> None:
        meta = self.getMeta(contents_id=contents_id, public_id=public_id)
        self._check_owner(meta, pid, force=force)
        if force:
            self.execute("DELETE FROM parallel_storage WHERE contents_id = ?", meta.contents_id)
        else:
            self.execute("DELETE FROM parallel_storage WHERE contents_id = ? AND pid = ?", meta.contents_id, pid)
        self.commit()

    def count_active(self, pid: str) -> int:
        rows = self.execute("""
            SELECT COUNT(*) FROM parallel_storage
            WHERE pid = ? AND status IN ('INIT', 'UPLOADING', 'READY', 'ERROR')
        """, pid)
        return rows[0][0]

    def list_stale(self, older_than_seconds: int) -> list[FileMeta]:
        rows = self.execute(self._META_SELECT + """
            WHERE status IN ('INIT', 'UPLOADING', 'READY', 'ERROR', 'ABORTED')
            AND creation_date <= datetime('now', ?)
        """, f"-{older_than_seconds} seconds")
        return [FileMeta(**dict(zip(self._META_COLUMNS, row))) for row in rows]


@dataclass(frozen=True)
class UploadMeta:
    """Metadata for a multipart upload session."""
    public_id: str
    total_chunks: int
    sha256: str
    
    def toJson(self) -> str:
        """Serialize to JSON string."""
        return json.dumps({
            "public_id": self.public_id,
            "total_chunks": self.total_chunks,
            "sha256": self.sha256
        })
        
    @staticmethod
    def readJson(path: Path) -> "UploadMeta":
        """Read UploadMeta from a JSON file."""
        try:
            with path.open(mode="r", encoding="utf-8") as m:
                meta_dict = json.load(m)
        except (FileNotFoundError, JSONDecodeError):
            raise PsDataCorruotedError()
            
        public_id = meta_dict.get("public_id")
        total_chunks = meta_dict.get("total_chunks")
        sha256 = meta_dict.get("sha256")
        if not isinstance(public_id, str) or not isinstance(sha256, str) or not isinstance(total_chunks, int):
            raise PsDataCorruotedError()
            
        return UploadMeta(
            public_id=public_id,
            total_chunks=total_chunks,
            sha256=sha256
        )

class MultiPartUploader:
    """Multipart uploads with owner checks, bounded chunks, and stale cleanup."""

    def __init__(self, db_file: str, working_dir: str, contents_dir: str, *,
                 max_upload_size: int = DEFAULT_MAX_UPLOAD_SIZE,
                 chunk_max_size: int = DEFAULT_CHUNK_MAX_SIZE,
                 min_chunk_size: int = DEFAULT_MIN_CHUNK_SIZE,
                 max_active_uploads_per_pid: int = DEFAULT_MAX_ACTIVE_UPLOADS_PER_PID,
                 max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS) -> None:
        self.db_file = db_file
        self.working_root = Path(working_dir)
        self.contents_root = Path(contents_dir)
        self.max_upload_size = max_upload_size
        self.chunk_max_size = chunk_max_size
        self.min_chunk_size = min_chunk_size
        self.max_active_uploads_per_pid = max_active_uploads_per_pid
        self.max_image_pixels = max_image_pixels
        self._PSDBM = ParallelStorageDBM(db_file)

    def _getUploadMeta(self, public_id: str) -> UploadMeta:
        """Load metadata for a validated upload identifier."""
        return UploadMeta.readJson(self.working_root / public_id / "meta.json")

    def _failed(self, pid: str, public_id: str) -> None:
        """Retain the failed row and discard its working directory."""
        meta = self._PSDBM.getMeta(public_id=public_id, pid=pid)
        self._PSDBM.status_change(pid, meta.contents_id, "ERROR")
        shutil.rmtree(self.working_root / public_id, ignore_errors=True)

    def register(self, filename: str, size: int, pid: str,
                 total_chunks: int, sha256: str) -> str:
        """Validate an upload declaration and create a private working directory."""
        if not isinstance(pid, str) or not pid:
            raise PsArgmentsError("pid")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise PsArgmentsError("size")
        if size > self.max_upload_size:
            raise PsUploadTooLargeError(size, self.max_upload_size)
        if not isinstance(total_chunks, int) or total_chunks < 1:
            raise PsArgmentsError("total_chunks")
        if (size + total_chunks - 1) // total_chunks > self.chunk_max_size:
            raise PsArgmentsError("total_chunks")
        if total_chunks > max(1, (size + self.min_chunk_size - 1) // self.min_chunk_size):
            raise PsArgmentsError("total_chunks")
        if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
            raise PsArgmentsError("sha256")
        name = Path(Path(filename).name)
        suffix = name.suffix.lower()
        original_suffix = suffix if SUFFIX_RE.fullmatch(suffix) else None
        if original_suffix is None:
            suffix = FALLBACK_SUFFIX
        with self._PSDBM.immediate_transaction():
            if self._PSDBM.count_active(pid) >= self.max_active_uploads_per_pid:
                raise PsTooManyActiveUploadsError(self.max_active_uploads_per_pid)
            public_id = self._PSDBM.register(
                name.stem[:200], suffix, size, pid, original_suffix=original_suffix)
        working_dir = self.working_root / public_id
        working_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(working_dir, 0o700)
        fd = os.open(working_dir / "meta.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(UploadMeta(public_id, total_chunks, sha256).toJson())
        return public_id

    def parts_upload(self, pid: str, public_id: str, count: int, blob: bytes, sha256: str) -> None:
        """Validate each chunk before writing and recalculate upload readiness."""
        if not isinstance(public_id, str) or not ID_RE.fullmatch(public_id):
            raise PsPublicIDInvalidError()
        meta = self._PSDBM.getMeta(public_id=public_id)
        if meta.pid != pid:
            raise PsPermissionError()
        working_dir = self.working_root / public_id
        if meta.status not in {"INIT", "UPLOADING", "ERROR"} or not working_dir.is_dir():
            raise PsFileStatusInvalidError()
        upload = self._getUploadMeta(public_id)
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count < upload.total_chunks:
            raise PsArgmentsError("count")
        if not isinstance(blob, (bytes, bytearray)):
            raise PsArgmentsError("blob")
        if len(blob) > self.chunk_max_size:
            raise PsChunkEntityTooLargeError()
        expected = expected_chunk_size(meta.size, upload.total_chunks, count)
        if len(blob) != expected:
            raise PsChunkSizeMismatchError(expected, len(blob))
        if hashlib.sha256(blob).hexdigest().lower() != sha256.lower():
            self._PSDBM.status_change(pid, meta.contents_id, "ERROR")
            raise PsDataCorruotedError()
        fd = os.open(working_dir / f"chunk{count}.parts", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(blob)
        present = sum((working_dir / f"chunk{i}.parts").exists() for i in range(upload.total_chunks))
        status = "READY" if present == upload.total_chunks else "UPLOADING"
        self._PSDBM.status_change(pid, meta.contents_id, status)

    def commit(self, pid: str, public_id: str) -> FileMeta:
        """Assemble, verify, classify, and commit the content-derived filename."""
        if not isinstance(public_id, str) or not ID_RE.fullmatch(public_id):
            raise PsPublicIDInvalidError()
        meta = self._PSDBM.getMeta(public_id=public_id)
        if meta.pid != pid:
            raise PsPermissionError()
        if meta.status != "READY":
            raise PsFileStatusInvalidError()
        working_dir = self.working_root / public_id
        upload = self._getUploadMeta(public_id)
        complete = working_dir / "complete.parts"
        with complete.open("wb") as output:
            for i in range(upload.total_chunks):
                part = working_dir / f"chunk{i}.parts"
                if not part.exists():
                    raise PsDataCorruotedError()
                with part.open("rb") as source:
                    shutil.copyfileobj(source, output)
        if (_sha256_hex_file(complete).lower() != upload.sha256.lower()
                or complete.stat().st_size != meta.size):
            self._failed(pid, public_id)
            raise PsDataCorruotedError()
        try:
            cls = classify_file(complete, meta.suffix, max_image_pixels=self.max_image_pixels)
        except PsImageTooLargeError:
            self._failed(pid, public_id)
            raise
        destination = self.contents_root / format_psc_filename(meta.contents_id, cls.suffix)
        self.contents_root.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination.unlink()
        shutil.move(str(complete), str(destination))
        self._PSDBM.finalize_commit(pid, meta.contents_id, types=cls.types, suffix=cls.suffix)
        shutil.rmtree(working_dir, ignore_errors=True)
        return self._PSDBM.getMeta(contents_id=meta.contents_id)

    def gc(self, *, older_than_seconds: int = 86400) -> GcReport:
        """Remove stale upload rows and old orphan working directories."""
        removed_rows = 0
        removed_dirs = 0
        for meta in self._PSDBM.list_stale(older_than_seconds):
            shutil.rmtree(self.working_root / meta.public_id, ignore_errors=True)
            self._PSDBM.remove(meta.pid, contents_id=meta.contents_id, force=True)
            removed_rows += 1
        cutoff = time.time() - older_than_seconds
        if self.working_root.exists():
            for directory in self.working_root.iterdir():
                if not directory.is_dir() or not ID_RE.fullmatch(directory.name):
                    continue
                try:
                    self._PSDBM.getMeta(public_id=directory.name)
                except PsPublicIDInvalidError:
                    if directory.stat().st_mtime < cutoff:
                        shutil.rmtree(directory, ignore_errors=True)
                        removed_dirs += 1
        return GcReport(removed_rows=removed_rows, removed_dirs=removed_dirs)
