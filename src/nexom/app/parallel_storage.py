"""Parallel storage and multipart upload."""

from typing import Literal
from pathlib import Path
from dataclasses import dataclass
import shutil
import hashlib
import secrets

from json.decoder import JSONDecodeError
import json

from .db import DatabaseManager

from ..core.error import PsStatusTypesError, PsFileStatusInvalidError, PsArgmentsError, PsPublicIDInvalidError, PsContentsIDInvalidError, PsDataCorruotedError, PsChunkEntityTooLargeError, PsPermissionError, PsFileTypesError

chunk_max_size = 1024 * 1024 * 10

FileTypes = Literal["Documents", "Images", "Binary", "Media", "Dangerous"]
FileStatus = Literal["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED", "ERROR"]
def _FileStatusTypesCheck(status: FileStatus) -> None:
    if not (status in ["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED"]): raise PsStatusTypesError(status)
    
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
    """
    Build a PSC filename for X-Accel-Redirect.

    Format:
        <contents_id>__PSC_arg1-000_arg2-111<suffix>
    kwargs are sorted alphabetically by key.
    """
    if kwargs:
        items = [f"{k}-{kwargs[k]}" for k in sorted(kwargs) if kwargs[k] is not None]
        tail = "__PSC_" + "_".join(items)
    else:
        tail = "__PSC_"
    return f"{contents_id}{tail}{suffix}"


class ParallelStorage:
    def __init__(self, db_file:str, contents_dir: str) -> None:
        self.contents_dir = Path(contents_dir)
        
        self._PSDBM = ParallelStorageDBM(db_file)
        
    def format_psc_public_id(self, public_id: str, **kwargs) -> Path:
        fMeta = self._PSDBM.getMeta(public_id=public_id)
        contents_actual_path = self.contents_dir / format_psc_filename(fMeta.contents_id, fMeta.suffix, **kwargs)
        return contents_actual_path.resolve()
    
    def comp_img(self, public_id: str, width: int, height: int, quality: int) -> Path:
        fMeta = self._PSDBM.getMeta(public_id=public_id)
        if not fMeta.isTypes("Images"):
            raise PsFileTypesError()
        
        if width <= 0 or height <= 0:
            raise PsArgmentsError()
        if quality < 1 or quality > 100:
            raise PsArgmentsError()
        
        original_path = self.format_psc_public_id(public_id)
        cache_path = (self.contents_dir / format_psc_filename(
            fMeta.contents_id, ".webp", width=width, height=height, quality=quality
        )).resolve()
        
        # originalの画像を指定の値で圧縮し、cache_pathへ保存、返り値はcache_path
        try:
            from PIL import Image  # type: ignore
        except Exception as e:
            raise ModuleNotFoundError(
                "Pillow is required for image compression. Install with: pip install Pillow"
            ) from e
        
        self.contents_dir.mkdir(parents=True, exist_ok=True)
        
        with Image.open(str(original_path)) as im:
            im = im.convert("RGB")
            if im.size != (width, height):
                im = im.resize((width, height), Image.LANCZOS)
            im.save(str(cache_path), format="WEBP", quality=quality, method=6)
        
        return cache_path
    
    def update_suffix(self, public_id: str, suffix: str) -> None:
        if not suffix.startswith("."):
            raise PsArgmentsError("suffix")
        fMeta = self._PSDBM.getMeta(public_id=public_id)
        self._PSDBM.update_suffix(fMeta.contents_id, suffix)
        
    def update_status(self, public_id: str, status: FileStatus) -> None:
        _FileStatusTypesCheck(status)
        fMeta = self._PSDBM.getMeta(public_id=public_id)
        self._PSDBM.status_change(fMeta.contents_id, status)


@dataclass(frozen=True)
class FileMeta:
    contents_id: str
    public_id: str
    types: str
    size: int
    pid: str
    filename: str
    suffix: str
    status: str
    permission_id: str | None
    creation_date: str
    last_access: str
    
    def isTypes(self, types: FileTypes) -> bool:
        if types not in ("Documents", "Images", "Binary", "Media", "Dangerous"):
            raise PsFileTypesError()
        return types == self.types

class ParallelStorageDBM(DatabaseManager):
    def __init__(self, db_file: str):
        super().__init__(db_file, auto_commit=False)
        
    def _init(self):
        self.execute(
            """
                CREATE TABLE IF NOT EXISTS parallel_storage (
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
                );
            """
        )
        self.commit()
        
    def _insert(self,
                *,
                contents_id: str,
                public_id: str,
                size: int,
                pid: str,
                filename: str,
                suffix: str,
                permission_id: str | None,
                ):
        self.execute(
            "INSERT INTO parallel_storage (contents_id, public_id, size, pid, filename, suffix, permission_id) VALUES(?, ?, ?, ?, ?, ?, ?)",
            contents_id, public_id, size, pid, filename, suffix, permission_id
        )
    def _get_by_public_id(self, public_id: str) -> tuple:
        l = self.execute("SELECT * FROM parallel_storage WHERE public_id = ?", public_id)
        if not l:
            raise PsPublicIDInvalidError()
        return l[0]

    def _get_by_contents_id(self, contents_id: str) -> tuple:
        l = self.execute("SELECT * FROM parallel_storage WHERE contents_id = ?", contents_id)
        if not l:
            raise PsContentsIDInvalidError()  # 例外名は本当は contents_id 用が欲しい
        return l[0]
        
    # First
    def register(self, filename: str, suffix: str, size: int, pid: str, permission_id: str | None = None) -> str:
        "Added in database and returns public_id"
        contents_id = _rand()
        public_id = _rand()
        self._insert(
            contents_id=contents_id,
            public_id=public_id,
            filename=filename,
            suffix=suffix,
            size=size,
            pid=pid,
            permission_id=permission_id
        )
        
        self.commit()
        
        return public_id
        
    # Changes
    def status_change(self, contents_id: str, status: FileStatus) -> None:
        _FileStatusTypesCheck(status)
        self.execute(
            "UPDATE parallel_storage SET status = ? WHERE contents_id = ?",
            status, contents_id
        )
        self.commit()
        
    def update_public_id(self, contents_id: str) -> None:
        new_public_id = _rand()
        self.execute(
            "UPDATE parallel_storage SET public_id = ? WHERE contents_id = ?",
            new_public_id, contents_id
        )
        self.commit()
    def update_types(self, contents_id: str, types: FileTypes) -> None:
        self.execute(
            "UPDATE parallel_storage SET types = ? WHERE contents_id = ?",
            types, contents_id
        )
        self.commit()
    def update_suffix(self, contents_id: str, suffix: str) -> None:
        self.execute(
            "UPDATE parallel_storage SET suffix = ? WHERE contents_id = ?",
            suffix, contents_id
        )
        self.commit()
        
    # Delete
    def remove(self, pid: str | None, *, contents_id:str | None = None, public_id:str | None = None) -> None:
        meta = self.getMeta(contents_id=contents_id, public_id=public_id)
    
        """
        permissons 実装後、ここで pid の認証をする。
        """
        possession_authoriry = True
        if not possession_authoriry : ...
        
        self.execute(
            "DELETE FROM parallel_storage WHERE contents_id = ?",
            meta.contents_id
        )
        self.commit()
        
        
    # Meta Getter
    def getMeta(self, *, contents_id:str | None = None, public_id:str | None = None) -> FileMeta:
        if (not contents_id) and (not public_id): raise PsArgmentsError()
        if contents_id and public_id: raise PsArgmentsError()
        
        if contents_id:
            record = self._get_by_contents_id(contents_id)
        if public_id:
            record = self._get_by_public_id(public_id)
        contents_id_, public_id, typess, sizes, pids, filename, suffix, status, permission_id, creation_date, last_access = record
        
        return FileMeta(contents_id_, public_id, typess, sizes, pids, filename, suffix, status, permission_id, creation_date, last_access)

    # Commit
    def commit(self) -> None:
        self._commit()
    
    
@dataclass(frozen=True)
class UploadMeta:
    public_id: str
    total_chunks: int
    sha256: str
    
    def toJson(self) -> str:
        return json.dumps({
            "public_id": self.public_id,
            "total_chunks": self.total_chunks,
            "sha256": self.sha256
        })
        
    @staticmethod
    def readJson(path: Path) -> "UploadMeta":
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
    def __init__(self, db_file: str, working_dir: str, contents_dir: str):
        self.db_file: str = db_file
        self.working_root: Path = Path(working_dir)
        self.contents_root: Path = Path(contents_dir)
        
        self._PSDBM = ParallelStorageDBM(db_file)
        
    def _getUploadMeta(self, public_id: str) -> UploadMeta:
        working_dir = self.working_root / public_id
        upload_meta = working_dir / "meta.json"
        
        return UploadMeta.readJson(upload_meta)
    
    def _failed(self, pid:str, public_id: str) -> None:
        self._PSDBM.remove(pid, public_id=public_id)
        working_dir = self.working_root / public_id
        
        shutil.rmtree(str(working_dir), ignore_errors=True)
        
        self._PSDBM.commit()
        
    def register(self, filename: str, size: int, pid: str, permission_id: str | None, total_chunks: int, sha256: str) -> str:
        "returns public_id"
        if size <= 0 or total_chunks <= 0:
            raise PsArgmentsError()
        
        stem = Path(filename).stem
        suffix = Path(filename).suffix

        public_id = self._PSDBM.register(stem, suffix, size, pid, permission_id)
        
        working_dir = self.working_root / public_id
        upload_meta = working_dir / "meta.json"
        
        uMeta = UploadMeta(public_id, total_chunks, sha256)
        
        working_dir.mkdir(parents=True, exist_ok=True)
        upload_meta.write_text(uMeta.toJson(), encoding="utf-8")
        
        self._PSDBM.commit()
        
        return public_id
        
    def parts_upload(self, pid: str, public_id: str, count: int, blob: bytes, sha256: str) -> None:
        working_dir = self.working_root / public_id
        upload_meta = working_dir / "meta.json"
        
        fMeta: FileMeta = self._PSDBM.getMeta(public_id=public_id)
        if (not fMeta.status in ["INIT", "UPLOADING", "ERROR"]) or (not working_dir.exists()): raise PsPublicIDInvalidError()
        
        if len(blob) > chunk_max_size:
            raise PsChunkEntityTooLargeError()
        
        if fMeta.pid != pid:
            raise PsPermissionError()
        
        parts = working_dir / f"chunk{count}.parts"
        parts.write_bytes(blob)
        
        actual = _sha256_hex_file(parts)
        
        if actual.lower() != sha256.lower(): 
            #self._failed(pid, public_id)
            self._PSDBM.status_change(fMeta.contents_id, "ERROR")
            raise PsDataCorruotedError()
        
        uMeta = UploadMeta.readJson(upload_meta)
        if count == uMeta.total_chunks - 1:
            self._PSDBM.status_change(fMeta.contents_id, "UPLOADING")
            for i in range(uMeta.total_chunks):
                if not (working_dir / f"chunk{i}.parts").exists():
                    break
            else:
                self._PSDBM.status_change(fMeta.contents_id, "READY")
        else:
            self._PSDBM.status_change(fMeta.contents_id, "UPLOADING")
        
    def commit(self, pid: str, public_id: str) -> FileMeta:
        fMeta: FileMeta = self._PSDBM.getMeta(public_id=public_id)
        file_suffix = Path(fMeta.filename).suffix
        
        if fMeta.pid != pid:
            raise PsPermissionError()

        working_dir = self.working_root / public_id
        upload_meta = working_dir / "meta.json"
        comp_file = working_dir / f"complete.parts"
        dest_file = self.contents_root / format_psc_filename(fMeta.contents_id, fMeta.suffix)

        uMeta = UploadMeta.readJson(upload_meta)

        with comp_file.open("wb") as o:
            for i in range(uMeta.total_chunks):
                parts = working_dir / f"chunk{i}.parts"
                if not parts.exists():
                    raise PsDataCorruotedError()
                with parts.open("rb") as p:
                    shutil.copyfileobj(p, o)

        actual = _sha256_hex_file(comp_file)
        if actual.lower() != uMeta.sha256.lower():
            raise PsDataCorruotedError()

        # サイズも最低限チェック
        if comp_file.stat().st_size != fMeta.size:
            raise PsDataCorruotedError()

        # move completed file into contents storage
        self.contents_root.mkdir(parents=True, exist_ok=True)
        if dest_file.exists():
            dest_file.unlink()
        shutil.move(str(comp_file), str(dest_file))

        # cleanup worker directory
        shutil.rmtree(str(working_dir), ignore_errors=True)

        self._PSDBM.status_change(fMeta.contents_id, "COMMITTED")
        return self._PSDBM.getMeta(contents_id=fMeta.contents_id)
