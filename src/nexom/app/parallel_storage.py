from typing import Literal
from pathlib import Path
from dataclasses import dataclass
import shutil
import hashlib
import secrets
import json

from .db import DatabaseManager

from ..core.error import PsStatusTypesError, PsFileStatusInvalidError, PsArgmentsError, PsPublicIDInvalidError, PsDataCorruotedError

FileTypes = Literal["Documents", "Images", "Binary", "Media", "Dangerous"]
FileStatus = Literal["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED"]
def _FileStatusTypesCheck(status: FileStatus) -> None:
    if not (status in ["INIT", "UPLOADING", "READY", "COMMITTED", "ABORTED"]): raise PsStatusTypesError(status)
    
def _rand(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)

def _sha256_hex_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read()
            if not b:
                break
            h.update(b)
    return h.hexdigest()


@dataclass(frozen=True)
class FileMeta:
    contents_id: str
    public_id: str
    types: str
    size: int
    pid: str
    filename: str
    status: str
    permission_id: str | None
    creation_date: str
    last_access: str

class ParallelStorageDBM(DatabaseManager):
    def __init__(self, db_file: str):
        super().__init__(db_file, auto_commit=False)
        
    def _init(self):
        self.execute_many(
            [
                (
                    """
                    CREATE TABLE IF NOT EXISTS parallel_storage WHERE contents_id = ? ,
                    meta.contents_id(
                        contents_id TEXT PRIMARY KEY,
                        public_id TEXT UNIQUE,
                        types TEXT DEFAULT "Binary",
                        size INT NOT NULL,
                        pid TEXT UNIQUE
                        filename TEXT NOT NULL,
                        status TEXT DEFAULT "INIT",
                        permission_id TEXT DEFAULT NULL,
                        creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    );
                    """,
                    (),
                ),
            ]
        )
        
    def _insert(self,
                *,
                contents_id: str,
                public_id: str,
                size: int,
                pid: str,
                filename: str,
                permission_id: str | None,
                ):
        self.execute(
            "INSERT INTO parallel_storage (contents_id, public_id, size, pid, filename, permission_id) VALUES(?, ?, ?, ?, ?, ?)",
            contents_id, public_id, size, pid, filename, permission_id
        )
    def _get_by_contents_id(self, contents_id: str) -> tuple:
        l = self.execute("SELECT * FROM parallel_storage WHERE contents_id = ?", contents_id)
    def _get_by_public_id(self, public_id: str) -> tuple:
        l = self.execute("SELECT * FROM parallel_storage WHERE public_id = ?", public_id)
        return l[0]
        
    # First
    def register(self, filename: str, size: int, pid: str, permission_id: str | None = None) -> str:
        "Added in database and returns public_id"
        contents_id = _rand()
        public_id = _rand()
        self._insert(
            contents_id=contents_id,
            public_id=public_id,
            filename=filename,
            size=size,
            pid=pid,
            permission_id=permission_id
        )
        
        return public_id
        
    # Changes
    def status_change(self, contents_id: str, status: FileStatus) -> None:
        _FileStatusTypesCheck(status)
        self.execute(
            "UPDATE parallel_storage SET status = ? WHERE contents_id = ?",
            status, contents_id
        )
        
    def update_public_id(self, contents_id: str) -> None:
        new_public_id = _rand()
        self.execute(
            "UPDATE parallel_storage SET public_id = ? WHERE contents_id = ?",
            new_public_id, contents_id
        )
    def update_types(self, contents_id: str, types: FileTypes) -> None:
        self.execute(
            "UPDATE parallel_storage SET types = ? WHERE contents_id = ?",
            types, contents_id
        )
        
    # Delete
    def remove(self, pid: str | None, *, contents_id:str | None, public_id:str | None = None) -> None:
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
        
        
    # Meta Getter
    def getMeta(self, *, contents_id:str | None, public_id:str | None = None) -> FileMeta:
        if (not contents_id) and (not contents_id): raise PsArgmentsError()
        if contents_id:
            record = self._get_by_contents_id(contents_id)
        if public_id:
            record = self._get_by_public_id(public_id)
        contents_id_, public_id, typess, sizes, pids, filenames, status, permission_id, creation_date, last_access = record
        
        if not ( status == "ABORTED" ): return PsFileStatusInvalidError()
        return FileMeta(contents_id_, public_id, typess, sizes, pids, filenames, status, permission_id, creation_date, last_access)

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
        with path.open(mode="r", encoding="utf-8") as m:
            meta_dict = json.load(m)
        d = json.load(meta_dict)
        return UploadMeta(
            public_id=d.get("public_id"),
            total_chunks=d.get("total_chunks"),
            sha256=d.get("sha256")
        )

class MultiPartUpload:
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
        
        shutil.rmtree(str(working_dir))
        
        self._PSDBM.commit()
        
    def register(self, filename: str, size: int, pid: int, permission_id: str | None, total_chunks: int, sha256: str):
        public_id = self._PSDBM.register(filename, size, pid, permission_id)
        
        working_dir = self.working_root / public_id
        upload_meta = working_dir / "meta.json"
        
        uMeta = UploadMeta(public_id, total_chunks, sha256)
        
        working_dir.mkdir()
        upload_meta.write_text(uMeta.toJson(), encoding="utf-8")
        
        self._PSDBM.commit()
        
    def parts_upload(self, pid: str, public_id: str, count: str, blob: bytes, sha256: str) -> None:
        working_dir = self.working_root / public_id
        
        fMeta: FileMeta = self._PSDBM.getMeta(public_id=public_id)
        if (not fMeta.status in ["INIT", "UPLOADING"]) or (not working_dir.exists()): raise PsPublicIDInvalidError()
        
        parts = working_dir / f"chunk{count}.parts"
        parts.write_bytes(blob)
        
        actual = _sha256_hex_file(str(parts))
        
        if actual.lower() != sha256.lower(): 
            self._failed(pid, public_id)
            raise PsDataCorruotedError()
        
    def build(self, public_id: str) -> FileMeta:
        fMeta: FileMeta = self._PSDBM.getMeta(public_id=public_id)
        file_suffix = Path(fMeta.filename).suffix
        
        working_dir = self.working_root / public_id
        upload_meta = working_dir / "meta.json"
        comp_file = working_dir / f"complete{file_suffix}"
        
        uMeta = UploadMeta.readJson(upload_meta)
        
        with comp_file.open("wb") as o:
            for i in range(uMeta.total_chunks):
                parts = working_dir / f"chunk{i}.parts"
                if not parts.exists():
                    raise PsDataCorruotedError()
                with parts.open("rb") as p:
                    o.write(p.read())
                    
        actual = _sha256_hex_file(comp_file)
        
        if actual.lower() != uMeta.sha256.lower(): raise PsDataCorruotedError()
        
        