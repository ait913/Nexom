"""User model and user database storage."""

from __future__ import annotations

from dataclasses import dataclass

import pathlib as plb
import re

from .db import DatabaseManager
from nexom.core.error import AuthInvalidFieldError


_PID_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")


# --------------------
# models
# --------------------

@dataclass
class User:
    """User record model."""
    uid: str
    user_id: str
    public_name: str
    password_hash: str
    password_salt: str
    is_active: int


# --------------------
# UserDatabaseManager
# --------------------

class UserDatabaseManager(DatabaseManager):
    """Per-user SQLite database manager."""
    def __init__(self, users_dir:str, pid: str, auto_commit: bool = True):
        if not isinstance(pid, str) or _PID_RE.fullmatch(pid) is None:
            raise AuthInvalidFieldError("pid")
        users_root = plb.Path(users_dir).resolve()
        db_file = (users_root / f"{pid}.db").resolve()
        if not db_file.is_relative_to(users_root):
            raise AuthInvalidFieldError("pid")
        super().__init__(str(db_file), auto_commit)
