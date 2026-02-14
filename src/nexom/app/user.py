"""User model and user database storage."""

from __future__ import annotations

from dataclasses import dataclass

import pathlib as plb

from .db import DatabaseManager


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
        db_file = str(plb.Path(users_dir) / f"{pid}.db")
        super().__init__(db_file, auto_commit)
