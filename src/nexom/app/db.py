from __future__ import annotations

from typing import Any
from sqlite3 import connect, Connection, Cursor, Error

from ..core.error import DBMConnectionInvalidError, DBError


class DatabaseManager:
    def __init__(self, db_file: str, auto_commit: bool = True):
        self.db_file: str = db_file
        self.auto_commit: bool = auto_commit

        self._conn: Connection | None = None
        self._cursor: Cursor | None = None

        self.start_connection(auto_commit=auto_commit)
        self._init()  # ←これ必須

    def _init(self) -> None:
        "for override"

    def start_connection(self, auto_commit: bool = True) -> None:
        self.auto_commit = auto_commit
        self._conn = connect(self.db_file)
        self._cursor = self._conn.cursor()

        self._cursor.execute("PRAGMA foreign_keys = ON")
        self.commit()

    def rip_connection(self) -> None:
        if self._conn is None:
            raise DBMConnectionInvalidError()
        self._conn.close()
        self._conn = None
        self._cursor = None

    def commit(self) -> None:
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()
        
        self._conn.commit()

    def excute(self, sql: str, *args: Any) -> list[tuple] | None:
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()

        try:
            self._cursor.execute(sql, tuple(args))
            if self.auto_commit:
                self._conn.commit()

            if sql.lstrip().upper().startswith("SELECT"):
                return self._cursor.fetchall()
            return None

        except Error as e:
            self._conn.rollback()
            raise DBError(str(e))

    def excute_many(self, *sql_inserts: tuple[str, tuple]) -> None:
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()

        try:
            for sql, values in sql_inserts:
                self._cursor.execute(sql, values)

            if self.auto_commit:
                self._conn.commit()

        except Error as e:
            self._conn.rollback()
            raise DBError(str(e))