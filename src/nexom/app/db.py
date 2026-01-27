from __future__ import annotations

from typing import Any, Iterable
from sqlite3 import (
    connect, 
    Connection, 
    Cursor, 

    Error,
    OperationalError,
    IntegrityError,
    ProgrammingError
)

from ..core.error import (
    DBError,

    DBMConnectionInvalidError, 
    DBOperationalError,
    DBIntegrityError,
    DBProgrammingError
)

def _call_error_handler(e: Error):
    if isinstance(e, OperationalError):
        raise DBOperationalError(str(e))
    elif isinstance(e, ProgrammingError):
        raise DBProgrammingError(str(e))
    elif isinstance(e, IntegrityError):
        raise DBIntegrityError(str(e))
    else:
        raise DBMConnectionInvalidError(str(e))


class DatabaseManager:
    def __init__(self, db_file: str, auto_commit: bool = True):
        self.db_file: str = db_file
        self.auto_commit: bool = auto_commit

        self._conn: Connection | None = None
        self._cursor: Cursor | None = None

        self.start_connection(auto_commit=auto_commit)
        self._init()

    def _init(self) -> None:
        "for override"
        ...

    def start_connection(self, auto_commit: bool = True) -> None:
        try:
            self.auto_commit = auto_commit
            self._conn = connect(self.db_file)
            self._cursor = self._conn.cursor()

            # ---- SQLite safety / performance defaults ----
            # foreign keys are OFF by default in SQLite
            self._cursor.execute("PRAGMA foreign_keys = ON")
            # better concurrency
            self._cursor.execute("PRAGMA journal_mode = WAL")
            # avoid immediate 'database is locked'
            self._cursor.execute("PRAGMA busy_timeout = 3000")
            # reasonable durability vs speed (WAL推奨とセット)
            self._cursor.execute("PRAGMA synchronous = NORMAL")

            self.commit()
        except Error as e:
            _call_error_handler(e)

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

    # ---- new canonical names ----

    def execute(self, sql: str, *args: Any) -> list[tuple] | None:
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
            _call_error_handler(e)


    def execute_many(self, sql_inserts: Iterable[ list[ tuple[str, tuple] ] ]) -> None:
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()

        try:
            for sql, values in sql_inserts:
                self._cursor.execute(sql, values)

            if self.auto_commit:
                self._conn.commit()

        except Error as e:
            self._conn.rollback()
            _call_error_handler(e)
        