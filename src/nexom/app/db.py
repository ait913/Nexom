"""SQLite database manager."""

from __future__ import annotations

import os

from contextlib import contextmanager
from typing import Any, Iterable, Iterator
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
    """
    Simple SQLite database manager.

    - Opens a connection on construction
    - Applies safe PRAGMA defaults
    - Provides execute/execute_many helpers
    """
    def __init__(self, db_file: str, auto_commit: bool = True, *, file_mode: int | None = 0o600):
        self.db_file: str = db_file
        self.auto_commit: bool = auto_commit
        self.file_mode = file_mode

        self._conn: Connection | None = None
        self._cursor: Cursor | None = None
        self._tx_depth: int = 0  # immediate_transaction() nesting depth

        self.start_connection(auto_commit=auto_commit)
        try:
            self._init()
        except BaseException:
            if self._conn is not None:
                self.rip_connection()
            raise

    def _init(self) -> None:
        """Initialize tables (override in subclasses)."""
        ...

    def start_connection(self, auto_commit: bool = True) -> None:
        """Open a SQLite connection and apply PRAGMA defaults."""
        try:
            self.auto_commit = auto_commit
            if (self.file_mode is not None and self.db_file != ":memory:"
                    and not str(self.db_file).startswith("file:")):
                try:
                    try:
                        fd = os.open(self.db_file, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                    except FileExistsError:
                        pass  # existing file: leave its mode alone
                    else:
                        try:
                            if self.file_mode != 0o600:
                                os.fchmod(fd, self.file_mode)
                        finally:
                            os.close(fd)
                except OSError as e:
                    raise DBOperationalError(str(e)) from e
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
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None
                    self._cursor = None
            _call_error_handler(e)

    @contextmanager
    def immediate_transaction(self) -> Iterator[None]:
        """
        Run a block inside BEGIN IMMEDIATE ... COMMIT (rolled back on error).

        Nestable: if the connection is already in a transaction, the block runs
        inside a SAVEPOINT (RELEASE on success, ROLLBACK TO on error) and never
        commits by itself, so an exception in the outer block also discards the
        inner changes. commit() is a no-op while inside a block.
        """
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()
        previous = self.auto_commit
        self.auto_commit = False
        self._tx_depth += 1
        try:
            if self._conn.in_transaction:
                name = f"sp_{self._tx_depth}"
                try:
                    self._cursor.execute(f"SAVEPOINT {name}")
                except Error as e:
                    _call_error_handler(e)
                try:
                    yield
                except BaseException:
                    if self._conn.in_transaction:  # execute() may already have rolled back
                        try:
                            self._cursor.execute(f"ROLLBACK TO {name}")
                            self._cursor.execute(f"RELEASE {name}")
                        except Error:
                            pass
                    raise
                try:
                    self._cursor.execute(f"RELEASE {name}")
                except Error as e:
                    _call_error_handler(e)
            else:
                try:
                    self._cursor.execute("BEGIN IMMEDIATE")
                except Error as e:
                    _call_error_handler(e)
                try:
                    yield
                    self._conn.commit()
                except BaseException:
                    self._conn.rollback()
                    raise
        finally:
            self._tx_depth -= 1
            self.auto_commit = previous

    def rip_connection(self) -> None:
        """Close the current connection."""
        if self._conn is None:
            raise DBMConnectionInvalidError()
        self._conn.close()
        self._conn = None
        self._cursor = None

    def _commit(self) -> None:
        """Commit the current transaction."""
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()
        self._conn.commit()
        
    def commit(self) -> None:
        """Public commit wrapper (no-op inside immediate_transaction(); the block commits)."""
        if self._tx_depth > 0:
            return
        self._commit()

    # ---- new canonical names ----

    def execute(self, sql: str, *args: Any) -> list[tuple] | None:
        """
        Execute a single SQL statement.

        Returns rows for statements with a result set, otherwise None.
        """
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()

        try:
            self._cursor.execute(sql, tuple(args))
            rows = self._cursor.fetchall() if self._cursor.description is not None else None
            if self.auto_commit:
                self._conn.commit()
            return rows

        except Error as e:
            self._rollback_outside_transaction()
            _call_error_handler(e)


    def execute_many(self, sql_inserts: Iterable[ tuple[str, tuple] ]) -> None:
        """Execute multiple SQL statements in a single transaction."""
        if self._conn is None or self._cursor is None:
            raise DBMConnectionInvalidError()

        try:
            for sql, values in sql_inserts:
                self._cursor.execute(sql, values)

            if self.auto_commit:
                self._conn.commit()

        except Error as e:
            self._rollback_outside_transaction()
            _call_error_handler(e)

    def _rollback_outside_transaction(self) -> None:
        """
        Roll back after a failed statement unless an immediate_transaction() block is open.

        Inside immediate_transaction() the rollback is left to the context manager:
        ROLLBACK TO <savepoint> for nested blocks, ROLLBACK for the outermost one.
        A connection-wide rollback here would discard the outer block's changes
        and locks when the inner error is caught and the outer block continues.

        Outside a block the legacy behaviour is kept.  (``in_transaction`` is not
        used as the criterion: sqlite3 opens an implicit transaction before any
        DML, so it is True right after a failed INSERT even in auto-commit mode.)
        """
        if self._conn is None or self._tx_depth > 0:
            return
        self._conn.rollback()

