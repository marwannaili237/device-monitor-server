"""Postgres compatibility layer — lets the SQLite-style code in main.py run
against Neon/Postgres with minimal changes.

Maps the connection API used by the app onto psycopg2:
  - conn.execute(sql, params)      -> returns a Result (fetchone/fetchall)
  - conn.execute(...) is callable
  - rows support r["col"] and dict(r)
  - '?' placeholders -> '%s'
  - INSERT OR REPLACE / INSERT OR IGNORE -> Postgres upsert
Requires: DATABASE_URL env var (postgresql://...).
"""
import os
import re

import psycopg2
from psycopg2.extras import RealDictCursor


class Result:
    """Iterable/callable accessor like sqlite3.Row-list returned by execute()."""
    def __init__(self, cur, sql, params):
        self._cur = cur
        self._rows = None
        self.description = cur.description if cur.description else None

    def fetchone(self):
        if self._rows is None:
            self._rows = self._cur.fetchall()
        if not self._rows:
            return None
        return self._rows[0]

    def fetchmany(self, n):
        if self._rows is None:
            self._rows = self._cur.fetchall()
        return self._rows[:n]

    def fetchall(self):
        if self._rows is None:
            self._rows = self._cur.fetchall()
        return self._rows

    def __iter__(self):
        return iter(self.fetchall())


def _translate(sql):
    """SQLite '?' placeholders -> %s, and upsert forms -> PG ON CONFLICT."""
    # INSERT OR IGNORE INTO t(cols) VALUES(...)  ->  INSERT INTO t(cols) VALUES(...) ON CONFLICT DO NOTHING
    sql = re.sub(
        r'\bINSERT\s+OR\s+IGNORE\s+INTO\b(\s+\w+)',
        lambda m: 'INSERT INTO' + m.group(1) + ' ON CONFLICT DO NOTHING',
        sql, flags=re.I)
    # INSERT OR REPLACE INTO settings(...)  ->  upsert on key
    sql = re.sub(
        r'\bINSERT\s+OR\s+REPLACE\s+INTO\b(\s+settings\b)',
        lambda m: 'INSERT INTO' + m.group(1) + ' ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value',
        sql, flags=re.I)
    # INSERT OR REPLACE INTO device_policy(...)  ->  upsert on device_id
    sql = re.sub(
        r'\bINSERT\s+OR\s+REPLACE\s+INTO\b(\s+device_policy\b)',
        lambda m: 'INSERT INTO' + m.group(1) + ' ON CONFLICT (device_id) DO UPDATE SET policy=EXCLUDED.policy',
        sql, flags=re.I)
    # generic INSERT OR REPLACE (e.g. apps) -> plain INSERT (safe: app DELETEs first)
    sql = re.sub(r'\bINSERT\s+OR\s+REPLACE\s+INTO\b', 'INSERT INTO', sql, flags=re.I)
    # placeholder conversion (avoid touching $$ literals; none in this codebase)
    out = []
    i = 0
    while i < len(sql):
        c = sql[i]
        if c == '?':
            out.append('%s')
        elif c == "'":
            # copy a quoted string unchanged
            j = i + 1
            out.append(c)
            while j < len(sql):
                out.append(sql[j])
                if sql[j] == '\\':
                    j += 1
                    if j < len(sql):
                        out.append(sql[j])
                elif sql[j] == "'":
                    break
                j += 1
            i = j
        else:
            out.append(c)
        i += 1
    return ''.join(out)


class PG:
    """Connection wrapper exposing execute() like sqlite3.Connection."""
    def __init__(self, dsn):
        self._dsn = dsn
        self._conn = None
        self._connect()

    def _connect(self):
        self._conn = psycopg2.connect(self._dsn, connect_timeout=20, cursor_factory=RealDictCursor)

    def execute(self, sql, params=None):
        if params is None:
            params = ()
        if not isinstance(params, (tuple, list)):
            params = (params,)
        stmt = _translate(sql)
        cur = self._conn.cursor()
        try:
            if len(params) == 0:
                # No '?' placeholders: execute raw so literal '%' (e.g. LIKE 'x:%') is safe.
                cur.execute(stmt)
            else:
                cur.execute(stmt, tuple(params))
        except Exception as e:
            self._conn.rollback()
            raise
        return Result(cur, stmt, params)

    # transaction helpers
    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    # context manager: commit on success, rollback on error (sqlite-like)
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        except Exception:
            pass
        return False

    def cursor(self):
        return self._conn.cursor()


def connect():
    dsn = os.environ["DATABASE_URL"]
    return PG(dsn)