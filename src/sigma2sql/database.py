"""Run rules where the logs already are: a read-only connection to a database.

Rules and logs are not to be trusted and this may be a production system, so every connection
refuses writes, each query has a time limit, and the address is never printed with its password.
"""

from __future__ import annotations

import base64
import http.client
import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

from sigma2sql.collection import Collection
from sigma2sql.errors import ConnectionLost, QueryTimeout
from sigma2sql.hunt import Report, open_duckdb, run_rules
from sigma2sql.runner import connect as connect_sqlite
from sigma2sql.sql import Dialect, Renderer, Target, quote_table

ENV = "SIGMA2SQL_DSN"
DEFAULT_TIMEOUT = 60
SCHEMES = "postgresql://, clickhouse://, clickhouses://, sqlite: or duckdb:"
# One SigmaHQ rule is larger than ClickHouse's default of 256 KiB.
CLICKHOUSE_QUERY_SIZE = 4 * 1024 * 1024


class Database(Protocol):
    dialect: Dialect

    def rows(self, query: str) -> list[dict[str, Any]]: ...

    def close(self) -> None: ...


class _Postgres:
    dialect: Dialect = "postgres"

    def __init__(self, dsn: str, timeout: int) -> None:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise SystemExit("PostgreSQL needs: pip install 'sigma2sql[postgres]'") from exc
        self.con: Any = psycopg.connect(dsn, autocommit=True, prepare_threshold=None)
        self.con.execute("SET default_transaction_read_only = on")
        self.con.execute(f"SET statement_timeout = {timeout * 1000}")
        self.con.execute("SET TIME ZONE 'UTC'")

    def rows(self, query: str) -> list[dict[str, Any]]:
        import psycopg

        try:
            cur = self.con.execute(query)
        except psycopg.errors.QueryCanceled as exc:
            raise QueryTimeout(str(exc)) from exc
        except psycopg.OperationalError as exc:
            if self.con.closed or self.con.broken:
                raise ConnectionLost(f"the database connection was lost: {exc}") from exc
            raise
        names = [column.name for column in cur.description]
        return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]

    def close(self) -> None:
        self.con.close()


def _clickhouse_error(body: str) -> str:
    try:
        return str(json.loads(body)["exception"]).strip()
    except (ValueError, KeyError, TypeError):
        return body


class _Refuse(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the user's password to another address."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_NO_REDIRECTS = urllib.request.build_opener(_Refuse)


class _ClickHouse:
    dialect: Dialect = "clickhouse"

    def __init__(self, dsn: str, timeout: int) -> None:
        url = urlsplit(dsn)
        secure = url.scheme in ("clickhouses", "https")
        scheme = "https" if secure else "http"
        host = f"[{url.hostname}]" if url.hostname and ":" in url.hostname else url.hostname
        port = url.port or (8443 if secure else 8123)
        settings: dict[str, str | int] = {
            "readonly": 2,  # 1 would also refuse the settings sent with each query
            "max_execution_time": timeout,
            "max_query_size": CLICKHOUSE_QUERY_SIZE,
            "output_format_json_quote_64bit_integers": 0,
        }
        database = url.path.strip("/")
        place = {"database": database} if database else {}
        base = f"{scheme}://{host}:{port}/?"
        self.url = base + urllib.parse.urlencode({**settings, **place})
        self.timeout = timeout + 30
        self.headers = {"Content-Type": "text/plain; charset=utf-8"}
        if url.username:
            login = f"{unquote(url.username)}:{unquote(url.password or '')}"
            token = base64.b64encode(login.encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        try:
            self.rows("SELECT 1")
        except RuntimeError as exc:
            if "readonly" not in str(exc).lower():
                raise
            # A user restricted with readonly = 1, the safest setup, may not send any setting.
            self.url = base + urllib.parse.urlencode(place)
            self.rows("SELECT 1")

    def rows(self, query: str) -> list[dict[str, Any]]:
        body = f"{query} FORMAT JSONEachRow".encode()
        request = urllib.request.Request(self.url, data=body, headers=self.headers)
        try:
            with _NO_REDIRECTS.open(request, timeout=self.timeout) as response:
                text = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = _clickhouse_error(exc.read(4000).decode("utf-8", "replace").strip())
            if "TIMEOUT_EXCEEDED" in detail or "Code: 159" in detail:
                raise QueryTimeout(detail) from exc
            raise RuntimeError(detail or f"ClickHouse answered {exc.code}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise ConnectionLost(f"the database connection was lost: {exc}") from exc
        return [json.loads(line) for line in text.splitlines() if line]

    def close(self) -> None:
        pass


class _Sqlite:
    dialect: Dialect = "sqlite"

    def __init__(self, path: str) -> None:
        self.con: sqlite3.Connection = connect_sqlite(path)

    def rows(self, query: str) -> list[dict[str, Any]]:
        cur = self.con.execute(query)
        names = [column[0] for column in cur.description]
        return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]

    def close(self) -> None:
        self.con.close()


class _DuckDb:
    dialect: Dialect = "duckdb"

    def __init__(self, path: str) -> None:
        self.con: Any = open_duckdb(path, read_only=True)

    def rows(self, query: str) -> list[dict[str, Any]]:
        cur = self.con.execute(query)
        names = [column[0] for column in cur.description]
        return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]

    def close(self) -> None:
        self.con.close()


def _local_path(dsn: str) -> str:
    path = unquote(urlsplit(dsn).path)
    if len(path) > 2 and path[0] == "/" and path[2] == ":":  # file:///C:/logs.db on Windows
        path = path[1:]
    if not path:
        raise ValueError("the database address has no file path")
    return path


def connect(dsn: str, timeout: int = DEFAULT_TIMEOUT) -> Database:
    try:
        scheme = urlsplit(dsn).scheme.lower()
    except ValueError as exc:
        raise ValueError("the database address cannot be read") from exc
    if scheme in ("postgresql", "postgres"):
        return _Postgres(dsn, timeout)
    if scheme in ("clickhouse", "clickhouses", "http", "https"):
        return _ClickHouse(dsn, timeout)
    if scheme == "sqlite":
        return _Sqlite(_local_path(dsn))
    if scheme == "duckdb":
        return _DuckDb(_local_path(dsn))
    raise ValueError(f"unknown kind of database address; expected {SCHEMES}")


def describe(dsn: str) -> str:
    """The address without the user name, password or options, safe to print and to report."""
    try:
        url = urlsplit(dsn)
    except ValueError:
        return "database"
    if url.scheme.lower() in ("sqlite", "duckdb"):
        return f"{url.scheme}:{url.path}"
    host = url.hostname or "localhost"
    try:
        port = f":{url.port}" if url.port else ""
    except ValueError:
        port = ""
    return f"{url.scheme}://{host}{port}{url.path}"


def scrub(text: str, dsn: str) -> str:
    """Take the password out of an error message from a driver."""
    try:
        password = urlsplit(dsn).password
    except ValueError:
        return text
    if password:
        for secret in {password, unquote(password)}:
            text = text.replace(secret, "***")
    return text


def _document(row: dict[str, Any], json_column: str | None) -> Any:
    """The event as a report shows it: its JSON document, or the columns of the row."""
    if json_column not in row:
        return row
    value = row[json_column]
    if isinstance(value, str | bytes):
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return row
    return value


def hunt_database(
    rules: Collection,
    db: Database,
    base: Target,
    examples: int = 0,
    progress: Callable[[int, int], None] | None = None,
) -> Report:
    """Run every rule and correlation in `rules` on the table `base` names, one at a time."""
    lenient = db.dialect in ("sqlite", "duckdb")
    target = replace(base, dialect=db.dialect, lenient_json=lenient)
    warnings: list[str] = []

    def count(query: str) -> int:
        return int(next(iter(db.rows(f"SELECT COUNT(*) AS n FROM ({query}) q")[0].values())))

    def sample(query: str, as_rows: bool) -> list[str]:
        found = db.rows(f"SELECT * FROM ({query}) q LIMIT {examples}")
        docs = found if as_rows else [_document(r, target.json_column) for r in found]
        return [json.dumps(doc, default=str, ensure_ascii=False) for doc in docs]

    events = _count_events(target, count, warnings)
    return run_rules(rules, target, events, warnings, count, sample, "*", examples, progress)


def _count_events(target: Target, count: Callable[[str], int], warnings: list[str]) -> int:
    """How many events the hunt looks at, in the base table and the tables of profile routes."""
    tables = list(dict.fromkeys([target.table, *(r.table for r in target.routes if r.table)]))
    time = Renderer(target).epoch()
    total = 0
    for table in tables:
        source = quote_table(table)
        try:
            if target.since is None:
                total += count(f"SELECT 1 AS x FROM {source}")
                continue
            recent = count(f"SELECT 1 AS x FROM {source} WHERE {time} >= {target.since!r}")
            total += recent
            readable = f"SELECT 1 AS x FROM {source} WHERE {time} IS NOT NULL"
            if not recent and count(f"SELECT 1 AS x FROM {source}") and not count(readable):
                raise ValueError(
                    f"--since: no row of {table} has a readable time in "
                    f"{target.timestamp}; set --timestamp-field or use a profile"
                )
        except QueryTimeout:
            warnings.append(f"{table}: the events could not be counted within the time limit")
        except (ValueError, ConnectionLost):
            raise
        except Exception:
            if len(tables) == 1:  # with routes, the rules that do use a missing table say so
                raise
    if target.lenient_json and target.json_column:
        column = quote_table(target.json_column)
        for table in tables:
            try:
                bad = count(
                    f"SELECT 1 AS x FROM {quote_table(table)} WHERE NOT json_valid({column})"
                )
            except ConnectionLost:
                raise
            except Exception:  # a missing route table is reported by the rules that use it
                continue
            if bad:
                warnings.append(f"{table}: {bad:,} rows are not valid JSON and have no fields")
    return total
