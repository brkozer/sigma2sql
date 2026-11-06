"""Run rules against sample events in an in-memory SQLite database."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import replace
from typing import Any

from sigma2sql.rule import Rule
from sigma2sql.sql import Target, to_query

TABLE = "events"
COLUMN = "data"


def connect() -> sqlite3.Connection:
    """SQLite connection with the functions the sqlite dialect uses and SQLite lacks."""
    conn = sqlite3.connect(":memory:")
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    conn.create_function("cidr_match", 2, _cidr_match, deterministic=True)
    conn.create_aggregate("sigma_percentile", 2, _Percentile)  # type: ignore[arg-type]
    return conn


def target(base: Target | None = None) -> Target:
    """`base` (mapping, timestamp settings) pointed at the runner's events table."""
    base = base or Target()
    routes = tuple(replace(r, table=None) for r in base.routes)
    return replace(base, dialect="sqlite", table=TABLE, json_column=COLUMN, routes=routes)


def load(events: list[dict[str, Any]]) -> sqlite3.Connection:
    conn = connect()
    conn.execute(f"CREATE TABLE {TABLE} ({COLUMN} TEXT NOT NULL)")
    conn.executemany(
        f"INSERT INTO {TABLE} (rowid, {COLUMN}) VALUES (?, ?)",
        [(i + 1, _stored(e)) for i, e in enumerate(events)],
    )
    return conn


def _stored(event: dict[str, Any]) -> str:
    """JSON as a log file holds it, so a keyword such as `Système` finds its text."""
    text = json.dumps(event, ensure_ascii=False)
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def matching_events(
    rule: Rule, events: list[dict[str, Any]], base: Target | None = None
) -> list[int]:
    """Return the indexes of the events the rule matches."""
    query = to_query(rule, target(base), columns="rowid")
    with closing(load(events)) as conn:
        return [row[0] - 1 for row in conn.execute(query + " ORDER BY rowid")]


def rows(query: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run a query (e.g. a correlation) over the events and return named rows."""
    with closing(load(events)) as conn:
        cur = conn.execute(query)
        names = [d[0] for d in cur.description]
        return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def read_jsonl(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {n}: {exc}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"line {n}: each event must be a JSON object")
        events.append(event)
    return events


class _Percentile:
    """Linear interpolation between the closest ranks, as PostgreSQL's percentile_cont."""

    def __init__(self) -> None:
        self.values: list[float] = []
        self.fraction = 0.0

    def step(self, value: float | None, fraction: float) -> None:
        self.fraction = fraction
        if value is not None:
            self.values.append(value)

    def finalize(self) -> float | None:
        if not self.values:
            return None
        ordered = sorted(self.values)
        rank = (len(ordered) - 1) * self.fraction
        low = int(rank)
        high = min(low + 1, len(ordered) - 1)
        return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def _regexp(pattern: str, value: Any) -> bool:
    return value is not None and re.search(pattern, str(value)) is not None


def _cidr_match(value: Any, network: str) -> bool:
    try:
        return ipaddress.ip_address(str(value)) in ipaddress.ip_network(network)
    except ValueError:
        return False
