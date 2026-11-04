"""Run a rule against sample events in an in-memory SQLite database."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from typing import Any

from sigma2sql.rule import Rule
from sigma2sql.sql import Target, to_query

TABLE = "events"
COLUMN = "data"


def connect() -> sqlite3.Connection:
    """SQLite connection with the REGEXP and cidr_match functions the sqlite dialect uses."""
    conn = sqlite3.connect(":memory:")
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    conn.create_function("cidr_match", 2, _cidr_match, deterministic=True)
    return conn


def matching_events(
    rule: Rule, events: list[dict[str, Any]], mapping: Mapping[str, str] | None = None
) -> list[int]:
    """Return the indexes of the events the rule matches."""
    target = Target("sqlite", TABLE, dict(mapping or {}), json_column=COLUMN)
    query = to_query(rule, target, columns="rowid")
    with closing(connect()) as conn:
        conn.execute(f"CREATE TABLE {TABLE} ({COLUMN} TEXT NOT NULL)")
        conn.executemany(
            f"INSERT INTO {TABLE} (rowid, {COLUMN}) VALUES (?, ?)",
            [(i + 1, json.dumps(e)) for i, e in enumerate(events)],
        )
        return [row[0] - 1 for row in conn.execute(query + " ORDER BY rowid")]


def read_jsonl(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"line {n}: each event must be a JSON object")
        events.append(event)
    return events


def _regexp(pattern: str, value: Any) -> bool:
    return value is not None and re.search(pattern, str(value)) is not None


def _cidr_match(value: Any, network: str) -> bool:
    try:
        return ipaddress.ip_address(str(value)) in ipaddress.ip_network(network)
    except ValueError:
        return False
