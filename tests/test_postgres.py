"""Run the shared cases against a real PostgreSQL. Set SIGMA2SQL_PG_DSN to enable."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import pytest

from cases import CASES, rule_for
from sigma2sql import Target, to_query

DSN = os.environ.get("SIGMA2SQL_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SIGMA2SQL_PG_DSN not set")

if DSN:
    import psycopg


@pytest.fixture(scope="module")
def conn() -> Iterator[Any]:
    with psycopg.connect(DSN, autocommit=True) as c:
        yield c


@pytest.mark.parametrize(
    ("name", "detection", "events", "expected"), CASES, ids=[c[0] for c in CASES]
)
def test_case(
    conn: Any, name: str, detection: str, events: list[dict[str, Any]], expected: list[int]
) -> None:
    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE events (n int, data jsonb)")
        try:
            for i, e in enumerate(events):
                cur.execute("INSERT INTO events VALUES (%s, %s)", (i, json.dumps(e)))
            query = to_query(rule_for(detection), Target("postgres", json_column="data"), "n")
            # psycopg treats % as a placeholder marker; the query has no parameters.
            cur.execute(query.replace("%", "%%") + " ORDER BY n")
            assert [row[0] for row in cur.fetchall()] == expected
        finally:
            cur.execute("DROP TABLE events")
