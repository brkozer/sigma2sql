from __future__ import annotations

import json
from typing import Any

import pytest

from cases import CASES, rule_for
from sigma2sql import Target, to_query
from sigma2sql.hunt import connect

pytest.importorskip("duckdb")


@pytest.mark.parametrize(
    ("name", "detection", "events", "expected"), CASES, ids=[c[0] for c in CASES]
)
def test_case(name: str, detection: str, events: list[dict[str, Any]], expected: list[int]) -> None:
    con = connect()
    con.execute("CREATE TABLE ev (n INTEGER, data JSON)")
    con.executemany(
        "INSERT INTO ev VALUES (?, ?)", [(i, json.dumps(e)) for i, e in enumerate(events)]
    )
    query = to_query(rule_for(detection), Target("duckdb", "ev", json_column="data"), "n")
    assert [row[0] for row in con.execute(query + " ORDER BY n").fetchall()] == expected
