"""Run the shared cases on a real ClickHouse server. Set SIGMA2SQL_CH_URL to enable."""

from __future__ import annotations

from typing import Any

import pytest

from cases import CASES, rule_for
from clickhouse import URL, clickhouse_rows
from sigma2sql import Target, to_query, to_where

pytestmark = pytest.mark.skipif(not URL, reason="SIGMA2SQL_CH_URL not set")


@pytest.mark.parametrize(
    ("name", "detection", "events", "expected"), CASES, ids=[c[0] for c in CASES]
)
def test_case(name: str, detection: str, events: list[dict[str, Any]], expected: list[int]) -> None:
    query = to_query(rule_for(detection), Target("clickhouse", json_column="data"), "n")
    found = clickhouse_rows(query + " ORDER BY n", events)
    assert [row["n"] for row in found] == expected


def test_cidr_skips_text_that_is_not_an_address() -> None:
    rule = rule_for("sel: {Ip|cidr: 10.0.0.0/8}\ncondition: sel")
    query = to_query(rule, Target("clickhouse", json_column="data"), "n")
    events: list[dict[str, Any]] = [{"Ip": "nope"}, {"Ip": ""}, {"Ip": "10.1.2.3"}, {"Other": 1}]
    assert [r["n"] for r in clickhouse_rows(query, events)] == [2]


def test_backslashes_survive_the_literal() -> None:
    expr = rule_for("sel: {A: 'c:\\x'}\ncondition: sel").compile()
    assert to_where(expr, Target("clickhouse")) == """lowerUTF8("A") = 'c:\\\\x'"""
