"""Correlations and legacy aggregations, run on every database that is available."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

import pytest

from clickhouse import clickhouse_rows
from sigma2sql import Collection, Correlation, RuleError, Target, correlation_query, load_documents
from sigma2sql.profile import apply_profile, load_profile
from sigma2sql.rule import Rule
from sigma2sql.runner import rows, target
from sigma2sql.sql import to_query

Runner = Callable[[str, list[dict[str, Any]], str], list[dict[str, Any]]]


def t(minute: int, second: int = 0) -> str:
    return f"2026-11-01T10:{minute:02d}:{second:02d}Z"


FAILED_LOGON = """
title: Failed logon
name: failed_logon
detection:
  sel: {EventID: 4625}
  condition: sel
"""

CASES: list[tuple[str, str, list[dict[str, Any]], list[tuple[Any, ...]]]] = [
    (
        "event_count in a sliding window, grouped",
        FAILED_LOGON
        + """---
title: Brute force
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [User]
  timespan: 5m
  condition: {gte: 3}
""",
        [
            {"EventID": 4625, "User": "alice", "timestamp": t(0)},
            {"EventID": 4625, "User": "alice", "timestamp": t(1)},
            {"EventID": 4624, "User": "alice", "timestamp": t(1, 30)},
            {"EventID": 4625, "User": "alice", "timestamp": t(2)},
            {"EventID": 4625, "User": "bob", "timestamp": t(0)},
            {"EventID": 4625, "User": "bob", "timestamp": t(10)},
            {"EventID": 4625, "User": "bob", "timestamp": t(20)},
        ],
        [("alice", 3)],
    ),
    (
        "value_count finds password spraying",
        FAILED_LOGON
        + """---
title: Spraying
correlation:
  type: value_count
  rules: failed_logon
  group-by: [IpAddress]
  timespan: 10m
  condition: {field: User, gte: 3}
""",
        [
            {"EventID": 4625, "User": "a", "IpAddress": "10.0.0.5", "timestamp": t(0)},
            {"EventID": 4625, "User": "a", "IpAddress": "10.0.0.5", "timestamp": t(1)},
            {"EventID": 4625, "User": "b", "IpAddress": "10.0.0.5", "timestamp": t(2)},
            {"EventID": 4625, "User": "c", "IpAddress": "10.0.0.5", "timestamp": t(3)},
            {"EventID": 4625, "User": "a", "IpAddress": "10.0.0.9", "timestamp": t(3)},
        ],
        [("10.0.0.5", 3)],
    ),
    (
        "temporal needs every rule in the window, with aliases",
        """
title: whoami
name: whoami
detection:
  sel: {Image|endswith: '\\whoami.exe'}
  condition: sel
---
title: net user
name: net_user
detection:
  sel: {CommandLine|contains: 'net user'}
  condition: sel
---
title: Recon burst
correlation:
  type: temporal
  rules: [whoami, net_user]
  group-by: [host]
  timespan: 1m
  aliases:
    host: {whoami: Computer, net_user: Hostname}
""",
        [
            {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc1", "timestamp": t(0)},
            {"CommandLine": "net user /domain", "Hostname": "pc1", "timestamp": t(0, 30)},
            {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc2", "timestamp": t(0)},
            {"CommandLine": "net user", "Hostname": "pc2", "timestamp": t(5)},
        ],
        [("pc1", 2)],
    ),
    (
        "value_sum over a window without group-by",
        """
title: Upload
name: upload
detection:
  sel: {Action: upload}
  condition: sel
---
title: Large upload
correlation:
  type: value_sum
  rules: [upload]
  timespan: 1h
  condition: {field: Bytes, gt: 1000}
""",
        [
            {"Action": "upload", "Bytes": 600, "timestamp": t(0)},
            {"Action": "upload", "Bytes": "500", "timestamp": t(30)},
            {"Action": "download", "Bytes": 5000, "timestamp": t(31)},
        ],
        [(1100,)],
    ),
    (
        "legacy count by, no timeframe",
        """
title: Many logons
detection:
  sel: {EventID: 4624}
  condition: sel | count() by IpAddress > 2
""",
        [
            {"EventID": 4624, "IpAddress": "1.1.1.1"},
            {"EventID": 4624, "IpAddress": "1.1.1.1"},
            {"EventID": 4624, "IpAddress": "1.1.1.1"},
            {"EventID": 4624, "IpAddress": "2.2.2.2"},
            {"EventID": 4624},
            {"EventID": 4624},
            {"EventID": 4624},
        ],
        [(None, 3), ("1.1.1.1", 3)],
    ),
    (
        "legacy distinct count with timeframe",
        """
title: Many users from one host
detection:
  sel: {EventID: 4624}
  timeframe: 1m
  condition: sel | count(User) by Host >= 2
""",
        [
            {"EventID": 4624, "User": "a", "Host": "h1", "timestamp": t(0)},
            {"EventID": 4624, "User": "b", "Host": "h1", "timestamp": t(0, 20)},
            {"EventID": 4624, "User": "a", "Host": "h2", "timestamp": t(0)},
            {"EventID": 4624, "User": "b", "Host": "h2", "timestamp": t(3)},
        ],
        [("h1", 2)],
    ),
    (
        "bad numbers and timestamps do not end a correlation",
        """
title: Transfer
name: transfer
detection:
  sel: {Action: download}
  condition: sel
---
title: Total
correlation:
  type: value_sum
  rules: [transfer]
  timespan: 10m
  condition: {field: Bytes, gte: 300}
""",
        [
            {"Action": "download", "Bytes": 100, "timestamp": t(0)},
            {"Action": "download", "Bytes": "-", "timestamp": t(1)},
            {"Action": "download", "Bytes": 200, "timestamp": t(2)},
            {"Action": "download", "Bytes": 900, "timestamp": "not a time"},
        ],
        [(300,)],
    ),
    (
        "value_median over a group",
        """
title: Transfer
name: transfer
detection:
  sel: {Action: download}
  condition: sel
---
title: Typical download size
correlation:
  type: value_median
  rules: [transfer]
  group-by: [User]
  condition: {field: Bytes, gte: 200}
""",
        [
            {"Action": "download", "User": "a", "Bytes": 100, "timestamp": t(0)},
            {"Action": "download", "User": "a", "Bytes": 200, "timestamp": t(1)},
            {"Action": "download", "User": "a", "Bytes": 9000, "timestamp": t(2)},
            {"Action": "download", "User": "b", "Bytes": 100, "timestamp": t(0)},
            {"Action": "download", "User": "b", "Bytes": 199, "timestamp": t(1)},
            {"Action": "upload", "User": "b", "Bytes": 9000, "timestamp": t(2)},
        ],
        [("a", 200)],
    ),
    (
        "value_percentile interpolates, in a window",
        """
title: Transfer
name: transfer
detection:
  sel: {Action: download}
  condition: sel
---
title: Large downloads
correlation:
  type: value_percentile
  rules: [transfer]
  timespan: 10m
  condition: {field: Bytes, percentile: 75, gte: 250}
""",
        [
            {"Action": "download", "Bytes": 100, "timestamp": t(0)},
            {"Action": "download", "Bytes": 200, "timestamp": t(1)},
            {"Action": "download", "Bytes": 300, "timestamp": t(2)},
        ],
        [(250,)],
    ),
]


def _sql(text: str, tgt: Target) -> tuple[str, list[str]]:
    docs = load_documents(text)
    corr = [d for d in docs if isinstance(d, Correlation)]
    if corr:
        col = Collection(rules=[d for d in docs if isinstance(d, Rule)], correlations=corr)
        return correlation_query(corr[0], col.resolve(corr[0]), tgt), list(corr[0].group_by)
    rule = docs[0]
    assert isinstance(rule, Rule) and rule.aggregation is not None
    return to_query(rule, tgt), list(rule.aggregation.group_by)


def _normalise(found: list[dict[str, Any]], groups: list[str]) -> list[tuple[Any, ...]]:
    out = []
    for row in found:
        value = float(row["value"])
        out.append((*(row[g] for g in groups), int(value) if value.is_integer() else value))
    return sorted(out, key=repr)


def _with(tgt: Target, profile: str | None) -> Target:
    return apply_profile(tgt, load_profile(profile)) if profile else tgt


def run_sqlite(
    text: str, events: list[dict[str, Any]], profile: str | None = None
) -> list[tuple[Any, ...]]:
    sql, groups = _sql(text, _with(target(), profile))
    return _normalise(rows(sql, events), groups)


def run_duckdb(
    text: str, events: list[dict[str, Any]], profile: str | None = None
) -> list[tuple[Any, ...]]:
    pytest.importorskip("duckdb")
    from sigma2sql.hunt import connect

    con = connect()
    con.executemany("INSERT INTO events VALUES (?)", [(json.dumps(e),) for e in events])
    sql, groups = _sql(text, _with(Target("duckdb", json_column="data"), profile))
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return _normalise([dict(zip(names, r, strict=True)) for r in cur.fetchall()], groups)


def run_postgres(
    text: str, events: list[dict[str, Any]], profile: str | None = None
) -> list[tuple[Any, ...]]:
    dsn = os.environ.get("SIGMA2SQL_PG_DSN")
    if not dsn:
        pytest.skip("SIGMA2SQL_PG_DSN not set")
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as con, con.cursor() as cur:
        cur.execute("CREATE TEMP TABLE events (data jsonb)")
        for e in events:
            cur.execute("INSERT INTO events VALUES (%s)", (json.dumps(e),))
        sql, groups = _sql(text, _with(Target("postgres", json_column="data"), profile))
        cur.execute(sql.replace("%", "%%"))
        assert cur.description is not None
        names = [d.name for d in cur.description]
        return _normalise([dict(zip(names, r, strict=True)) for r in cur.fetchall()], groups)


def run_clickhouse(
    text: str, events: list[dict[str, Any]], profile: str | None = None
) -> list[tuple[Any, ...]]:
    sql, groups = _sql(text, _with(Target("clickhouse", json_column="data"), profile))
    return _normalise(clickhouse_rows(sql, events), groups)


@pytest.mark.parametrize(
    "engine", [run_sqlite, run_duckdb, run_postgres, run_clickhouse], ids=lambda f: f.__name__
)
@pytest.mark.parametrize(("name", "text", "events", "expected"), CASES, ids=[c[0] for c in CASES])
def test_case(
    engine: Callable[..., list[tuple[Any, ...]]],
    name: str,
    text: str,
    events: list[dict[str, Any]],
    expected: list[tuple[Any, ...]],
) -> None:
    assert engine(text, events) == sorted(expected, key=repr)


BRUTE_FORCE = (
    FAILED_LOGON
    + """---
title: Brute force
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [TargetUserName]
  timespan: 5m
  condition: {gte: 3}
"""
)


def evtx_event(minute: int) -> dict[str, Any]:
    system = {"EventID": 4625, "TimeCreated": {"#attributes": {"SystemTime": t(minute)}}}
    return {"Event": {"System": system, "EventData": {"TargetUserName": "admin"}}}


def ecs_event(minute: int) -> dict[str, Any]:
    return {
        "@timestamp": t(minute),
        "event": {"code": "4625"},
        "winlog": {"event_data": {"TargetUserName": "admin"}},
    }


@pytest.mark.parametrize(
    "run", [run_sqlite, run_duckdb, run_postgres, run_clickhouse], ids=lambda r: r.__name__[4:]
)
@pytest.mark.parametrize(
    ("profile", "event"), [("evtx", evtx_event), ("ecs-winlogbeat", ecs_event)]
)
def test_time_window_with_a_profile(
    run: Callable[..., list[tuple[Any, ...]]],
    profile: str,
    event: Callable[[int], dict[str, Any]],
) -> None:
    """These profiles have a `default_field`, which must not move the time field."""
    assert run(BRUTE_FORCE, [event(0), event(1), event(2)], profile) == [("admin", 3)]
    assert run(BRUTE_FORCE, [event(0), event(10), event(20)], profile) == []


@pytest.mark.parametrize(
    "run", [run_sqlite, run_duckdb, run_postgres, run_clickhouse], ids=lambda r: r.__name__[4:]
)
def test_time_field_kept_with_the_other_fields(
    run: Callable[..., list[tuple[Any, ...]]], tmp_path: Any
) -> None:
    profile = tmp_path / "p.yml"
    profile.write_text('nested: true\ntimestamp: ts\ndefault_field: "attrs.{field}"\n')
    events = [
        {"attrs": {"EventID": 4625, "TargetUserName": "admin", "ts": t(m)}} for m in (0, 1, 2)
    ]
    assert run(BRUTE_FORCE, events, str(profile)) == [("admin", 3)]


def test_mapping_can_move_the_time_field() -> None:
    tgt = Target("duckdb", json_column="data", mapping={"timestamp": "when"})
    assert "$.when" in _sql(BRUTE_FORCE, tgt)[0].replace('"', "")


def test_epoch_timestamps() -> None:
    text = CASES[0][1]
    events = [
        {"EventID": 4625, "User": "u", "ts": 1_700_000_000_000 + i * 60_000} for i in range(3)
    ]
    tgt = target(Target(timestamp="ts", timestamp_format="epoch_ms"))
    sql, groups = _sql(text, tgt)
    assert _normalise(rows(sql, events), groups) == [("u", 3)]


def test_referenced_rules_are_not_standalone() -> None:
    docs = load_documents(CASES[0][1])
    col = Collection(
        rules=[d for d in docs if isinstance(d, Rule)],
        correlations=[d for d in docs if isinstance(d, Correlation)],
    )
    assert col.standalone() == []
    generating = load_documents(
        CASES[0][1].replace("type: event_count", "type: event_count\n  generate: true")
    )
    col = Collection(
        rules=[d for d in generating if isinstance(d, Rule)],
        correlations=[d for d in generating if isinstance(d, Correlation)],
    )
    assert [r.title for r in col.standalone()] == ["Failed logon"]


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("type: temporal_ordered\n  rules: [a]", "temporal_ordered"),
        ("type: value_median\n  rules: [a]\n  condition: {gte: 2}", "condition field"),
        (
            "type: value_percentile\n  rules: [a]\n  condition: {field: f, gte: 2}",
            "percentile",
        ),
        (
            "type: value_percentile\n  rules: [a]\n  condition: {field: f, percentile: 101, lt: 2}",
            "percentile",
        ),
        ("type: value_count\n  rules: [a]\n  condition: {gte: 2}", "condition field"),
        ("type: event_count\n  rules: [a]\n  timespan: 5x\n  condition: {gte: 2}", "timespan"),
        ("type: event_count\n  rules: [a]\n  condition: {gte: two}", "condition"),
        ("type: event_count\n  rules: [nope]\n  condition: {gte: 2}", "unknown rules"),
    ],
)
def test_bad_correlations(spec: str, message: str) -> None:
    text = (
        "title: a\nname: a\ndetection:\n  s: {A: 1}\n  condition: s\n---\ncorrelation:\n  " + spec
    )
    with pytest.raises(Exception, match=message) as info:
        docs = load_documents(text)
        corr = next(d for d in docs if isinstance(d, Correlation))
        Collection(rules=[d for d in docs if isinstance(d, Rule)]).resolve(corr)
    assert isinstance(info.value, RuleError | Exception)
