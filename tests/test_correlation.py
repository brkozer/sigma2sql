"""Correlations and legacy aggregations, run on SQLite, DuckDB and (with a DSN) PostgreSQL."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

import pytest

from sigma2sql import Collection, Correlation, RuleError, Target, correlation_query, load_documents
from sigma2sql.rule import Rule
from sigma2sql.runner import rows, target
from sigma2sql.sql import Dialect, to_query

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

RECON = r"""
title: whoami
name: whoami
detection:
  sel: {Image|endswith: '\whoami.exe'}
  condition: sel
---
title: net user
name: net_user
detection:
  sel: {CommandLine|contains: 'net user'}
  condition: sel
---
title: Recon sequence
correlation:
  type: temporal_ordered
  rules: [whoami, net_user]
  group-by: [host]
  timespan: 1m
  aliases:
    host: {whoami: Computer, net_user: Hostname}
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
        "temporal_ordered needs the rules in order, with aliases",
        RECON,
        [
            # pc1: whoami then net user, in order and inside the window.
            {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc1", "timestamp": t(0)},
            {"CommandLine": "net user /domain", "Hostname": "pc1", "timestamp": t(0, 30)},
            # pc2: the same two events the other way round.
            {"CommandLine": "net user", "Hostname": "pc2", "timestamp": t(0)},
            {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc2", "timestamp": t(0, 30)},
            # pc3: in order, but five minutes apart.
            {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc3", "timestamp": t(0)},
            {"CommandLine": "net user", "Hostname": "pc3", "timestamp": t(5)},
            # pc4: only the first half of the sequence.
            {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc4", "timestamp": t(0)},
        ],
        [("pc1", 2)],
    ),
    (
        "temporal_ordered with three steps, no groups, no timespan",
        """
title: download
name: download
detection:
  sel: {Action: download}
  condition: sel
---
title: execute
name: execute
detection:
  sel: {Action: execute}
  condition: sel
---
title: connect
name: connect
detection:
  sel: {Action: connect}
  condition: sel
---
title: Download and run
correlation:
  type: temporal_ordered
  rules: [download, execute, connect]
""",
        [
            {"Action": "download", "timestamp": t(0)},
            {"Action": "execute", "timestamp": t(1)},
            {"Action": "connect", "timestamp": t(2)},
        ],
        [(3,)],
    ),
    (
        "temporal_ordered ignores events that only fit one step once",
        """
title: both
name: both
detection:
  sel: {Action|contains: 'login'}
  condition: sel
---
title: Twice in a row
correlation:
  type: temporal_ordered
  rules: [both, both]
""",
        # One event cannot be both steps, and equal timestamps are not ordered.
        [{"Action": "login", "timestamp": t(0)}],
        [],
    ),
    (
        "a rule listed twice is one source of events",
        """
title: failed
name: failed
detection:
  sel: {EventID: 4625}
  condition: sel
---
title: Repeated failures
correlation:
  type: event_count
  rules: [failed, failed]
  timespan: 5m
  condition: {gte: 2}
""",
        [
            {"EventID": 4625, "timestamp": t(0)},
            {"EventID": 4625, "timestamp": t(0, 30)},
            {"EventID": 4624, "timestamp": t(1)},
        ],
        # Two matching events, not four: the duplicate entry must not duplicate the events.
        [(2,)],
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


def run_sqlite(text: str, events: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    sql, groups = _sql(text, target())
    return _normalise(rows(sql, events), groups)


def run_duckdb(text: str, events: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    pytest.importorskip("duckdb")
    from sigma2sql.hunt import connect

    con = connect()
    con.executemany("INSERT INTO events VALUES (?)", [(json.dumps(e),) for e in events])
    sql, groups = _sql(text, Target("duckdb", json_column="data"))
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return _normalise([dict(zip(names, r, strict=True)) for r in cur.fetchall()], groups)


def run_postgres(text: str, events: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    dsn = os.environ.get("SIGMA2SQL_PG_DSN")
    if not dsn:
        pytest.skip("SIGMA2SQL_PG_DSN not set")
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as con, con.cursor() as cur:
        cur.execute("CREATE TEMP TABLE events (data jsonb)")
        for e in events:
            cur.execute("INSERT INTO events VALUES (%s)", (json.dumps(e),))
        sql, groups = _sql(text, Target("postgres", json_column="data"))
        cur.execute(sql.replace("%", "%%"))
        assert cur.description is not None
        names = [d.name for d in cur.description]
        return _normalise([dict(zip(names, r, strict=True)) for r in cur.fetchall()], groups)


@pytest.mark.parametrize("engine", [run_sqlite, run_duckdb, run_postgres], ids=lambda f: f.__name__)
@pytest.mark.parametrize(("name", "text", "events", "expected"), CASES, ids=[c[0] for c in CASES])
def test_case(
    engine: Callable[..., list[tuple[Any, ...]]],
    name: str,
    text: str,
    events: list[dict[str, Any]],
    expected: list[tuple[Any, ...]],
) -> None:
    assert engine(text, events) == sorted(expected, key=repr)


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
        ("type: temporal_ordered\n  rules: [a]", "needs two or more"),
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


def _rows(dialect: Dialect, sql: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Named rows from the database `sql` was written for."""
    if dialect == "sqlite":
        return rows(sql, events)
    pytest.importorskip("duckdb")
    from sigma2sql.hunt import connect

    con = connect()
    con.executemany("INSERT INTO events VALUES (?)", [(json.dumps(e),) for e in events])
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]


@pytest.mark.parametrize("dialect", ["sqlite", "duckdb"])
def test_ordered_reports_the_first_sequence(dialect: Dialect) -> None:
    events = [
        {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc1", "timestamp": t(0)},
        {"CommandLine": "net user", "Hostname": "pc1", "timestamp": t(0, 30)},
        {"Image": "C:\\Windows\\whoami.exe", "Computer": "pc1", "timestamp": t(10)},
        {"CommandLine": "net user", "Hostname": "pc1", "timestamp": t(10, 30)},
    ]
    sql, groups = _sql(RECON, Target(dialect, json_column="data"))
    found = _rows(dialect, sql, events)
    assert _normalise(found, groups) == [("pc1", 2)]
    # The window of the earlier sequence, not of the later one.
    starts = [str(row["window_start"]).removesuffix(".000") for row in found]
    ends = [str(row["window_end"]).removesuffix(".000") for row in found]
    assert starts == ["2026-11-01 10:00:00"]
    assert ends == ["2026-11-01 10:00:30"]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("  condition: {gte: 2}\n", "takes no condition"),
        ("  condition: {field: Action, gte: 2}\n", "takes no condition"),
        ("  field: Action\n", "counts no field"),
    ],
)
def test_ordered_takes_no_condition(extra: str, message: str) -> None:
    text = (
        "title: a\nname: a\ndetection:\n  s: {A: 1}\n  condition: s\n---\n"
        "title: b\nname: b\ndetection:\n  s: {B: 1}\n  condition: s\n---\n"
        "title: both\ncorrelation:\n  type: temporal_ordered\n  rules: [a, b]\n" + extra
    )
    with pytest.raises(RuleError, match=message):
        load_documents(text)
