"""`hunt` connected to a database, on every database that is available."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import clickhouse
from sigma2sql import database
from sigma2sql.cli import main

TABLE = "s2s_hunt_events"
EVENTS: list[dict[str, Any]] = [
    {"EventID": 4625, "User": "admin", "timestamp": "2026-11-01T10:00:00Z", "Path": "C:\\Windows"},
    {"EventID": 4625, "User": "admin", "timestamp": "2026-11-01T10:01:00Z"},
    {"EventID": 4625, "User": "admin", "timestamp": "2026-11-01T10:02:00Z"},
    {"EventID": 4624, "User": "bob", "timestamp": "2026-11-05T10:00:00Z"},
]
RULES = r"""title: failed
name: failed
level: high
detection: {s: {EventID: 4625}, condition: s}
---
title: three failures
level: critical
correlation:
  type: event_count
  rules: [failed]
  group-by: [User]
  timespan: 5m
  condition: {gte: 3}
---
title: path keyword
level: low
detection: {k: ['C:\Windows'], condition: k}
---
title: logon
level: medium
detection: {s: {EventID: 4624}, condition: s}
"""


def sqlite_db(tmp_path: Path) -> Iterator[str]:
    path = tmp_path / "logs.db"
    con = sqlite3.connect(path)
    con.execute(f"CREATE TABLE {TABLE} (event TEXT)")
    con.executemany(f"INSERT INTO {TABLE} VALUES (?)", [(json.dumps(e),) for e in EVENTS])
    con.commit()
    con.close()
    yield f"sqlite:{path}"


def duckdb_db(tmp_path: Path) -> Iterator[str]:
    duck = pytest.importorskip("duckdb")
    path = tmp_path / "logs.duckdb"
    con = duck.connect(str(path))
    con.execute(f"CREATE TABLE {TABLE} (event JSON)")
    con.executemany(f"INSERT INTO {TABLE} VALUES (?)", [(json.dumps(e),) for e in EVENTS])
    con.close()
    yield f"duckdb:{path}"


def postgres_db(tmp_path: Path) -> Iterator[str]:
    dsn = os.environ.get("SIGMA2SQL_PG_DSN")
    if not dsn:
        pytest.skip("SIGMA2SQL_PG_DSN not set")
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as con:
        con.execute(f"DROP TABLE IF EXISTS {TABLE}")
        con.execute(f"CREATE TABLE {TABLE} (event jsonb)")
        for event in EVENTS:
            con.execute(f"INSERT INTO {TABLE} VALUES (%s)", (json.dumps(event),))
    yield dsn
    with psycopg.connect(dsn, autocommit=True) as con:
        con.execute(f"DROP TABLE {TABLE}")


def clickhouse_db(tmp_path: Path) -> Iterator[str]:
    if not clickhouse.URL:
        pytest.skip("SIGMA2SQL_CH_URL not set")
    clickhouse.execute(f"DROP TABLE IF EXISTS {TABLE}")
    clickhouse.execute(f"CREATE TABLE {TABLE} (event String) ENGINE = Memory")
    rows = "\n".join(json.dumps({"event": json.dumps(e)}) for e in EVENTS)
    clickhouse.execute(f"INSERT INTO {TABLE} FORMAT JSONEachRow", rows)
    yield clickhouse.URL
    clickhouse.execute(f"DROP TABLE {TABLE}")


Fixture = Callable[[Path], Iterator[str]]
ALL = [sqlite_db, duckdb_db, postgres_db, clickhouse_db]


@pytest.fixture(params=ALL, ids=lambda f: f.__name__[:-3])
def dsn(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    yield from request.param(tmp_path)


def hunt(tmp_path: Path, address: str, monkeypatch: pytest.MonkeyPatch, *extra: str) -> int:
    monkeypatch.setenv(database.ENV, address)
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    args = ["hunt", str(rules), "-t", TABLE, "--json-column", "event", "--format", "json", *extra]
    return main(args)


def test_rules_run_in_the_database(
    tmp_path: Path, dsn: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert hunt(tmp_path, dsn, monkeypatch, "-e", "1") == 0
    out = capsys.readouterr()
    hits = {h["title"]: h for h in json.loads(out.out)}
    assert {t: h["count"] for t, h in hits.items()} == {
        "three failures": 1,
        "logon": 1,
        "path keyword": 1,
    }
    assert hits["logon"]["examples"] == [EVENTS[3]]
    assert hits["three failures"]["examples"][0]["value"] == 3
    assert "matched 4 events" in out.err


def test_since_limits_the_events(
    tmp_path: Path, dsn: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert hunt(tmp_path, dsn, monkeypatch, "--since", "2026-11-03") == 0
    out = capsys.readouterr()
    assert [h["title"] for h in json.loads(out.out)] == ["logon"]
    assert "matched 1 events" in out.err


def test_the_connection_cannot_write(tmp_path: Path, dsn: str) -> None:
    db = database.connect(dsn)
    try:
        with pytest.raises(
            Exception, match=r"(?i)read.?only|readonly|cannot execute|attempt to write"
        ):
            db.rows(
                f"DELETE FROM {TABLE}"
                if db.dialect != "clickhouse"
                else f"INSERT INTO {TABLE} VALUES ('x')"
            )
    finally:
        db.close()
    check = database.connect(dsn)
    try:
        assert len(check.rows(f"SELECT * FROM {TABLE}")) == len(EVENTS)
    finally:
        check.close()


def test_a_missing_table_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for fixture in (sqlite_db,):
        address = next(fixture(tmp_path))
        monkeypatch.setenv(database.ENV, address)
        rules = tmp_path / "rules.yml"
        rules.write_text(RULES)
        assert main(["hunt", str(rules), "-t", "nothing_here"]) == 2
        assert "nothing_here" in capsys.readouterr().err


def test_html_names_the_database_without_its_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    address = next(sqlite_db(tmp_path))
    out = tmp_path / "r.html"
    assert hunt(tmp_path, address, monkeypatch, "--html", str(out)) == 0
    assert "sqlite:" in out.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("dsn_text", "shown"),
    [
        (
            "postgresql://u:s3cret@db.example:5433/logs?sslmode=require&password=x",
            "postgresql://db.example:5433/logs",
        ),
        ("clickhouse://u:s3cret@ch.example/logs", "clickhouse://ch.example/logs"),
        ("sqlite:/tmp/a.db", "sqlite:/tmp/a.db"),
    ],
)
def test_describe_leaves_out_secrets(dsn_text: str, shown: str) -> None:
    assert database.describe(dsn_text) == shown


def test_scrub_removes_the_password() -> None:
    text = database.scrub("login failed with s3cr%40t and s3cr@t", "postgresql://u:s3cr%40t@h/d")
    assert "s3cr" not in text


def test_connection_failure_does_not_print_the_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    monkeypatch.setenv(database.ENV, "clickhouse://u:hunter2@127.0.0.1:1/x")
    assert main(["hunt", str(rules)]) == 2
    assert "hunter2" not in capsys.readouterr().err


def test_no_logs_and_no_database_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(database.ENV, raising=False)
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    assert main(["hunt", str(rules)]) == 2
    assert database.ENV in capsys.readouterr().err


def test_table_needs_a_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    assert main(["hunt", str(rules), "--logs", "x.jsonl", "-t", "a"]) == 2


def test_unknown_address_does_not_echo_it() -> None:
    with pytest.raises(ValueError) as caught:
        database.connect("mysql://u:hunter2@h/d")
    assert "hunter2" not in str(caught.value)


def test_a_bad_since_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "rules.yml"
    rules.write_text(RULES)
    assert main(["hunt", str(rules), "--logs", "x.jsonl", "--since", "soon"]) == 2
    assert "--since" in capsys.readouterr().err


HOSTILE = """title: quote
level: high
detection:
  s:
    User: "x'; DROP TABLE s2s_hunt_events; --"
  condition: s
---
title: field
level: high
detection:
  s:
    "a'); DROP TABLE s2s_hunt_events; --": y
  condition: s
"""


def test_rule_text_stays_data(
    tmp_path: Path, dsn: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(database.ENV, dsn)
    rules = tmp_path / "hostile.yml"
    rules.write_text(HOSTILE)
    main(["hunt", str(rules), "-t", TABLE, "--json-column", "event"])
    db = database.connect(dsn)
    try:
        assert len(db.rows(f"SELECT * FROM {TABLE}")) == len(EVENTS)
    finally:
        db.close()


def test_a_malformed_row_does_not_end_every_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    address = next(sqlite_db(tmp_path))
    path = address.removeprefix("sqlite:")
    con = sqlite3.connect(path)
    con.execute(f"INSERT INTO {TABLE} VALUES ('this is not json')")
    con.commit()
    con.close()
    assert hunt(tmp_path, address, monkeypatch) == 0
    out = capsys.readouterr()
    assert len(json.loads(out.out)) == 3
    assert "1 rows are not valid JSON and have no fields" in out.err


def test_a_missing_column_is_a_skip_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "plain.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE p (EventID INT)")
    con.execute("INSERT INTO p VALUES (1)")
    con.commit()
    con.close()
    rules = tmp_path / "r.yml"
    rules.write_text("title: t\ndetection: {s: {ParentImage|contains: Image}, condition: s}\n")
    monkeypatch.setenv(database.ENV, f"sqlite:{path}")
    assert main(["hunt", str(rules), "-t", "p", "--format", "json"]) == 2
    out = capsys.readouterr()
    assert json.loads(out.out) == [] and "no such column" in out.err


def test_since_without_a_readable_time_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    address = next(sqlite_db(tmp_path))
    args = ["--timestamp-field", "nothing", "--since", "2000-01-01"]
    assert hunt(tmp_path, address, monkeypatch, *args) == 2
    assert "readable time" in capsys.readouterr().err


def test_a_lost_connection_stops_the_hunt(tmp_path: Path) -> None:
    from sigma2sql.collection import Collection
    from sigma2sql.errors import ConnectionLost
    from sigma2sql.sql import Target

    class Gone:
        dialect = "postgres"

        def rows(self, query: str) -> list[dict[str, Any]]:
            if "x FROM" in query:
                return [{"n": 1}]
            raise ConnectionLost("gone")

        def close(self) -> None:
            pass

    rules = tmp_path / "r.yml"
    rules.write_text(RULES)
    col = Collection.load([rules])
    with pytest.raises(ConnectionLost):
        database.hunt_database(col, Gone(), Target(json_column="e"))  # type: ignore[arg-type]


def test_a_timeout_makes_a_fail_on_run_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sigma2sql import cli
    from sigma2sql.hunt import Report

    rules = tmp_path / "r.yml"
    rules.write_text(RULES)
    monkeypatch.setattr(
        cli.database, "connect", lambda *_: type("D", (), {"close": lambda s: None})()
    )
    monkeypatch.setattr(cli.database, "hunt_database", lambda *a: Report(1, [], 0, [], 0, [], 1))
    monkeypatch.setenv(database.ENV, "postgresql://h/d")
    assert main(["hunt", str(rules), "--fail-on", "low"]) == 2
    assert "incomplete" in capsys.readouterr().err


def test_a_bad_address_is_a_message_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "r.yml"
    rules.write_text(RULES)
    monkeypatch.setenv(database.ENV, "postgresql://u:se[cret@h/d")
    assert main(["hunt", str(rules)]) == 2
    assert "se[cret" not in capsys.readouterr().err


def test_redirects_are_not_followed() -> None:
    handler = database._Refuse()
    assert handler.redirect_request() is None


def test_a_missing_base_table_is_fine_when_rules_are_routed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    address = next(duckdb_db(tmp_path))
    profile = tmp_path / "p.yml"
    profile.write_text(f"logsources:\n  - match: {{product: windows}}\n    table: {TABLE}\n")
    rules = tmp_path / "r.yml"
    rules.write_text(
        "title: t\nlogsource: {product: windows}\ndetection: {s: {EventID: 4624}, condition: s}\n"
    )
    monkeypatch.setenv(database.ENV, address)
    args = ["-t", "absent", "--json-column", "event", "-p", str(profile), "--format", "json"]
    assert main(["hunt", str(rules), *args]) == 0
    assert json.loads(capsys.readouterr().out)[0]["count"] == 1


def test_clickhouse_errors_are_readable() -> None:
    assert database._clickhouse_error('{"exception": "Code: 60. bad"}') == "Code: 60. bad"
    assert database._clickhouse_error("Code: 60. plain") == "Code: 60. plain"
