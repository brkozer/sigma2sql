from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sigma2sql import coverage
from sigma2sql.cli import main
from sigma2sql.database import ENV
from sigma2sql.expr import And, Exists, FieldRef, Not, NullMatch, Or, SigmaString, StrMatch

pytest.importorskip("duckdb")


def match(name: str | None) -> StrMatch:
    return StrMatch(name, SigmaString(("x",)))


def has(name: str | None) -> bool:
    return name == "A"


@pytest.mark.parametrize(
    ("expr", "can_match"),
    [
        (match("A"), True),
        (match("B"), False),
        (And((match("A"), match("B"))), False),
        (Or((match("A"), match("B"))), True),
        (Not(match("B")), True),
        (Not(Not(match("B"))), False),
        (And((match("A"), Not(match("B")))), True),
        (NullMatch("B"), True),
        (Not(NullMatch("B")), False),
        (Exists("B", True), False),
        (Exists("B", False), True),
        (FieldRef("A", "B"), False),
        (FieldRef("A", "A"), True),
    ],
)
def test_possible(expr: object, can_match: bool) -> None:
    assert coverage.possible(expr, has)[0] is can_match  # type: ignore[arg-type]


def test_nulls_are_not_fields_and_nesting_is_followed() -> None:
    doc = {"a": {"b": 1, "c": None}, "d": None}
    assert set(coverage.field_names(doc, True)) == {"a", "a.b"}
    assert set(coverage.field_names(doc, False)) == {"a"}


RULES = """title: ready
detection: {s: {A: 1, B: 2}, condition: s}
---
title: partial
detection: {s: {A: 1}, t: {Gone: 2}, condition: s or t}
---
title: blind
detection: {s: {Gone: 2, Lost: 3}, condition: s}
---
title: negated
detection: {s: {A: 1}, t: {Gone: 2}, condition: s and not t}
---
title: keyword
detection: {k: [hello], condition: k}
---
title: base
name: base
detection: {s: {A: 1}, condition: s}
---
title: seq
correlation: {type: event_count, rules: [base], timespan: 5m, condition: {gte: 1}}
"""


def run(tmp_path: Path, capsys: pytest.CaptureFixture[str], *args: str) -> dict[str, object]:
    rules = tmp_path / "r.yml"
    rules.write_text(RULES)
    assert main(["coverage", str(rules), "--format", "json", *args]) == 0
    result: dict[str, object] = json.loads(capsys.readouterr().out)
    return result


def statuses(result: dict[str, object]) -> dict[str, str]:
    return {r["title"]: r["status"] for r in result["rules"]}  # type: ignore[attr-defined]


def test_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    logs = tmp_path / "e.jsonl"
    logs.write_text('{"A": 1, "B": 2, "timestamp": "2026-11-01T00:00:00Z"}\n')
    result = run(tmp_path, capsys, "--logs", str(logs))
    assert statuses(result) == {
        "ready": "ready",
        "partial": "partial",
        "blind": "blind",
        "negated": "partial",
        "keyword": "ready",
        "seq": "ready",
    }
    fields = {f["field"]: f for f in result["missing_fields"]}  # type: ignore[attr-defined]
    assert fields["Gone"] == {"field": "Gone", "blinds": 1, "weakens": 2}


def test_a_timespan_needs_a_time_field(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    logs = tmp_path / "e.jsonl"
    logs.write_text('{"A": 1, "B": 2}\n')
    assert statuses(run(tmp_path, capsys, "--logs", str(logs)))["seq"] == "blind"


def test_a_profile_maps_fields(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    logs = tmp_path / "e.jsonl"
    logs.write_text('{"x": {"gone": 1}, "A": 1, "B": 2}\n')
    profile = tmp_path / "p.yml"
    profile.write_text("nested: true\nfields:\n  Gone: x.gone\n  Lost: x.gone\n")
    result = run(tmp_path, capsys, "--logs", str(logs), "-p", str(profile))
    assert statuses(result)["blind"] == "ready"


def test_a_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "l.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE logs (A INT, B INT)")
    con.execute("INSERT INTO logs VALUES (1, 2)")
    con.commit()
    con.close()
    monkeypatch.setenv(ENV, f"sqlite:{path}")
    result = run(tmp_path, capsys, "-t", "logs")
    assert statuses(result)["ready"] == "ready"
    assert statuses(result)["keyword"] == "blind"


def test_table_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    logs = tmp_path / "e.jsonl"
    logs.write_text('{"A": 1, "B": 2}\n')
    rules = tmp_path / "r.yml"
    rules.write_text(RULES)
    assert main(["coverage", str(rules), "--logs", str(logs)]) == 0
    out = capsys.readouterr().out
    assert "rules can never match" in out and "MISSING FIELD" in out and "Gone" in out


def test_no_events_is_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    logs = tmp_path / "e.jsonl"
    logs.write_text("")
    rules = tmp_path / "r.yml"
    rules.write_text(RULES)
    assert main(["coverage", str(rules), "--logs", str(logs)]) == 2
