from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sigma2sql.cli import main
from sigma2sql.sarif import Finding, report

EXAMPLES = Path(__file__).parent.parent / "examples"
RULES = str(EXAMPLES / "rules")
EVENTS = str(EXAMPLES / "events.jsonl")


def results(doc: dict[str, Any]) -> list[dict[str, Any]]:
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "sigma2sql"
    return list(run["results"])


@pytest.mark.parametrize(
    ("level", "sarif", "severity"),
    [
        ("critical", "error", "9.5"),
        ("high", "error", "8.0"),
        ("medium", "warning", "5.5"),
        ("low", "note", "3.0"),
        ("informational", "note", "1.0"),
        (None, "warning", "5.5"),
    ],
)
def test_levels(level: str | None, sarif: str, severity: str) -> None:
    doc = report([Finding("a", "A", level, "m", None)], "1")
    assert results(doc)[0]["level"] == sarif
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == severity


def test_repeated_rules_are_listed_once() -> None:
    doc = report(
        [Finding("a", "A", "high", "1", None), Finding("b", "B", "high", "2", None)]
        + [Finding("a", "A", "high", "3", None)],
        "1",
    )
    assert [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]] == ["a", "b"]
    assert [r["ruleIndex"] for r in results(doc)] == [0, 1, 0]


def test_paths_are_relative_uris(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    finding = Finding("a", "A", "high", "m", tmp_path / "rules" / "a b.yml")
    location = results(report([finding], "1"))[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "rules/a b.yml"


def test_hunt_writes_sarif_next_to_the_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("duckdb")
    out = tmp_path / "hunt.sarif"
    assert main(["hunt", RULES, "--logs", EVENTS, "--sarif", str(out)]) == 0
    assert "LEVEL" in capsys.readouterr().out
    found = results(json.loads(out.read_text()))
    assert len(found) == 4
    assert {r["level"] for r in found} == {"error", "warning"}
    assert any("2 matches" in r["message"]["text"] for r in found)


def test_check_writes_failures(tmp_path: Path) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text("title: t\ndetection:\n  s: {A: 1}\n  condition: s\n")
    (tmp_path / "r.match.jsonl").write_text('{"A": 2}\n')
    out = tmp_path / "check.sarif"
    assert main(["check", str(rule), "--sarif", str(out)]) == 1
    (found,) = results(json.loads(out.read_text()))
    assert found["ruleId"] == "rule-test" and "missed" in found["message"]["text"]


def test_passing_check_writes_an_empty_report(tmp_path: Path) -> None:
    out = tmp_path / "check.sarif"
    assert main(["check", RULES, "--sarif", str(out)]) == 0
    assert results(json.loads(out.read_text())) == []
