from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigma2sql.cli import main

duckdb = pytest.importorskip("duckdb")

EXAMPLES = Path(__file__).parent.parent / "examples"
RULES = str(EXAMPLES / "rules")
EVENTS = str(EXAMPLES / "events.jsonl")


def test_hunt_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hunt", RULES, "--logs", EVENTS]) == 0
    out = capsys.readouterr()
    lines = out.out.splitlines()
    assert lines[0].split() == ["LEVEL", "HITS", "RULE"]
    # high before medium, then by hit count
    assert [line.split()[:2] for line in lines[1:]] == [
        ["high", "2"],
        ["high", "1"],
        ["medium", "1"],
    ]
    assert "3 of 3 rules matched 8 events (0 rules skipped)" in out.err


def test_hunt_json_with_examples(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hunt", RULES, "--logs", EVENTS, "--format", "json", "-e", "1"]) == 0
    hits = json.loads(capsys.readouterr().out)
    rdp = next(h for h in hits if h["title"].startswith("Successful RDP"))
    assert rdp["count"] == 1 and rdp["examples"][0]["IpAddress"] == "203.0.113.45"


def test_hunt_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hunt", RULES, "--logs", EVENTS, "--fail-on", "high"]) == 1
    assert (
        main(
            [
                "hunt",
                str(EXAMPLES / "rules" / "rdp_from_outside.yml"),
                "--logs",
                EVENTS,
                "--fail-on",
                "high",
            ]
        )
        == 0
    )


def test_hunt_reads_parquet_and_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    con = duckdb.connect()
    con.execute(f"CREATE TABLE t AS SELECT * FROM read_json_auto('{EVENTS}')")
    con.execute(f"COPY (SELECT * FROM t WHERE EventID = 1) TO '{tmp_path / 'proc.parquet'}'")
    con.execute(f"COPY (SELECT * FROM t WHERE EventID <> 1) TO '{tmp_path / 'logon.csv'}'")
    assert (
        main(["hunt", RULES, "--logs", str(tmp_path / "*.parquet"), str(tmp_path / "*.csv")]) == 0
    )
    out = capsys.readouterr()
    assert "3 of 3 rules matched 8 events" in out.err


def test_hunt_rejects_unknown_log_type(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "events.txt"
    log.write_text("x")
    assert main(["hunt", RULES, "--logs", str(log)]) == 2
    assert "expected .json" in capsys.readouterr().err
