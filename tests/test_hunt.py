from __future__ import annotations

import json
import sys
import types
from collections.abc import Iterator
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
        ["high", "1"],
        ["medium", "1"],
    ]
    assert "4 of 4 rules matched 12 events (0 rules skipped)" in out.err


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
    assert "4 of 4 rules matched 12 events" in out.err


def test_hunt_rejects_unknown_log_type(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "events.txt"
    log.write_text("x")
    assert main(["hunt", RULES, "--logs", str(log)]) == 2
    assert "expected .json" in capsys.readouterr().err


EVTX_EVENT = {
    "Event": {
        "System": {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1,
            "TimeCreated": {"#attributes": {"SystemTime": "2026-11-01T10:00:00Z"}},
        },
        "EventData": {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        },
    }
}


@pytest.fixture
def fake_evtx(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """The evtx package, reading pretty-printed records as the real one does."""
    opened: list[str] = []

    class PyEvtxParser:
        def __init__(self, path: str) -> None:
            opened.append(path)

        def records_json(self) -> Iterator[dict[str, object]]:
            yield {"event_record_id": 1, "data": json.dumps(EVTX_EVENT, indent=2)}

    module = types.ModuleType("evtx")
    module.PyEvtxParser = PyEvtxParser  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "evtx", module)
    yield opened


def test_hunt_reads_evtx_with_the_evtx_profile(
    tmp_path: Path, fake_evtx: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("a.evtx", "b.EVTX"):
        (tmp_path / name).write_bytes(b"")
    rule = str(EXAMPLES / "rules" / "office_spawns_shell.yml")
    assert main(["hunt", rule, "--logs", str(tmp_path / "a.evtx")]) == 0
    assert "1 of 1 rules matched 1 events" in capsys.readouterr().err
    assert fake_evtx == [str(tmp_path / "a.evtx")]


def test_hunt_expands_evtx_globs(
    tmp_path: Path, fake_evtx: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("a.evtx", "b.evtx"):
        (tmp_path / name).write_bytes(b"")
    assert main(["hunt", RULES, "--logs", str(tmp_path / "*.evtx")]) == 0
    assert "2 events" in capsys.readouterr().err
    assert len(fake_evtx) == 2


def test_hunt_reports_a_missing_evtx_file(
    tmp_path: Path, fake_evtx: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["hunt", RULES, "--logs", str(tmp_path / "none.evtx")]) == 2
    assert "no such file" in capsys.readouterr().err


def parser_with(monkeypatch: pytest.MonkeyPatch, *steps: object) -> None:
    """A fake evtx parser: each step is a record to return or an error to raise."""

    class Records:
        def __init__(self) -> None:
            self.steps = list(steps)

        def __iter__(self) -> Records:
            return self

        def __next__(self) -> object:
            if not self.steps:
                raise StopIteration
            step = self.steps.pop(0)
            if isinstance(step, Exception):
                raise step
            return step

    class PyEvtxParser:
        def __init__(self, path: str) -> None:
            if "bad" in Path(path).name:
                raise OSError("bad file header")

        def records_json(self) -> Records:
            return Records()

    module = types.ModuleType("evtx")
    module.PyEvtxParser = PyEvtxParser  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "evtx", module)


RECORD = {"data": json.dumps(EVTX_EVENT)}
WHOLE_FILE = b"x" * (4096 + 65536)


def test_damaged_chunk_keeps_the_other_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parser_with(monkeypatch, RECORD, RuntimeError("bad chunk 1"), RECORD)
    log = tmp_path / "a.evtx"
    log.write_bytes(WHOLE_FILE)
    assert main(["hunt", RULES, "--logs", str(log)]) == 0
    err = capsys.readouterr().err
    assert "warning:" in err and "bad chunk 1" in err
    assert "matched 2 events" in err


def test_truncated_file_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parser_with(monkeypatch, RECORD)
    log = tmp_path / "a.evtx"
    log.write_bytes(WHOLE_FILE[:-3000])
    assert main(["hunt", RULES, "--logs", str(log)]) == 0
    assert "file is truncated" in capsys.readouterr().err


def test_one_unreadable_file_does_not_stop_the_hunt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parser_with(monkeypatch, RECORD)
    (tmp_path / "bad.evtx").write_bytes(WHOLE_FILE)
    (tmp_path / "good.evtx").write_bytes(WHOLE_FILE)
    assert main(["hunt", RULES, "--logs", str(tmp_path / "*.evtx")]) == 0
    err = capsys.readouterr().err
    assert "bad file header" in err and "matched 1 events" in err


def test_a_lone_unreadable_file_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parser_with(monkeypatch)
    log = tmp_path / "bad.evtx"
    log.write_bytes(WHOLE_FILE)
    assert main(["hunt", RULES, "--logs", str(log)]) == 2
    assert "no event could be read" in capsys.readouterr().err


def test_nothing_readable_is_an_error_not_a_clean_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parser_with(monkeypatch)
    log = tmp_path / "a.evtx"
    log.write_bytes(WHOLE_FILE[:-3000])
    assert main(["hunt", RULES, "--logs", str(log)]) == 2
    assert "no event could be read" in capsys.readouterr().err


def test_an_empty_log_is_fine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parser_with(monkeypatch)
    log = tmp_path / "a.evtx"
    log.write_bytes(b"x" * 4096)
    assert main(["hunt", RULES, "--logs", str(log)]) == 0
    assert "warning" not in capsys.readouterr().err


def test_a_failing_rule_does_not_end_the_hunt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("title: Bad regex\ndetection:\n  s: {Image|re: '('}\n  condition: s\n")
    assert main(["hunt", RULES, str(bad), "--logs", EVENTS]) == 0
    out = capsys.readouterr()
    assert "Office application" in out.out
    assert "skip" in out.err and "bad.yml" in out.err
    assert "1 rules skipped" in out.err
