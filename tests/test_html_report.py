from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sigma2sql import html_report
from sigma2sql.cli import main
from sigma2sql.hunt import Hit, Report
from sigma2sql.rule import load_documents

pytest.importorskip("duckdb")

EXAMPLES = Path(__file__).parent.parent / "examples"
RULES = str(EXAMPLES / "rules")
EVENTS = str(EXAMPLES / "events.jsonl")
ATTACK = "<img src=x onerror=alert(1)></pre><script>alert(2)</script>\"'"
WHEN = datetime(2026, 11, 9, tzinfo=UTC)


def page(tmp_path: Path, *extra: str) -> str:
    out = tmp_path / "report.html"
    assert main(["hunt", RULES, "--logs", EVENTS, "--html", str(out), *extra]) == 0
    return out.read_text(encoding="utf-8")


def rule(**fields: object) -> object:
    doc = {"title": ATTACK, "detection": {"s": {"A": 1}, "condition": "s"}, **fields}
    return load_documents(json.dumps(doc))[0]


def test_report_lists_the_matches(tmp_path: Path) -> None:
    text = page(tmp_path)
    assert "Office application starting a shell" in text
    assert "Brute force against one account" in text
    assert '<a class="high" href="#level-high">high 3</a>' in text
    assert text.count("<details") == 4


def test_examples_reach_the_report_but_not_the_terminal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = page(tmp_path)
    assert "203.0.113.45" in text
    assert "203.0.113.45" not in capsys.readouterr().out


def test_examples_option_still_applies_to_the_terminal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    page(tmp_path, "-e", "1")
    assert "203.0.113.45" in capsys.readouterr().out


def test_page_cannot_run_or_load_anything(tmp_path: Path) -> None:
    text = page(tmp_path)
    assert "default-src 'none'" in text
    assert "<script" not in text
    assert not re.search(r"(src|href)=\"(https?:)?//", text)


def test_log_and_rule_text_is_escaped() -> None:
    item = rule(description=ATTACK, tags=[ATTACK], falsepositives=[ATTACK], references=[ATTACK])
    event = json.dumps({"CommandLine": ATTACK})
    report = Report(1, [Hit(item, 1, [event])], 1, [(item, ATTACK)], 0, [ATTACK])  # type: ignore[arg-type]
    text = html_report.render(report, [(Path(ATTACK), ATTACK)], [ATTACK], ATTACK, WHEN)
    assert "<script>alert" not in text
    assert "<img src=x" not in text
    assert "&lt;script&gt;" in text


def test_only_web_references_become_links() -> None:
    item = rule(references=["javascript:alert(1)", "https://example.com/a?b=1&c=2"])
    report = Report(1, [Hit(item, 1)], 1, [])  # type: ignore[arg-type]
    text = html_report.render(report, [], ["x"], "1", WHEN)
    assert 'href="javascript' not in text
    assert 'href="https://example.com/a?b=1&amp;c=2"' in text


def test_invisible_characters_are_shown() -> None:
    event = json.dumps({"A": "evil\u202egnp.exe"}, ensure_ascii=False)
    report = Report(1, [Hit(rule(), 1, [event])], 1, [])  # type: ignore[arg-type]
    text = html_report.render(report, [], ["x"], "1", WHEN)
    assert "\u202e" not in text and "\\u202e" in text


def test_long_examples_are_cut() -> None:
    event = json.dumps({"A": "x" * 100000})
    report = Report(1, [Hit(rule(), 1, [event])], 1, [])  # type: ignore[arg-type]
    assert "cut at 20000 characters" in html_report.render(report, [], ["x"], "1", WHEN)


def test_no_match_says_so(tmp_path: Path) -> None:
    logs = tmp_path / "e.jsonl"
    logs.write_text('{"Nothing": 1}\n')
    out = tmp_path / "r.html"
    assert main(["hunt", RULES, "--logs", str(logs), "--html", str(out)]) == 0
    assert "No rule matched" in out.read_text(encoding="utf-8")


def test_unwritable_file_is_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "no" / "such" / "r.html"
    assert main(["hunt", RULES, "--logs", EVENTS, "--html", str(out)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_report_is_written_when_fail_on_trips(tmp_path: Path) -> None:
    out = tmp_path / "r.html"
    assert main(["hunt", RULES, "--logs", EVENTS, "--html", str(out), "--fail-on", "high"]) == 1
    assert out.exists()


def test_a_long_list_of_logs_is_folded() -> None:
    report = Report(1, [], 1, [])
    text = html_report.render(report, [], [f"log{i}.evtx" for i in range(50)], "1", WHEN)
    assert "50 log paths" in text
    assert "log49.evtx" in text
    assert "log paths" not in html_report.render(report, [], ["a.evtx"], "1", WHEN)


def test_only_the_first_serious_matches_start_open() -> None:
    hits = [Hit(rule(level="high"), 1) for _ in range(30)]
    report = Report(1, hits, 30, [])  # type: ignore[arg-type]
    text = html_report.render(report, [], ["x"], "1", WHEN)
    assert text.count("<details open>") == html_report.MAX_OPEN
