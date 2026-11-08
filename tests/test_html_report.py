from __future__ import annotations

import json
import re
from dataclasses import replace
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
    assert '<label for="f-high" class="high"><b>3</b>High</label>' in text
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


@pytest.mark.parametrize("depth", [1500, 100000])
def test_deeply_nested_event_keeps_the_report(depth: int) -> None:
    event = '{"A": ' + "[" * depth + "1" + "]" * depth + "}"
    report = Report(1, [Hit(rule(), 1, [event])], 1, [])  # type: ignore[arg-type]
    assert "<pre>" in html_report.render(report, [], ["x"], "1", WHEN)


@pytest.mark.parametrize(
    ("event", "kept"),
    [
        ('{"C": "mimikatz", "C": "notepad"}', "mimikatz"),
        ('{"n": 123456789012345678901234567890.123456789}', "123456789012345678901234567890.123"),
        ('{"f": 1e999}', "1e999"),
    ],
)
def test_an_event_is_never_changed_by_printing_it(event: str, kept: str) -> None:
    report = Report(1, [Hit(rule(), 1, [event])], 1, [])  # type: ignore[arg-type]
    assert kept in html_report.render(report, [], ["x"], "1", WHEN)


@pytest.mark.parametrize("char", ["\u061c", "\U000e0041", "\u3164", "\x1b", "\ufe0f"])
def test_more_invisible_characters_are_shown(char: str) -> None:
    item = replace(rule(), title=f"a{char}b")  # type: ignore[type-var]
    text = html_report.render(Report(1, [Hit(item, 1)], 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert f"a{char}b" not in text and f"\\u{ord(char):04x}" in text


def test_ordinary_letters_stay() -> None:
    assert "şifre Système" in html_report._text("şifre Système")


def test_page_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(html_report, "MAX_EXAMPLES_TOTAL", 1000)
    event = json.dumps({"A": "x" * 900})
    hits = [Hit(rule(), 1, [event]) for _ in range(5)]
    text = html_report.render(Report(1, hits, 5, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert text.count("More examples left out") == 4


@pytest.mark.parametrize(
    "fields",
    [
        {"description": ["a"], "tags": "x", "falsepositives": [None, 5, {"a": 1}]},
        {"references": {"a": 1}, "description": 12},
    ],
)
def test_metadata_of_any_shape_does_not_stop_a_rule(fields: dict[str, object]) -> None:
    assert rule(**fields) == rule()


def test_scalar_tags_are_kept() -> None:
    assert rule(tags="attack.t1059").tags == ("attack.t1059",)  # type: ignore[attr-defined]


def test_no_rule_could_run_is_not_reported_as_no_match(tmp_path: Path) -> None:
    bad = tmp_path / "a.yml"
    bad.write_text("title: [unclosed")
    out = tmp_path / "r.html"
    assert main(["hunt", str(bad), "--logs", EVENTS, "--html", str(out)]) == 2
    text = out.read_text(encoding="utf-8")
    assert "No rule could run" in text and "1 rule did not run" in text


def test_a_bad_sarif_path_does_not_lose_the_report(tmp_path: Path) -> None:
    out = tmp_path / "r.html"
    sarif = tmp_path / "no" / "x.sarif"
    args = ["--logs", EVENTS, "--html", str(out), "--sarif", str(sarif)]
    assert main(["hunt", RULES, *args]) == 2
    assert out.exists()


def test_upper_case_scheme_is_a_link() -> None:
    item = rule(references=["HTTPS://EXAMPLE.ORG/A"])
    text = html_report.render(Report(1, [Hit(item, 1)], 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert 'href="HTTPS://EXAMPLE.ORG/A"' in text


def test_a_big_event_is_not_indented_before_it_is_cut() -> None:
    event = json.dumps({"A": list(range(100000))})
    text = html_report._pretty(event)
    assert text.endswith("cut at 20000 characters") and "\n  " not in text


def test_one_big_match_does_not_use_up_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(html_report, "MAX_EXAMPLES_TOTAL", 1000)
    big = Hit(rule(), 2, [json.dumps({"A": "x" * 5000}), json.dumps({"A": "y"})])
    small = Hit(rule(), 1, [json.dumps({"B": "small"})])
    text = html_report.render(Report(1, [big, small], 2, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert "small" in text


def test_negative_zero_stays_as_written() -> None:
    assert '"z":-0' in html_report._pretty('{"z":-0}').replace(" ", "")


def test_no_rule_applies_is_not_called_a_failure() -> None:
    report = Report(1, [], 0, [], 3)
    assert "No rule applies" in html_report.render(report, [], ["x"], "1", WHEN)


def test_deep_event_in_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules = tmp_path / "r.yml"
    rules.write_text("title: t\ndetection: {s: {A: x}, condition: s}\n")
    logs = tmp_path / "e.jsonl"
    logs.write_text('{"A": "x", "D": ' + "[" * 1500 + "1" + "]" * 1500 + "}\n")
    assert main(["hunt", str(rules), "--logs", str(logs), "--format", "json", "-e", "1"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["count"] == 1


def test_a_huge_number_skips_only_that_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "good.yml").write_text("title: g\ndetection: {s: {EventID: 4624}, condition: s}\n")
    (tmp_path / "bad.yml").write_text(
        "title: b\ncorrelation: {type: event_count, rules: [x], condition: {gte: "
        + "9" * 400
        + "}}\n"
    )
    assert main(["hunt", str(tmp_path), "--logs", EVENTS]) == 0
    assert "bad.yml" in capsys.readouterr().err


def test_only_levels_that_matched_can_be_picked() -> None:
    hits = [Hit(rule(level="critical"), 1), Hit(rule(), 1)]
    report = Report(1, hits, 2, [])  # type: ignore[arg-type]
    text = html_report.render(report, [], ["x"], "1", WHEN)
    assert re.findall(r'type="radio" name="level" id="f-(\w+)"', text) == [
        "all",
        "critical",
        "unset",
    ]


def test_every_level_can_be_filtered_by_css() -> None:
    for level in [*html_report.LEVELS, "unset"]:
        assert f"#f-{level}:checked ~ .list .rule:not(.{level})" in html_report._STYLE


def test_techniques_come_from_attack_tags_only() -> None:
    tags = ["attack.execution", "attack.t1059.001", "cve.2021.1", "attack.T1003", "attack.t1"]
    assert html_report._techniques(tags) == "T1059.001 T1003"


def test_rows_start_closed(tmp_path: Path) -> None:
    assert "<details open" not in page(tmp_path)


def test_a_hostile_title_is_escaped_in_the_row() -> None:
    text = html_report.render(Report(1, [Hit(rule(), 1)], 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert '<span class="name">&lt;img src=x' in text


def test_tactics_are_counted_in_attack_order() -> None:
    hits = [
        Hit(rule(tags=["attack.impact", "attack.execution"]), 1),
        Hit(rule(tags=["attack.execution", "attack.t1059"]), 1),
    ]
    text = html_report.render(Report(1, hits, 2, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert text.index('for="t-execution"') < text.index('for="t-impact"')
    assert re.search(r'for="t-execution" style="--x:75%"><b>2</b>', text)
    assert '<span class="none"><b>0</b>Discovery</span>' in text
    assert "tc-impact" in text


def test_a_hostile_tag_never_becomes_a_class() -> None:
    hits = [Hit(rule(tags=['attack.x" onclick="a', "attack.execution"]), 1)]
    text = html_report.render(Report(1, hits, 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert 'class="rule unset tc-execution"' in text


def test_every_tactic_can_be_filtered_by_css() -> None:
    for tactic in html_report.TACTICS:
        assert f"#t-{tactic}:checked ~ .list .rule:not(.tc-{tactic})" in html_report._STYLE


def test_no_tactic_strip_without_tactics() -> None:
    text = html_report.render(Report(1, [Hit(rule(), 1)], 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert 'class="strip"' not in text


def test_the_retired_tactic_shows_only_when_used() -> None:
    used = Hit(rule(tags=["attack.defense-evasion"]), 1)
    other = Hit(rule(tags=["attack.stealth", "attack.defense-impairment"]), 1)
    with_it = html_report.render(Report(1, [used], 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    without = html_report.render(Report(1, [other], 1, []), [], ["x"], "1", WHEN)  # type: ignore[arg-type]
    assert "Defense evasion" in with_it and "Defense evasion" not in without
    assert 'for="t-stealth"' in without and 'for="t-defense-impairment"' in without
