from __future__ import annotations

from pathlib import Path

import pytest

from sigma2sql.cli import main

EXAMPLES = Path(__file__).parent.parent / "examples" / "rules"

RULE = """title: cmd
logsource: {product: windows, category: process_creation}
detection:
  s: {Image|endswith: '\\\\cmd.exe'}
  condition: s
"""


BAD_REGEX = """title: bad regex
detection:
  s: {A|re: '('}
  condition: s
"""


def test_invalid_regex_fails_only_that_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a.yml").write_text(BAD_REGEX)
    (tmp_path / "a.match.jsonl").write_text('{"A": "x"}\n')
    (tmp_path / "b.yml").write_text(RULE)
    (tmp_path / "b.nomatch.jsonl").write_text('{"Image": "x"}\n')
    sarif = tmp_path / "out.sarif"
    assert main(["check", str(tmp_path), "--sarif", str(sarif)]) == 1
    out = capsys.readouterr()
    assert "invalid regex" in out.out and "ok   " in out.out
    assert sarif.exists()


def test_invalid_regex_no_event_reaches_is_still_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a.yml").write_text(BAD_REGEX)
    (tmp_path / "a.nomatch.jsonl").write_text('{"Other": 1}\n')
    assert main(["check", str(tmp_path)]) == 1
    assert "invalid regex" in capsys.readouterr().out


def test_rules_without_tests_are_still_loaded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "broken.yml").write_text("title: [unclosed")
    (tmp_path / "latin.yml").write_bytes("title: caf\xe9\n".encode("latin-1"))
    (tmp_path / "regex.yml").write_text(BAD_REGEX)
    (tmp_path / "fine.yml").write_text(RULE)
    assert main(["check", str(tmp_path)]) == 1
    assert "0 passed, 3 failed, 1 without tests" in capsys.readouterr().err


def test_an_empty_folder_next_to_a_good_one_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "good"
    good.mkdir()
    (good / "a.yml").write_text(RULE)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["check", str(good), str(empty)]) == 2


def test_test_with_no_rule_is_an_error(tmp_path: Path) -> None:
    events = tmp_path / "e.jsonl"
    events.write_text("{}\n")
    assert main(["test", str(tmp_path), str(events), "--expect", "match"]) == 2


def test_upper_case_suffixes_are_rule_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a.YML").write_text(RULE)
    assert main(["check", str(tmp_path)]) == 0
    assert "1 without tests" in capsys.readouterr().err


def test_line_separator_inside_a_string(tmp_path: Path) -> None:
    rule = tmp_path / "a.yml"
    rule.write_text("title: k\ndetection:\n  s: {A: 1}\n  condition: s\n")
    events = tmp_path / "e.jsonl"
    events.write_text('{"A": 1, "M": "x\u2028y"}\n', encoding="utf-8")
    assert main(["test", str(rule), str(events), "--expect", "match"]) == 0


def test_json_nested_too_deeply_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "cmd.yml").write_text(RULE)
    (tmp_path / "cmd.match.jsonl").write_text("[" * 200000 + "\n")
    assert main(["check", str(tmp_path)]) == 1
    assert "nested too deeply" in capsys.readouterr().out


def test_a_lone_surrogate_in_an_event(tmp_path: Path) -> None:
    rule = tmp_path / "a.yml"
    rule.write_text("title: k\ndetection:\n  s: {M|re: 'x.y'}\n  condition: s\n")
    events = tmp_path / "e.jsonl"
    events.write_text('{"M": "x\\ud83dy"}\n')
    assert main(["test", str(rule), str(events), "--expect", "match"]) == 0


def test_invalid_regex_in_test_is_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule = tmp_path / "a.yml"
    rule.write_text(BAD_REGEX)
    events = tmp_path / "e.jsonl"
    events.write_text('{"A": "x"}\n')
    assert main(["test", str(rule), str(events)]) == 2


@pytest.mark.parametrize("command", ["check", "hunt"])
def test_a_rule_path_that_leads_nowhere_is_an_error(
    tmp_path: Path, command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    logs = ["--logs", "x.jsonl"] if command == "hunt" else []
    assert main([command, str(tmp_path / "missing"), *logs]) == 2
    assert "no such file" in capsys.readouterr().err
    assert main([command, str(tmp_path), *logs]) == 2
    assert "no .yml or .yaml files" in capsys.readouterr().err


def test_a_file_that_is_not_utf8_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a.yml").write_bytes(RULE.encode("utf-16"))
    (tmp_path / "a.match.jsonl").write_text("{}\n")
    assert main(["check", str(tmp_path)]) == 1
    assert "not a UTF-8 file" in capsys.readouterr().out


def test_broken_test_file_keeps_the_other_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "cmd.yml").write_text(RULE)
    (tmp_path / "cmd.match.jsonl").write_text('{"Image": "x"}\n')
    (tmp_path / "cmd.nomatch.jsonl").write_text('{"Image": "x"}\n\nnot json\n')
    assert main(["check", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "missed" in out and "line 3" in out


def test_non_ascii_keyword_matches(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule = tmp_path / "a.yml"
    rule.write_text(
        "title: k\ndetection:\n  words: ['Système']\n  condition: words\n", encoding="utf-8"
    )
    events = tmp_path / "e.jsonl"
    events.write_text('{"A": "AUTORITE NT\\\\Système"}\n', encoding="utf-8")
    assert main(["test", str(rule), str(events), "--expect", "match"]) == 0


def test_unwritable_sarif_is_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "cmd.yml").write_text(RULE)
    out = tmp_path / "no" / "such" / "dir.sarif"
    assert main(["check", str(tmp_path), "--sarif", str(out)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_examples_pass(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(EXAMPLES), "--require-tests"]) == 0
    out = capsys.readouterr()
    assert out.out.count("ok   ") == 4
    assert "4 passed, 0 failed, 0 without tests" in out.err


def test_reports_missed_and_unexpected_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "cmd.yml").write_text(RULE)
    (tmp_path / "cmd.match.jsonl").write_text(
        '{"Image": "C:\\\\Windows\\\\cmd.exe"}\n{"Image": "C:\\\\Windows\\\\notepad.exe"}\n'
    )
    (tmp_path / "cmd.nomatch.jsonl").write_text('{"Image": "D:\\\\tools\\\\cmd.exe"}\n')
    assert main(["check", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "cmd: missed cmd.match.jsonl event(s) 2" in out
    assert "cmd: matched cmd.nomatch.jsonl event(s) 1" in out


def test_untested_rules(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "cmd.yml").write_text(RULE)
    assert main(["check", str(tmp_path)]) == 0
    assert "0 passed, 0 failed, 1 without tests" in capsys.readouterr().err
    assert main(["check", str(tmp_path), "--require-tests"]) == 1


def test_profile_applies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "cmd.yml").write_text(RULE)
    # With the sysmon profile, only EventID 1 counts as process creation.
    (tmp_path / "cmd.nomatch.jsonl").write_text(
        '{"EventID": 3, "Image": "C:\\\\Windows\\\\cmd.exe"}\n'
    )
    assert main(["check", str(tmp_path)]) == 1
    assert main(["check", str(tmp_path), "--profile", "sysmon"]) == 0
