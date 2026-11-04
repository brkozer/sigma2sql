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
