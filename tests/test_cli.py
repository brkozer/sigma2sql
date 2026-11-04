from __future__ import annotations

from pathlib import Path

import pytest

from sigma2sql.cli import main

EXAMPLES = Path(__file__).parent.parent / "examples"
EVENTS = EXAMPLES / "events.jsonl"


@pytest.mark.parametrize(
    ("rule", "matches"),
    [
        ("encoded_powershell.yml", 2),
        ("office_spawns_shell.yml", 1),
        ("rdp_from_outside.yml", 1),
    ],
)
def test_example_rules(rule: str, matches: int, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test", str(EXAMPLES / "rules" / rule), str(EVENTS), "--expect", "match"]) == 0
    out = capsys.readouterr()
    assert len(out.out.splitlines()) == matches
    assert f"{matches} of 8 events matched" in out.err


def test_expect_none_fails_when_something_matches() -> None:
    rule = EXAMPLES / "rules" / "office_spawns_shell.yml"
    assert main(["test", str(rule), str(EVENTS), "--expect", "none"]) == 1


def test_convert_directory(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(["convert", str(EXAMPLES / "rules"), "-d", "postgres", "--json-column", "data"]) == 0
    )
    out = capsys.readouterr()
    assert out.out.count("SELECT * FROM") == 3
    assert "converted 3/3 rules" in out.err


def test_convert_reports_unsupported_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "ok.yml").write_text("title: ok\ndetection:\n  s: {A: 1}\n  condition: s\n")
    (rules / "agg.yml").write_text(
        "title: agg\ndetection:\n  s: {A: 1}\n  condition: s | count() > 3\n"
    )
    mapping = tmp_path / "map.yml"
    mapping.write_text("A: col_a\n")
    assert main(["convert", str(rules), "-m", str(mapping)]) == 1
    out = capsys.readouterr()
    assert 'WHERE "col_a" = 1;' in out.out
    assert "agg.yml" in out.err and "converted 1/2 rules" in out.err


def test_bad_mapping(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mapping = tmp_path / "map.yml"
    mapping.write_text("- not a map\n")
    assert main(["convert", str(EXAMPLES / "rules"), "-m", str(mapping)]) == 2
    assert "mapping" in capsys.readouterr().err
