"""The `expand` modifier: %name% placeholders filled in from --placeholders."""

from __future__ import annotations

from pathlib import Path

import pytest

from cases import rule_for
from sigma2sql import Target, UnsupportedRule
from sigma2sql.cli import main
from sigma2sql.profile import load_placeholders
from sigma2sql.runner import matching_events

USERS = [{"User": "alice"}, {"User": "bob"}, {"User": "mallory"}, {"Port": 22}]


def run(body: str, events: list[dict[str, object]], **values: tuple[object, ...]) -> list[int]:
    return matching_events(rule_for(body), events, Target(placeholders=values))


def test_placeholder_becomes_a_list_of_values() -> None:
    body = "sel: {User|expand: '%admins%'}\ncondition: sel"
    assert run(body, USERS, admins=("alice", "bob")) == [0, 1]


def test_placeholder_in_a_filter() -> None:
    body = "sel: {User|contains: a}\nok: {User|expand: '%admins%'}\ncondition: sel and not ok"
    assert run(body, USERS, admins=("alice",)) == [2]


def test_placeholder_inside_a_longer_value() -> None:
    events = [{"Path": "C:\\Users\\alice\\a.exe"}, {"Path": "C:\\Users\\eve\\a.exe"}]
    body = "sel: {Path|expand: 'C:\\Users\\%u%\\a.exe'}\ncondition: sel"
    assert run(body, events, u=("alice", "bob")) == [0]


def test_two_placeholders_give_every_combination() -> None:
    events = [{"A": "x-1"}, {"A": "y-2"}, {"A": "z-1"}]
    body = "sel: {A|expand: '%l%-%n%'}\ncondition: sel"
    assert run(body, events, l=("x", "y"), n=(1, 2)) == [0, 1]


def test_position_modifiers_apply_to_each_value() -> None:
    body = "sel: {User|contains|expand: '%part%'}\ncondition: sel"
    assert run(body, USERS, part=("lic", "mall")) == [0, 2]


def test_values_may_use_wildcards() -> None:
    body = "sel: {User|expand: '%admins%'}\ncondition: sel"
    assert run(body, USERS, admins=("a*",)) == [0]


def test_a_whole_value_placeholder_keeps_numbers() -> None:
    body = "sel: {Port|expand: '%ports%'}\ncondition: sel"
    assert run(body, USERS, ports=(22,)) == [3]


def test_regex_placeholder() -> None:
    body = "sel: {User|re|expand: '^%first%.*e$'}\ncondition: sel"
    assert run(body, USERS, first=("a", "b")) == [0]


def test_percent_signs_without_expand_are_literal() -> None:
    events = [{"Path": "%TEMP%\\a.exe"}]
    assert run("sel: {Path|startswith: '%TEMP%'}\ncondition: sel", events) == [0]


def test_lone_percent_sign_stays_literal() -> None:
    events = [{"Rate": "100%"}]
    assert run("sel: {Rate|expand: '100%'}\ncondition: sel", events) == [0]


def test_missing_placeholder_is_reported_by_name() -> None:
    with pytest.raises(UnsupportedRule, match="%admins%"):
        run("sel: {User|expand: '%admins%'}\ncondition: sel", USERS)


def test_load_placeholders(tmp_path: Path) -> None:
    path = tmp_path / "p.yml"
    path.write_text("admins: [alice, bob]\nport: 22\n")
    assert load_placeholders(path) == {"admins": ("alice", "bob"), "port": (22,)}


@pytest.mark.parametrize("text", ["- a\n", "x: []\n", "x: {a: 1}\n"])
def test_bad_placeholder_files(tmp_path: Path, text: str) -> None:
    path = tmp_path / "p.yml"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_placeholders(path)


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text("title: t\ndetection:\n  s: {U|expand: '%a%'}\n  condition: s\n")
    assert main(["convert", str(rule)]) == 1
    assert "%a%" in capsys.readouterr().err
    values = tmp_path / "p.yml"
    values.write_text("a: [x, y]\n")
    assert main(["convert", str(rule), "--placeholders", str(values)]) == 0
    out = capsys.readouterr().out
    assert "'x'" in out and "'y'" in out
