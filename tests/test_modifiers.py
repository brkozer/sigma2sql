"""Errors and generated SQL for regex flags, `neq` and timestamp parts."""

from __future__ import annotations

import pytest

from cases import rule_for
from sigma2sql import RuleError, Target, UnsupportedRule, to_where
from sigma2sql.expr import Not, Regex, StrMatch


def where(detection: str, dialect: str = "sqlite") -> str:
    return to_where(rule_for(detection).compile(), Target(dialect))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("mods", "postgres", "other"),
    [
        ("re", "a", "a"),
        ("re|i", "(?i)a", "(?i)a"),
        ("re|m", "(?n)a", "(?m)a"),
        ("re|s", "(?s)a", "(?s)a"),
        ("re|m|s", "(?w)a", "(?ms)a"),
        ("re|i|m|s", "(?iw)a", "(?ims)a"),
    ],
)
def test_regex_flags_per_dialect(mods: str, postgres: str, other: str) -> None:
    body = f"sel: {{A|{mods}: a}}\ncondition: sel"
    assert where(body, "postgres") == f"""\"A\" ~ '{postgres}'"""
    assert where(body, "sqlite") == f"""\"A\" REGEXP '{other}'"""
    assert where(body, "duckdb") == f"""regexp_matches(\"A\", '{other}')"""


def test_inline_flags_move_to_the_flag_field() -> None:
    expr = rule_for("sel: {A|re: '(?i)abc(?=d)'}\ncondition: sel").compile()
    assert expr == Regex("A", "abc(?=d)", "i")


def test_scoped_inline_groups_stay_in_the_pattern() -> None:
    expr = rule_for("sel: {A|re: '(?i:a)b'}\ncondition: sel").compile()
    assert expr == Regex("A", "(?i:a)b", "")


def test_neq_wraps_the_whole_item() -> None:
    expr = rule_for("sel: {A|neq: [x, y]}\ncondition: sel").compile()
    assert isinstance(expr, Not)


def test_neq_before_or_after_other_modifiers() -> None:
    a = rule_for("sel: {A|neq|contains: x}\ncondition: sel").compile()
    b = rule_for("sel: {A|contains|neq: x}\ncondition: sel").compile()
    assert a == b and isinstance(a, Not) and isinstance(a.item, StrMatch)


@pytest.mark.parametrize(
    ("detection", "error", "message"),
    [
        ("sel: {A|i: x}\ncondition: sel", RuleError, "regex flags"),
        ("sel: {A|m: x}\ncondition: sel", RuleError, "regex flags"),
        ("sel: {A|hour|minute: 1}\ncondition: sel", RuleError, "more than one"),
        ("sel: {A|hour: x}\ncondition: sel", RuleError, "number"),
        ("sel: {'|neq': x}\ncondition: sel", UnsupportedRule, "neq"),
    ],
)
def test_errors(detection: str, error: type[Exception], message: str) -> None:
    with pytest.raises(error, match=message):
        rule_for(detection).compile()
