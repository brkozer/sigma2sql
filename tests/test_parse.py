from __future__ import annotations

import pytest

from cases import rule_for
from sigma2sql import RuleError, Target, UnsupportedRule, load_rule, to_query, to_where
from sigma2sql.expr import SigmaString, StrMatch, Wildcard


def test_sigma_string_escapes() -> None:
    s = SigmaString.parse("a\\*b*c?\\\\d\\e")
    assert s.parts == ("a*b", Wildcard.MANY, "c", Wildcard.ONE, "\\d\\e")


def test_column_mode_quotes_identifiers() -> None:
    rule = rule_for('sel: {"we\\"ird": 1}\ncondition: sel')
    assert to_query(rule, Target(table="logs.proc")) == (
        'SELECT * FROM "logs"."proc" WHERE "we""ird" = 1'
    )


def test_postgres_rendering() -> None:
    expr = rule_for("sel: {Image|endswith: '\\cmd.exe', User: Admin}\ncondition: sel").compile()
    assert to_where(expr, Target("postgres")) == (
        "(\"Image\" ILIKE '%\\\\cmd.exe' ESCAPE '\\' AND LOWER(\"User\") = 'admin')"
    )


def test_unused_search_is_not_compiled() -> None:
    rule = rule_for("sel: {A: 1}\nunused: {B|base64offset: x}\ncondition: sel")
    assert to_where(rule.compile(), Target()) == '"A" = 1'


def test_keywords_need_somewhere_to_search() -> None:
    with pytest.raises(UnsupportedRule, match="keyword"):
        to_where(rule_for("keywords: [evil]\ncondition: keywords").compile(), Target())


@pytest.mark.parametrize(
    ("detection", "error", "message"),
    [
        ("sel: {A: 1}\ncondition: sel | max(A) > 5", UnsupportedRule, "only count"),
        ("sel: {A|base64offset: x}\ncondition: sel", UnsupportedRule, "base64offset"),
        ("sel: {A: 1}\ncondition: other", RuleError, "unknown search"),
        ("sel: {A: 1}\ncondition: 1 of filter_*", RuleError, "does not match"),
        ("sel: {A: 1}\ncondition: (sel", RuleError, "too early"),
        ("sel: {A: 1}\ncondition: sel sel", RuleError, "unexpected"),
        ("sel: {A|gt: abc}\ncondition: sel", RuleError, "number"),
        ("sel: {A|cidr: nope}\ncondition: sel", RuleError, "CIDR"),
        ("sel: {A: []}\ncondition: sel", RuleError, "empty"),
    ],
)
def test_errors(detection: str, error: type[Exception], message: str) -> None:
    with pytest.raises(error, match=message):
        rule_for(detection).compile()


def test_rule_metadata_and_multiple_conditions() -> None:
    rule = load_rule(
        "title: T\nid: abc\nlevel: high\n"
        "detection:\n  a: {X: 1}\n  b: {Y: 2}\n  condition: [a, b]\n"
    )
    assert (rule.title, rule.id, rule.level) == ("T", "abc", "high")
    assert to_where(rule.compile(), Target()) == '("X" = 1 OR "Y" = 2)'


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("action: global\ntitle: x\n", UnsupportedRule),
        ("filter:\n  rules: [a]\n", UnsupportedRule),
        ("- a\n- b\n", RuleError),
        ("title: x\n", RuleError),
        ("detection:\n  sel: {A: 1}\n", RuleError),
        (
            "detection:\n  s: {A: 1}\n  condition: s\n"
            "---\ndetection:\n  s: {B: 1}\n  condition: s\n",
            UnsupportedRule,
        ),
        ("logsource: x\ndetection:\n  s: {A: 1}\n  condition: s\n", RuleError),
        ("detection: [\n", RuleError),
    ],
)
def test_bad_rules(text: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        load_rule(text)


def test_keyword_match_is_contains() -> None:
    expr = rule_for("keywords: evil\ncondition: keywords").compile()
    assert expr == StrMatch(None, SigmaString((Wildcard.MANY, "evil", Wildcard.MANY)))


def test_long_lists_are_grouped() -> None:
    values = ", ".join(f"h{i}" for i in range(120))
    expr = rule_for(f"sel: {{Hash: [{values}]}}\ncondition: sel").compile()
    sql = to_where(expr, Target(json_column="data"))
    assert sql.startswith("((") and sql.count("(") - sql.count("json_extract(") == 4


def test_postgres_rejects_regex_repeats_over_255() -> None:
    rule = rule_for("sel: {A|re: 'x{1,256}'}\ncondition: sel")
    with pytest.raises(UnsupportedRule, match="255"):
        to_where(rule.compile(), Target("postgres"))
    assert "REGEXP" in to_where(rule.compile(), Target("sqlite"))
