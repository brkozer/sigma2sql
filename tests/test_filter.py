"""Sigma filters: conditions kept apart from the rules they narrow down."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigma2sql import Collection, RuleError, Target, UnsupportedRule, load_documents, to_query
from sigma2sql.cli import main
from sigma2sql.correlation import correlation_query
from sigma2sql.rule import Filter, Rule
from sigma2sql.runner import matching_events, rows, target

RULE = """title: Shell
id: 11111111-1111-4111-8111-111111111111
name: shell
logsource: {product: windows, category: process_creation}
detection:
  sel: {Image|endswith: cmd.exe}
  condition: sel
"""
OTHER = """title: Network
id: 22222222-2222-4222-8222-222222222222
logsource: {product: windows, category: network_connection}
detection:
  sel: {Image|endswith: cmd.exe}
  condition: sel
"""
FILTER = """title: Not on build servers
logsource: {product: windows, category: process_creation}
filter:
  rules: [11111111-1111-4111-8111-111111111111]
  build: {Computer|startswith: build-}
  condition: not build
"""
EVENTS = [
    {"Image": "C:\\cmd.exe", "Computer": "pc-1"},
    {"Image": "C:\\cmd.exe", "Computer": "build-7"},
    {"Image": "C:\\cmd.exe"},
    {"Image": "C:\\notepad.exe", "Computer": "pc-1"},
]


def collection(tmp_path: Path, *texts: str) -> Collection:
    paths = []
    for i, text in enumerate(texts):
        paths.append(tmp_path / f"{i}.yml")
        paths[-1].write_text(text)
    return Collection.load(paths)


def test_filter_narrows_the_rule(tmp_path: Path) -> None:
    (rule,) = collection(tmp_path, RULE, FILTER).rules
    # A missing field passes `not build`, as in any Sigma condition.
    assert matching_events(rule, EVENTS) == [0, 2]


def test_rule_without_filter_is_unchanged(tmp_path: Path) -> None:
    (rule,) = collection(tmp_path, RULE).rules
    assert matching_events(rule, EVENTS) == [0, 1, 2]


def test_rule_can_be_named_by_name(tmp_path: Path) -> None:
    text = FILTER.replace("11111111-1111-4111-8111-111111111111", "shell")
    (rule,) = collection(tmp_path, RULE, text).rules
    assert matching_events(rule, EVENTS) == [0, 2]


def test_a_single_reference_may_be_a_string(tmp_path: Path) -> None:
    text = FILTER.replace("[11111111-1111-4111-8111-111111111111]", "shell")
    (rule,) = collection(tmp_path, RULE, text).rules
    assert len(rule.filters) == 1


@pytest.mark.parametrize("rules", ["any", "ANY", "[]"])
def test_any_applies_to_every_rule_of_the_logsource(tmp_path: Path, rules: str) -> None:
    text = FILTER.replace("[11111111-1111-4111-8111-111111111111]", rules)
    col = collection(tmp_path, RULE, OTHER, text)
    assert [len(r.filters) for r in col.rules] == [1, 0]


def test_other_logsource_is_left_alone(tmp_path: Path) -> None:
    text = FILTER.replace(
        "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    )
    col = collection(tmp_path, RULE, OTHER, text)
    assert [len(r.filters) for r in col.rules] == [0, 0]
    assert len(col.unused_filters()) == 1


def test_wider_filter_logsource_applies(tmp_path: Path) -> None:
    text = FILTER.replace("{product: windows, category: process_creation}", "{product: windows}")
    (rule,) = collection(tmp_path, RULE, text).rules
    assert len(rule.filters) == 1


def test_several_filters_all_apply(tmp_path: Path) -> None:
    second = FILTER.replace("build-", "pc-").replace("build", "office")
    (rule,) = collection(tmp_path, RULE, FILTER, second).rules
    assert matching_events(rule, EVENTS) == [2]


def test_filter_uses_placeholders(tmp_path: Path) -> None:
    text = FILTER.replace("Computer|startswith: build-", "Computer|expand: '%servers%'")
    (rule,) = collection(tmp_path, RULE, text).rules
    base = Target(placeholders={"servers": ("build-7",)})
    assert matching_events(rule, EVENTS, base) == [0, 2]


def test_filter_reaches_correlations(tmp_path: Path) -> None:
    corr = """title: Many shells
correlation:
  type: event_count
  rules: [shell]
  group-by: [Image]
  condition: {gte: 2}
"""
    col = collection(tmp_path, RULE, corr, FILTER)
    query = correlation_query(col.correlations[0], col.resolve(col.correlations[0]), target())
    events = [{**e, "timestamp": "2026-11-01T10:00:00Z"} for e in EVENTS]
    assert [r["value"] for r in rows(query, events)] == [2]


def test_filter_is_part_of_the_sql(tmp_path: Path) -> None:
    (rule,) = collection(tmp_path, RULE, FILTER).rules
    assert "NOT COALESCE" in to_query(rule, Target(json_column="data"))


def test_filters_are_not_reported_as_rules(tmp_path: Path) -> None:
    col = collection(tmp_path, RULE, FILTER)
    assert (len(col.rules), len(col.filters), col.errors) == (1, 1, [])


def test_parsed_fields() -> None:
    (doc,) = load_documents(FILTER)
    assert isinstance(doc, Filter) and not isinstance(doc, Rule)
    assert doc.rules == ("11111111-1111-4111-8111-111111111111",)
    assert doc.condition == "not build"


@pytest.mark.parametrize(
    ("text", "error", "message"),
    [
        ("filter: [a]\nlogsource: {product: x}\n", RuleError, "must be a map"),
        ("filter:\n  rules: any\n  s: {A: 1}\n  condition: s\n", RuleError, "logsource"),
        ("logsource: {product: x}\nfilter:\n  s: {A: 1}\n  condition: s\n", RuleError, "rules"),
        (
            "logsource: {product: x}\nfilter:\n  rules: 5\n  s: {A: 1}\n  condition: s\n",
            RuleError,
            "rules",
        ),
        ("logsource: {product: x}\nfilter:\n  rules: any\n  s: {A: 1}\n", RuleError, "condition"),
        (
            "logsource: {product: x}\nfilter:\n  rules: any\n  s: {A: 1}\n  condition: [s]\n",
            RuleError,
            "condition",
        ),
        ("logsource: {product: x}\nfilter:\n  rules: any\n  condition: s\n", RuleError, "searches"),
        (
            "logsource: {product: x}\nfilter:\n  rules: any\n  s: {A: 1}\n"
            "  condition: s | count() > 1\n",
            UnsupportedRule,
            "aggregations",
        ),
    ],
)
def test_bad_filters(text: str, error: type[Exception], message: str) -> None:
    with pytest.raises(error, match=message):
        load_documents(text)


def test_cli_warns_about_a_filter_that_matches_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text(RULE)
    stray = tmp_path / "f.yml"
    stray.write_text(FILTER.replace("11111111-1111-4111-8111-111111111111", "nope"))
    assert main(["convert", str(rule), str(stray)]) == 0
    assert "applies to no rule" in capsys.readouterr().err
