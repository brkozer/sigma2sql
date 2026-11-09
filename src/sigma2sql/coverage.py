"""Which rules can match these logs at all, judged from the fields a sample of events has.

Most detection gaps are silent: a rule needs `ParentImage`, the logs do not have it, and the
rule simply never fires. Missing fields are treated the way the SQL treats them, so a rule
that says `not ParentImage: x` still counts as able to match.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from sigma2sql import database
from sigma2sql.collection import Collection
from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.expr import (
    And,
    Cidr,
    Compare,
    Exists,
    Expr,
    FieldRef,
    Not,
    NullMatch,
    NumMatch,
    Or,
    Regex,
    StrMatch,
    TimePart,
)
from sigma2sql.hunt import COLUMN, TABLE, _for_these_logs, connect, load_logs
from sigma2sql.rule import Correlation, Document, Rule
from sigma2sql.sql import Renderer, Target, quote_table

READY = "ready"
PARTIAL = "partial"
BLIND = "blind"
ORDERED_TYPES = ("temporal", "temporal_ordered")
Has = Callable[[str | None], bool]


@dataclass
class RuleCoverage:
    rule: Document
    status: str
    missing: tuple[str, ...] = ()


@dataclass
class Coverage:
    rules: list[RuleCoverage]
    sampled: int
    skipped: list[tuple[Document, str]] = field(default_factory=list)
    other_logs: int = 0
    # Every field name found, to offer when mapping a missing one.
    seen: set[str] = field(default_factory=set)

    def count(self, status: str) -> int:
        return sum(1 for r in self.rules if r.status == status)

    def missing_fields(self) -> list[tuple[str, int, int]]:
        """Each missing field with how many rules it blinds and how many it weakens."""
        blind: Counter[str] = Counter()
        partial: Counter[str] = Counter()
        for rule in self.rules:
            (blind if rule.status == BLIND else partial).update(rule.missing)
        ranked = sorted({*blind, *partial}, key=lambda f: (-blind[f], -partial[f], f))
        return [(name, blind[name], partial[name]) for name in ranked]


def field_names(document: Mapping[str, Any], nested: bool) -> Iterator[str]:
    """The fields that hold a value. A null is the same as the field not being there."""
    for key, value in document.items():
        if value is None:
            continue
        name = str(key)
        yield name
        if nested and isinstance(value, Mapping):
            yield from (f"{name}.{inner}" for inner in field_names(value, nested))


def fields_used(expr: Expr) -> Iterator[str]:
    match expr:
        case And(items) | Or(items):
            for item in items:
                yield from fields_used(item)
        case Not(item):
            yield from fields_used(item)
        case FieldRef(name, other):
            yield name
            yield other
        case StrMatch(name) | Regex(name):
            if name is not None:
                yield name
        case NumMatch(name) | NullMatch(name) | Cidr(name) | Compare(name) | TimePart(name):
            yield name
        case Exists(name):
            yield name


def possible(expr: Expr, has: Has) -> tuple[bool, bool]:
    """Whether the expression can come out true, and whether it can come out false."""
    match expr:
        case And(items):
            results = [possible(item, has) for item in items]
            return all(r[0] for r in results), any(r[1] for r in results)
        case Or(items):
            results = [possible(item, has) for item in items]
            return any(r[0] for r in results), all(r[1] for r in results)
        case Not(item):
            can_true, can_false = possible(item, has)
            return can_false, can_true
        case FieldRef(name, other):
            return (True, True) if has(name) and has(other) else (False, True)
        case NullMatch(name):
            return (True, True) if has(name) else (True, False)
        case Exists(name, exists):
            if has(name):
                return True, True
            return (False, True) if exists else (True, False)
        case StrMatch(name) | Regex(name):
            return (True, True) if has(name) else (False, True)
        case _:
            assert not isinstance(expr, And | Or | Not)
            return (True, True) if has(expr.field) else (False, True)


def _rule_coverage(rule: Rule, renderer: Renderer, seen: set[str], keywords: bool) -> RuleCoverage:
    def has(name: str | None) -> bool:
        if name is None:
            return keywords
        return any(place in seen for place in renderer.locations(name))

    expr = rule.compile(renderer.t.placeholders)
    missing = tuple(sorted({name for name in fields_used(expr) if not has(name)}))
    if not possible(expr, has)[0]:
        return RuleCoverage(rule, BLIND, missing)
    return RuleCoverage(rule, PARTIAL if missing else READY, missing)


def _correlation_coverage(
    corr: Correlation, parts: list[RuleCoverage], renderer: Renderer, seen: set[str]
) -> RuleCoverage:
    missing = {name for part in parts for name in part.missing}
    blind = [part for part in parts if part.status == BLIND]
    if corr.timespan is not None and not any(p in seen for p in renderer.time_locations()):
        return RuleCoverage(corr, BLIND, tuple(sorted({*missing, renderer.t.timestamp})))
    lost = bool(blind) if corr.type in ORDERED_TYPES else len(blind) == len(parts)
    if lost:
        return RuleCoverage(corr, BLIND, tuple(sorted(missing)))
    return RuleCoverage(corr, PARTIAL if missing else READY, tuple(sorted(missing)))


def measure(
    rules: Collection,
    target: Target,
    sample: Callable[[str], list[dict[str, Any]]],
    keywords: bool,
) -> Coverage:
    """Judge every rule against the fields found by `sample`, which reads rows of a table."""
    renderer = Renderer(target)
    seen_by_table: dict[str, set[str]] = {}
    sampled = 0

    def seen_in(rule: Rule) -> set[str]:
        nonlocal sampled
        route = next((r for r in target.routes if r.applies(rule.logsource)), None)
        table = (route.table if route else None) or target.table
        if table not in seen_by_table:
            rows = sample(table)
            sampled += len(rows)
            seen_by_table[table] = {n for row in rows for n in field_names(row, target.nested)}
        return seen_by_table[table]

    cache: dict[int, RuleCoverage] = {}

    def judge(rule: Rule) -> RuleCoverage:
        if id(rule) not in cache:
            cache[id(rule)] = _rule_coverage(rule, renderer, seen_in(rule), keywords)
        return cache[id(rule)]

    candidates: list[Document] = [*rules.standalone(), *rules.correlations]
    items = [item for item in candidates if _for_these_logs(item, rules, target)]
    result = Coverage([], 0, other_logs=len(candidates) - len(items))
    for item in items:
        try:
            if isinstance(item, Correlation):
                parts = rules.resolve(item)
                judged = [judge(part) for part in parts]
                seen = seen_in(parts[0])
                result.rules.append(_correlation_coverage(item, judged, renderer, seen))
            else:
                result.rules.append(judge(item))
        except (RuleError, UnsupportedRule) as exc:
            result.skipped.append((item, str(exc)))
    result.sampled = sampled
    result.seen = set().union(*seen_by_table.values()) if seen_by_table else set()
    return result


def of_files(
    rules: Collection,
    logs: list[str],
    size: int,
    target: Target,
    warn: Callable[[str], None] | None = None,
) -> Coverage:
    con = connect()
    warnings: list[str] = []
    load_logs(con, logs, warnings)
    for warning in warnings:
        if warn:
            warn(warning)
    routes = tuple(replace(r, table=None) for r in target.routes)
    target = replace(target, dialect="duckdb", table=TABLE, json_column=COLUMN, routes=routes)

    def sample(_: str) -> list[dict[str, Any]]:
        query = f"SELECT CAST({COLUMN} AS VARCHAR) FROM {TABLE} LIMIT {size}"
        return [json.loads(row[0]) for row in con.execute(query).fetchall()]

    return measure(rules, target, sample, keywords=True)


def of_database(rules: Collection, db: database.Database, size: int, target: Target) -> Coverage:
    target = replace(target, dialect=db.dialect)

    def sample(table: str) -> list[dict[str, Any]]:
        rows = db.rows(f"SELECT * FROM {quote_table(table)} LIMIT {size}")
        found = [database.document(row, target.json_column) for row in rows]
        return [row for row in found if isinstance(row, dict)]

    return measure(rules, target, sample, bool(target.json_column or target.keyword_column))
