"""Render Expr trees as SQL for SQLite, PostgreSQL and DuckDB."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from sigma2sql.errors import UnsupportedRule
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
    SigmaString,
    StrMatch,
    Wildcard,
)
from sigma2sql.rule import Rule

Dialect = Literal["sqlite", "postgres", "duckdb"]
DIALECTS: tuple[Dialect, ...] = ("sqlite", "postgres", "duckdb")

# SQLite parses `a OR b OR ...` into a tree as deep as the list and stops at depth 1000,
# which rules with long hash lists exceed. Grouping keeps the depth logarithmic.
GROUP = 50
# Largest {m,n} repetition count each engine accepts (SQLite uses Python's re: no limit).
MAX_REPEAT: dict[Dialect, int | None] = {"sqlite": None, "postgres": 255, "duckdb": 1000}
REPEAT = re.compile(r"\{(\d+)(?:,(\d*))?\}")
# RE2 (DuckDB) has no lookaround or backreferences.
RE2_UNSUPPORTED = re.compile(r"\(\?<?[=!]|\\[1-9]")


@dataclass(frozen=True)
class Target:
    """Where the events live and how Sigma field names reach them.

    With `json_column`, every event is one JSON object in that column and fields are
    read as top-level keys. Otherwise each field is its own column.
    """

    dialect: Dialect = "sqlite"
    table: str = "events"
    mapping: Mapping[str, str] = field(default_factory=dict)
    json_column: str | None = None
    keyword_column: str | None = None


def to_query(rule: Rule, target: Target, columns: str = "*") -> str:
    where = to_where(rule.compile(), target)
    return f"SELECT {columns} FROM {quote_table(target.table)} WHERE {where}"


def to_where(expr: Expr, target: Target) -> str:
    return Renderer(target).render(expr)


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def quote_table(name: str) -> str:
    return ".".join(quote_ident(part) for part in name.split("."))


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class Renderer:
    def __init__(self, target: Target) -> None:
        self.t = target
        self.d = target.dialect
        self.json = target.json_column is not None

    def render(self, expr: Expr) -> str:
        match expr:
            case And(items):
                return _join([self.render(i) for i in items], "AND")
            case Or(items):
                return _join([self.render(i) for i in items], "OR")
            case Not(item):
                # A missing field makes the inner test NULL; Sigma treats that as "no match",
                # so the negation has to come out true rather than NULL.
                return f"NOT COALESCE({self.render(item)}, FALSE)"
            case StrMatch(f, value, cased):
                col = self.keyword() if f is None else self.column(f)
                return self.string(col, value, cased)
            case NumMatch(f, value):
                col = self.column(f)
                if not self.json:
                    return f"{col} = {value}"
                # JSON may hold 4688 or "4688"; compare the text form so both match.
                text = f"CAST({col} AS TEXT)" if self.d == "sqlite" else col
                return f"{text} = {literal(str(value))}"
            case NullMatch(f):
                return f"{self.column(f)} IS NULL"
            case Exists(f, exists):
                return f"{self.column(f)} IS {'NOT ' if exists else ''}NULL"
            case Regex(f, pattern, ignore_case):
                return self.regex(self.column(f), ("(?i)" if ignore_case else "") + pattern)
            case Cidr(f, network):
                col = self.column(f)
                if self.d == "postgres":
                    return f"({col})::inet <<= {literal(network)}::inet"
                return f"cidr_match({col}, {literal(network)})"
            case Compare(f, op, value):
                return f"{self.number(self.column(f))} {op} {value}"
            case FieldRef(f, other):
                return f"{self.column(f)} = {self.column(other)}"
        raise AssertionError(f"unhandled expression {expr!r}")

    def column(self, sigma_field: str) -> str:
        name = self.t.mapping.get(sigma_field, sigma_field)
        if self.t.json_column is None:
            return quote_ident(name)
        col = quote_ident(self.t.json_column)
        if self.d == "postgres":
            return f"{col}->>{literal(name)}"
        path = literal('$."' + name.replace("\\", "\\\\").replace('"', '\\"') + '"')
        if self.d == "duckdb":
            return f"{col}->>{path}"
        return f"json_extract({col}, {path})"

    def number(self, col: str) -> str:
        """Numeric view of a column; JSON values arrive as text in PostgreSQL and DuckDB."""
        if not self.json:
            return col
        if self.d == "postgres":
            return f"({col})::numeric"
        if self.d == "duckdb":
            return f"TRY_CAST({col} AS DOUBLE)"
        return f"CAST({col} AS REAL)"

    def keyword(self) -> str:
        if self.t.keyword_column:
            return quote_ident(self.t.keyword_column)
        if self.t.json_column:
            col = quote_ident(self.t.json_column)
            return col if self.d == "sqlite" else f"CAST({col} AS TEXT)"
        raise UnsupportedRule("keyword searches need a keyword column or a JSON column")

    def string(self, col: str, value: SigmaString, cased: bool) -> str:
        if not value.has_wildcards:
            text = value.text
            if cased:
                return f"{col} = {literal(text)}"
            if self.d == "sqlite":
                return f"{col} = {literal(text)} COLLATE NOCASE"
            return f"LOWER({col}) = {literal(text.lower())}"
        if self.d == "sqlite":
            if cased:
                return f"{col} GLOB {literal(_glob(value))}"
            return f"{col} LIKE {literal(_like(value))} ESCAPE '\\'"
        op = "LIKE" if cased else "ILIKE"
        return f"{col} {op} {literal(_like(value))} ESCAPE '\\'"

    def regex(self, col: str, pattern: str) -> str:
        limit = MAX_REPEAT[self.d]
        bounds = [int(n) for m in REPEAT.finditer(pattern) for n in m.groups() if n]
        if limit is not None and any(n > limit for n in bounds):
            raise UnsupportedRule(f"{self.d} regexes allow at most {limit} repetitions: {pattern}")
        if self.d == "postgres":
            return f"{col} ~ {literal(pattern)}"
        if self.d == "duckdb":
            if RE2_UNSUPPORTED.search(pattern):
                raise UnsupportedRule(
                    f"duckdb (RE2) has no lookaround or backreferences: {pattern}"
                )
            return f"regexp_matches({col}, {literal(pattern)})"
        return f"{col} REGEXP {literal(pattern)}"

    def same(self, a: str, b: str) -> str:
        """Null-safe equality."""
        return f"{a} IS {b}" if self.d == "sqlite" else f"{a} IS NOT DISTINCT FROM {b}"


def _join(parts: list[str], op: str) -> str:
    while len(parts) > GROUP:
        parts = [_join(parts[i : i + GROUP], op) for i in range(0, len(parts), GROUP)]
    return "(" + f" {op} ".join(parts) + ")"


def _like(value: SigmaString) -> str:
    out: list[str] = []
    for part in value.parts:
        if part is Wildcard.MANY:
            out.append("%")
        elif part is Wildcard.ONE:
            out.append("_")
        else:
            assert isinstance(part, str)
            out.append(part.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
    return "".join(out)


def _glob(value: SigmaString) -> str:
    out: list[str] = []
    for part in value.parts:
        if part is Wildcard.MANY:
            out.append("*")
        elif part is Wildcard.ONE:
            out.append("?")
        else:
            assert isinstance(part, str)
            out.append("".join(f"[{c}]" if c in "*?[" else c for c in part))
    return "".join(out)
