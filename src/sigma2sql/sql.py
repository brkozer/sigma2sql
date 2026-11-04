"""Render Expr trees as SQL for SQLite and PostgreSQL."""

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

Dialect = Literal["sqlite", "postgres"]
DIALECTS: tuple[Dialect, ...] = ("sqlite", "postgres")

# SQLite parses `a OR b OR ...` into a tree as deep as the list and stops at depth 1000,
# which rules with long hash lists exceed. Grouping keeps the depth logarithmic.
GROUP = 50
PG_DUPMAX = 255
REPEAT = re.compile(r"\{(\d+)(?:,(\d*))?\}")


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
    return _Renderer(target).render(expr)


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def quote_table(name: str) -> str:
    return ".".join(quote_ident(part) for part in name.split("."))


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class _Renderer:
    def __init__(self, target: Target) -> None:
        self.t = target
        self.pg = target.dialect == "postgres"

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
                if self.t.json_column is None:
                    return f"{col} = {value}"
                # JSON may hold 4688 or "4688"; compare the text form so both match.
                text = col if self.pg else f"CAST({col} AS TEXT)"
                return f"{text} = {literal(str(value))}"
            case NullMatch(f):
                return f"{self.column(f)} IS NULL"
            case Exists(f, exists):
                return f"{self.column(f)} IS {'NOT ' if exists else ''}NULL"
            case Regex(f, pattern, ignore_case):
                pattern = ("(?i)" if ignore_case else "") + pattern
                bounds = [int(n) for m in REPEAT.finditer(pattern) for n in m.groups() if n]
                if self.pg and any(n > PG_DUPMAX for n in bounds):
                    raise UnsupportedRule(
                        f"PostgreSQL regexes allow at most {PG_DUPMAX} repetitions: {pattern}"
                    )
                op = "~" if self.pg else "REGEXP"
                return f"{self.column(f)} {op} {literal(pattern)}"
            case Cidr(f, network):
                col = self.column(f)
                if self.pg:
                    return f"({col})::inet <<= {literal(network)}::inet"
                return f"cidr_match({col}, {literal(network)})"
            case Compare(f, op, value):
                col = self.column(f)
                if self.t.json_column is not None:
                    col = f"({col})::numeric" if self.pg else f"CAST({col} AS REAL)"
                return f"{col} {op} {value}"
            case FieldRef(f, other):
                return f"{self.column(f)} = {self.column(other)}"
        raise AssertionError(f"unhandled expression {expr!r}")

    def column(self, sigma_field: str) -> str:
        name = self.t.mapping.get(sigma_field, sigma_field)
        json_col = self.t.json_column
        if json_col is None:
            return quote_ident(name)
        if self.pg:
            return f"{quote_ident(json_col)}->>{literal(name)}"
        path = '$."' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return f"json_extract({quote_ident(json_col)}, {literal(path)})"

    def keyword(self) -> str:
        if self.t.keyword_column:
            return quote_ident(self.t.keyword_column)
        if self.t.json_column:
            col = quote_ident(self.t.json_column)
            return f"{col}::text" if self.pg else col
        raise UnsupportedRule("keyword searches need a keyword column or a JSON column")

    def string(self, col: str, value: SigmaString, cased: bool) -> str:
        if not value.has_wildcards:
            text = value.text
            if cased:
                return f"{col} = {literal(text)}"
            if self.pg:
                return f"LOWER({col}) = {literal(text.lower())}"
            return f"{col} = {literal(text)} COLLATE NOCASE"
        if cased and not self.pg:
            return f"{col} GLOB {literal(_glob(value))}"
        op = "LIKE" if cased or not self.pg else "ILIKE"
        return f"{col} {op} {literal(_like(value))} ESCAPE '\\'"


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
