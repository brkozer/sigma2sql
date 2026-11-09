"""Render Expr trees as SQL for SQLite, PostgreSQL, DuckDB and ClickHouse."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal, TypeGuard

from sigma2sql.detection import compile_search
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
    TimePart,
    Wildcard,
)
from sigma2sql.rule import Rule

Dialect = Literal["sqlite", "postgres", "duckdb", "clickhouse"]
TimestampFormat = Literal["iso", "epoch_s", "epoch_ms"]
DIALECTS: tuple[Dialect, ...] = ("sqlite", "postgres", "duckdb", "clickhouse")

# SQLite parses `a OR b OR ...` into a tree as deep as the list and stops at depth 1000,
# which rules with long hash lists exceed. Grouping keeps the depth logarithmic.
GROUP = 50
# Largest {m,n} repetition count each engine accepts (SQLite uses Python's re: no limit).
MAX_REPEAT: dict[Dialect, int | None] = {
    "sqlite": None,
    "postgres": 255,
    "duckdb": 1000,
    "clickhouse": 1000,
}
REPEAT = re.compile(r"\{(\d+)(?:,(\d*))?\}")
# RE2 (DuckDB, ClickHouse) has no lookaround or backreferences.
# Word boundaries inside CamelCase names: NewValue -> New Value.
CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
RE2_UNSUPPORTED = re.compile(r"\(\?<?[=!]|\\[1-9]")
STRFTIME = {"minute": "%M", "hour": "%H", "day": "%d", "month": "%m", "year": "%Y"}
CLICKHOUSE_PARTS = {
    "minute": "toMinute",
    "hour": "toHour",
    "day": "toDayOfMonth",
    "week": "toISOWeek",
    "month": "toMonth",
    "year": "toYear",
}


@dataclass(frozen=True)
class Route:
    """Logsource routing: rules whose `logsource` has every key/value in `match` read
    from `table` (if set) and get `where` (a Sigma search map, in target field names) added.
    """

    match: Mapping[str, str]
    table: str | None = None
    where: Mapping[str, Any] | None = None

    def applies(self, logsource: Mapping[str, str]) -> bool:
        return all(
            str(logsource.get(k, "")).lower() == str(v).lower() for k, v in self.match.items()
        )


@dataclass(frozen=True)
class Target:
    """Where the events live and how Sigma field names reach them.

    With `json_column`, every event is one JSON object in that column and fields are
    read as top-level keys (or, with `nested`, dotted paths into nested objects).
    Otherwise each field is its own column. A field missing from `mapping` is looked up
    through the `default_field` templates (`{field}` is the Sigma name, `{field_words}` the
    same name split into words, e.g. "New Value"), or under its own name.
    """

    dialect: Dialect = "sqlite"
    table: str = "events"
    # Sigma field -> column/key, or a sequence of candidates tried in order.
    mapping: Mapping[str, str | tuple[str, ...]] = field(default_factory=dict)
    json_column: str | None = None
    keyword_column: str | None = None
    # Event time, used by correlations and aggregations with a timespan.
    timestamp: str = "timestamp"
    timestamp_format: TimestampFormat = "iso"
    nested: bool = False
    default_field: str | tuple[str, ...] | None = None
    routes: tuple[Route, ...] = ()
    # The logs only hold this `logsource.product`, so `hunt` leaves out rules for others.
    product: str | None = None
    # Values for `%name%` placeholders in rules that use the `expand` modifier.
    placeholders: Mapping[str, tuple[Any, ...]] = field(default_factory=dict)
    # Only events from this moment on, in seconds since 1970.
    since: float | None = None
    # A row that is not valid JSON counts as no match instead of ending the query, for
    # databases that accept anything in a text column.
    lenient_json: bool = False


def to_query(rule: Rule, target: Target, columns: str = "*") -> str:
    """SQL for a detection rule. Rules with a legacy `| count()` aggregation return
    one row per group (and window) that meets the threshold; `columns` is then ignored."""
    if rule.aggregation is not None:
        from sigma2sql.correlation import correlation_query

        return correlation_query(rule.aggregation, [replace(rule, aggregation=None)], target)
    table, where = source(rule, target)
    return f"SELECT {columns} FROM {table} WHERE {where}"


def source(rule: Rule, target: Target) -> tuple[str, str]:
    """The quoted table and WHERE clause for a rule, after logsource routing."""
    where = to_where(rule.compile(target.placeholders), target)
    if target.since is not None:
        where = f"({Renderer(target).epoch()} >= {target.since!r} AND {where})"
    route = next((r for r in target.routes if r.applies(rule.logsource)), None)
    if route is None:
        return quote_table(target.table), where
    if route.where:
        # Route conditions are written in target field names, so no mapping applies.
        raw = replace(target, mapping={}, default_field=None)
        extra = to_where(compile_search("logsource", dict(route.where)), raw)
        where = f"({extra} AND {where})"
    return quote_table(route.table or target.table), where


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

    def lit(self, value: str) -> str:
        """A string literal; ClickHouse treats backslashes in literals as escapes."""
        return literal(value.replace("\\", "\\\\") if self.d == "clickhouse" else value)

    def render(self, expr: Expr) -> str:
        match expr:
            case And(items):
                return _join([self.render(i) for i in items], "AND")
            case Or(items):
                return _join(self.alternatives(items), "OR")
            case Not(item):
                # A missing field makes the inner test NULL; Sigma treats that as "no match",
                # so the negation has to come out true rather than NULL.
                return f"NOT COALESCE({self.render(item)}, FALSE)"
            case StrMatch(f, _, cased):
                col = self.keyword() if f is None else self.column(f)
                value = self.searched(expr)
                if f is not None and self._is_boolean_text(value):
                    # json_extract turns JSON true into 1, which `true` would never equal.
                    kind = col.replace("json_extract(", "json_type(")
                    words = "WHEN 'true' THEN 'true' WHEN 'false' THEN 'false'"
                    col = f"CASE {kind} {words} ELSE {col} END"
                return self.string(col, value, cased)
            case NumMatch(f, value):
                col = self.column(f)
                if not self.json:
                    return f"{col} = {value}"
                # JSON may hold 4688 or "4688"; compare the text form so both match.
                text = f"CAST({col} AS TEXT)" if self.d == "sqlite" else col
                return f"{text} = {self.lit(str(value))}"
            case NullMatch(f):
                return f"{self.column(f)} IS NULL"
            case Exists(f, exists):
                return f"{self.column(f)} IS {'NOT ' if exists else ''}NULL"
            case Regex(f, pattern, flags):
                col = self.keyword() if f is None else self.column(f)
                return self.regex(col, pattern, flags)
            case Cidr(f, network):
                col = self.column(f)
                if self.d == "postgres":
                    address = _postgres_cast(col, "inet")
                    return f"{address} <<= {self.lit(network)}::inet"
                if self.d == "clickhouse":
                    # isIPAddressInRange raises on text that is not an address.
                    text = f"toString({col})"
                    valid = f"(isIPv4String({text}) OR isIPv6String({text}))"
                    return f"({valid} AND isIPAddressInRange({text}, {self.lit(network)}))"
                return f"cidr_match({col}, {self.lit(network)})"
            case Compare(f, op, value):
                return f"{self.number(self.column(f))} {op} {value}"
            case TimePart(f, part, value):
                return f"{self.time_part(self.column(f), part)} = {value}"
            case FieldRef(f, other):
                return f"{self.column(f)} = {self.column(other)}"
        raise AssertionError(f"unhandled expression {expr!r}")

    def alternatives(self, items: tuple[Expr, ...]) -> list[str]:
        """The terms of an OR. DuckDB keeps memory per term and thread, so the thousands of
        patterns some rules list for one field run it out of memory; those become one test."""
        if self.d != "duckdb":
            return [self.render(i) for i in items]
        fields = Counter(i.field for i in items if _uncased(i))
        long = [name for name, count in fields.items() if count > GROUP]
        terms = [self.render(i) for i in items if not (_uncased(i) and i.field in long)]
        for name in long:
            col = self.keyword() if name is None else self.column(name)
            values = [self.searched(i) for i in items if _uncased(i) and i.field == name]
            patterns = [self.lit(_like(v)) for v in values]
            test = f"lambda p: ilike_escape({col}, p, '\\')"
            terms.append(f"len(list_filter([{', '.join(patterns)}], {test})) > 0")
        return terms

    def column(self, sigma_field: str) -> str:
        name = self.t.mapping.get(sigma_field)
        if name is None:
            templates = self._templates()
            name = _expand(templates, sigma_field) if templates else sigma_field
        return self._located(name)

    def time_column(self) -> str:
        """The event time: a profile gives its full path, which `default_field` must not
        move, while a plain name such as `UtcTime` can sit with the other fields."""
        name = self.t.mapping.get(self.t.timestamp)
        if name is None:
            templates = self._templates()
            name = _expand(templates, self.t.timestamp) if templates else self.t.timestamp
            if templates and self.json:
                name = (self.t.timestamp, *name)
        return self._located(name)

    def _templates(self) -> tuple[str, ...]:
        templates = self.t.default_field or ()
        return (templates,) if isinstance(templates, str) else templates

    def _located(self, name: str | Sequence[str]) -> str:
        if not isinstance(name, str):
            if len(name) == 1:
                return self.path(name[0])
            # Several candidate locations: the first one present wins.
            return f"COALESCE({', '.join(self.path(n) for n in name)})"
        return self.path(name)

    def path(self, name: str) -> str:
        if self.t.json_column is None:
            return quote_ident(name)
        col = quote_ident(self.t.json_column)
        keys = name.split(".") if self.t.nested else [name]
        if self.d == "clickhouse":
            # Nullable(String): numbers come back as text and a missing key as NULL.
            args = ", ".join(self.lit(k) for k in keys)
            return f"JSONExtract({col}, {args}, 'Nullable(String)')"
        parts = [_dq(p) for p in keys]
        if self.d == "postgres":
            if len(parts) == 1:
                return f"{col}->>{self.lit(name)}"
            return f"{col}#>>{self.lit('{' + ','.join(parts) + '}')}"
        path = self.lit("$" + "".join("." + p for p in parts))
        if self.d == "duckdb":
            # Parentheses: before DuckDB 2.0, `a AND b->>c = d` parses as `(a AND b)->>...`.
            return f"TRY({col}->>{path})" if self.t.lenient_json else f"({col}->>{path})"
        if self.t.lenient_json:
            return f"CASE WHEN json_valid({col}) THEN json_extract({col}, {path}) END"
        return f"json_extract({col}, {path})"

    def number(self, col: str) -> str:
        """Numeric view of a column; JSON values arrive as text in PostgreSQL and DuckDB."""
        if not self.json:
            return col
        if self.d == "postgres":
            return _postgres_cast(col, "numeric")
        if self.d == "duckdb":
            return f"TRY_CAST({col} AS DOUBLE)"
        if self.d == "clickhouse":
            return _clickhouse_number(col)
        return _sqlite_number(col)

    def cast_number(self, expr: str) -> str:
        if self.d == "postgres":
            return _postgres_cast(expr, "double precision")
        if self.d == "duckdb":
            return f"TRY_CAST({expr} AS DOUBLE)"
        if self.d == "clickhouse":
            return _clickhouse_number(f"toString({expr})")
        return _sqlite_number(expr)

    def epoch(self, col: str | None = None) -> str:
        """Seconds since 1970 of a time column, by default the configured timestamp field."""
        col = col or self.time_column()
        fmt = self.t.timestamp_format
        if fmt != "iso":
            seconds = self.cast_number(col)
            return seconds if fmt == "epoch_s" else f"({seconds} / 1000.0)"
        if self.d == "postgres":
            return f"EXTRACT(EPOCH FROM {_postgres_cast(col, 'timestamptz')})"
        if self.d == "duckdb":
            return f"epoch(TRY_CAST({col} AS TIMESTAMPTZ))"
        if self.d == "clickhouse":
            parsed = f"parseDateTime64BestEffortOrNull(toString({col}), 3, 'UTC')"
            return f"(toUnixTimestamp64Milli({parsed}) / 1000.0)"
        return f"unixepoch({col}, 'subsec')"

    def from_epoch(self, expr: str) -> str:
        if self.d == "sqlite":
            return f"datetime({expr}, 'unixepoch', 'subsec')"
        if self.d == "postgres":
            return f"to_timestamp({expr})"
        if self.d == "clickhouse":
            return f"fromUnixTimestamp64Milli(toInt64(({expr}) * 1000), 'UTC')"
        # A plain (UTC) TIMESTAMP: TIMESTAMPTZ values need pytz on the Python side.
        return f"make_timestamp(CAST(({expr}) * 1000000 AS BIGINT))"

    def time_part(self, col: str, part: str) -> str:
        """One part of a time column, in UTC; weeks are ISO 8601 weeks."""
        seconds = self.epoch(col)
        if self.d == "postgres":
            return f"EXTRACT({part.upper()} FROM to_timestamp({seconds}) AT TIME ZONE 'UTC')"
        if self.d == "duckdb":
            return f"date_part({self.lit(part)}, {self.from_epoch(seconds)})"
        if self.d == "clickhouse":
            return f"{CLICKHOUSE_PARTS[part]}({self.from_epoch(seconds)})"
        if part == "week":
            # The week of the year's Thursdays, which is how ISO 8601 numbers weeks.
            thursday = f"date({seconds}, 'unixepoch', '-3 days', 'weekday 4')"
            return f"((CAST(strftime('%j', {thursday}) AS INTEGER) - 1) / 7 + 1)"
        return f"CAST(strftime({self.lit(STRFTIME[part])}, {seconds}, 'unixepoch') AS INTEGER)"

    def percentile(self, expr: str, fraction: float) -> str:
        """Aggregate: the value at `fraction` of the sorted values, interpolated."""
        if self.d == "postgres":
            return f"percentile_cont({fraction}) WITHIN GROUP (ORDER BY {expr})"
        if self.d == "duckdb":
            return f"quantile_cont({expr}, {fraction})"
        if self.d == "clickhouse":
            return f"quantileExactInclusive({fraction})({expr})"
        return f"sigma_percentile({expr}, {fraction})"

    def _is_boolean_text(self, value: SigmaString) -> bool:
        if self.d != "sqlite" or not self.json or value.has_wildcards:
            return False
        return value.text.lower() in ("true", "false")

    def searched(self, item: StrMatch) -> SigmaString:
        """A keyword in JSON mode is looked for in the document's text, where `C:\\Windows` and
        a quote are escaped, so it has to be written the way that text holds it."""
        if item.field is not None or self.t.keyword_column or not self.json:
            return item.value
        parts = tuple(
            json.dumps(p, ensure_ascii=False)[1:-1] if isinstance(p, str) else p
            for p in item.value.parts
        )
        return SigmaString(parts)

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
                return f"{col} = {self.lit(text)}"
            if self.d == "sqlite":
                return f"{col} = {self.lit(text)} COLLATE NOCASE"
            if self.d == "clickhouse":  # lower() only folds ASCII there
                return f"lowerUTF8({col}) = {self.lit(text.lower())}"
            return f"LOWER({col}) = {self.lit(text.lower())}"
        if self.d == "sqlite":
            if cased:
                return f"{col} GLOB {self.lit(_glob(value))}"
            return f"{col} LIKE {self.lit(_like(value))} ESCAPE '\\'"
        op = "LIKE" if cased else "ILIKE"
        if self.d == "clickhouse":  # no ESCAPE clause; the backslash always escapes
            return f"{col} {op} {self.lit(_like(value))}"
        return f"{col} {op} {self.lit(_like(value))} ESCAPE '\\'"

    def regex(self, col: str, pattern: str, flags: str = "") -> str:
        limit = MAX_REPEAT[self.d]
        bounds = [int(n) for m in REPEAT.finditer(pattern) for n in m.groups() if n]
        if limit is not None and any(n > limit for n in bounds):
            raise UnsupportedRule(f"{self.d} regexes allow at most {limit} repetitions: {pattern}")
        if self.d == "postgres":
            return f"{col} ~ {self.lit(_postgres_flags(flags) + _postgres_regex(pattern))}"
        if self.d in ("duckdb", "clickhouse") and RE2_UNSUPPORTED.search(pattern):
            raise UnsupportedRule(f"{self.d} (RE2) has no lookaround or backreferences: {pattern}")
        if self.d == "clickhouse":
            # match() lets `.` reach newlines by default; Sigma regexes do not.
            prefix = f"(?{flags})" if "s" in flags else f"(?{flags}-s)"
            return f"match({col}, {self.lit(prefix + pattern)})"
        if flags:
            pattern = f"(?{flags}){pattern}"
        if self.d == "duckdb":
            return f"regexp_matches({col}, {self.lit(pattern)})"
        return f"{col} REGEXP {self.lit(pattern)}"

    def same(self, a: str, b: str) -> str:
        """Null-safe equality."""
        return f"{a} IS {b}" if self.d == "sqlite" else f"{a} IS NOT DISTINCT FROM {b}"


def _expand(templates: tuple[str, ...], sigma_field: str) -> tuple[str, ...]:
    words = CAMEL.sub(" ", sigma_field)
    names: list[str] = []
    for template in templates:
        name = template.replace("{field_words}", words).replace("{field}", sigma_field)
        if name not in names:
            names.append(name)
    return tuple(names)


def _postgres_cast(expr: str, kind: str) -> str:
    """A cast that gives NULL for bad values, as a failed cast would otherwise end the query:
    Windows logs write `-` in address and number fields all the time."""
    return f"CASE WHEN pg_input_is_valid(({expr})::text, '{kind}') THEN ({expr})::{kind} END"


# GLOB has no repetition, so a number is described by what it cannot look like: other
# characters, two dots (10.0.0.1), a second exponent, a sign inside it (1-2), a dangling
# exponent or sign (1e, e5).
NOT_A_NUMBER = (
    "*[^0-9.eE+-]*",
    "*.*.*",
    "*[eE]*[eE.]*",
    "*[0-9.][+-]*",
    "*[+-][+eE-]*",
    "[eE]*",
    ".[eE]*",
    "[+-].[eE]*",
    "*[eE+-]",
)


def _sqlite_number(expr: str) -> str:
    """CAST alone turns text into 0, which would satisfy a `lt` comparison."""
    text = f"CAST({expr} AS TEXT)"
    checks = [f"{text} GLOB '*[0-9]*'"]
    checks += [f"{text} NOT GLOB '{pattern}'" for pattern in NOT_A_NUMBER]
    return f"CASE WHEN {' AND '.join(checks)} THEN CAST({expr} AS REAL) END"


def _clickhouse_number(text: str) -> str:
    """toFloat64OrNull reads `e5` as 0, `1e+` as 1 and also takes `nan` and `inf`."""
    pattern = "^[+-]?([0-9]+[.]?[0-9]*|[.][0-9]+)([eE][+-]?[0-9]+)?$"
    return f"if(match({text}, '{pattern}'), toFloat64OrNull({text}), NULL)"


def _uncased(item: Expr) -> TypeGuard[StrMatch]:
    return isinstance(item, StrMatch) and not item.cased


def _postgres_regex(pattern: str) -> str:
    """PostgreSQL reads `\\b` as a backspace; its word boundary is `\\y` (`\\B` is `\\Y`)."""
    out: list[str] = []
    in_set = False
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            pair = pattern[i : i + 2]
            out.append({"\\b": "\\y", "\\B": "\\Y"}.get(pair, pair) if not in_set else pair)
            i += 2
            continue
        if char == "[" and not in_set:
            in_set = True
        elif char == "]" and in_set:
            in_set = False
        out.append(char)
        i += 1
    return "".join(out)


def _postgres_flags(flags: str) -> str:
    """Embedded options: PostgreSQL's letters for `m` and `s` differ from Python's."""
    newlines = {"ms": "w", "m": "n", "s": "s"}.get(flags.replace("i", ""), "")
    letters = ("i" if "i" in flags else "") + newlines
    return f"(?{letters})" if letters else ""


def _dq(key: str) -> str:
    """A double-quoted JSON path key or PostgreSQL array element."""
    return '"' + key.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
