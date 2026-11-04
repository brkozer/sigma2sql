from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

import yaml

from sigma2sql.condition import compile_condition
from sigma2sql.detection import compile_search
from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.expr import Expr, any_of

CorrelationType = Literal[
    "event_count", "value_count", "value_sum", "value_avg", "temporal", "temporal_ordered"
]
CORRELATION_TYPES: tuple[CorrelationType, ...] = (
    "event_count",
    "value_count",
    "value_sum",
    "value_avg",
    "temporal",
    "temporal_ordered",
)
OPS = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "="}
LEGACY_OPS = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte", "=": "eq", "==": "eq"}
TIMESPAN = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$")
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
# `selection | count(field) by a, b > 5`, the pre-correlation aggregation syntax.
AGGREGATION = re.compile(
    r"^count\(\s*(?P<field>[\w.-]*)\s*\)"
    r"(?:\s+by\s+(?P<by>[\w.-]+(?:\s*,\s*[\w.-]+)*))?"
    r"\s*(?P<op>>=|<=|==|=|>|<)\s*(?P<value>\d+)$"
)

Condition = tuple[tuple[str, float], ...]


@dataclass(frozen=True)
class Rule:
    title: str
    id: str | None
    level: str | None
    searches: dict[str, Any]
    conditions: tuple[str, ...]
    logsource: Mapping[str, str] = dataclasses.field(default_factory=dict)
    name: str | None = None
    # Set for rules written with the legacy `| count() ...` condition syntax.
    aggregation: Correlation | None = None
    path: Path | None = dataclasses.field(default=None, compare=False)

    def compile(self) -> Expr:
        """Build the match tree. Searches the condition never uses are not compiled."""
        cache: dict[str, Expr] = {}

        def resolve(name: str) -> Expr:
            if name not in cache:
                cache[name] = compile_search(name, self.searches[name])
            return cache[name]

        names = list(self.searches)
        return any_of([compile_condition(c, names, resolve) for c in self.conditions])

    @property
    def ref(self) -> str:
        """The name correlations use for this rule."""
        return self.name or self.id or self.title


@dataclass(frozen=True)
class Correlation:
    """A Sigma correlation rule: a count or sequence over the matches of other rules."""

    title: str
    id: str | None
    level: str | None
    type: CorrelationType
    rules: tuple[str, ...]
    group_by: tuple[str, ...] = ()
    timespan: int | None = None  # seconds
    condition: Condition = ()
    field: str | None = None
    aliases: Mapping[str, Mapping[str, str]] = dataclasses.field(default_factory=dict)
    generate: bool = False
    name: str | None = None
    path: Path | None = dataclasses.field(default=None, compare=False)


Document = Rule | Correlation


def load_documents(text: str, path: Path | None = None) -> list[Document]:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RuleError(f"invalid YAML: {exc}") from exc
    if not docs:
        raise RuleError("empty rule file")
    out: list[Document] = []
    for doc in docs:
        if not isinstance(doc, dict):
            raise RuleError("a rule must be a YAML map")
        if "action" in doc:
            raise UnsupportedRule("legacy rule collections ('action: global') are not supported")
        if "correlation" in doc:
            out.append(_correlation(doc, path))
        elif "filter" in doc:
            raise UnsupportedRule("filter rules are not supported")
        else:
            out.append(_rule(doc, path))
    return out


def load_file(path: Path) -> list[Document]:
    return load_documents(path.read_text(encoding="utf-8"), path)


def load_rule(text: str, path: Path | None = None) -> Rule:
    """Load a file that holds exactly one detection rule."""
    docs = load_documents(text, path)
    if len(docs) != 1 or not isinstance(docs[0], Rule):
        raise UnsupportedRule("expected a single detection rule")
    return docs[0]


def load_rule_file(path: Path) -> Rule:
    return load_rule(path.read_text(encoding="utf-8"), path)


def _meta(doc: dict[str, Any], path: Path | None) -> dict[str, Any]:
    def opt(key: str) -> str | None:
        value = doc.get(key)
        return str(value) if value is not None else None

    return {
        "title": str(doc.get("title") or (path.stem if path else "untitled")),
        "id": opt("id"),
        "level": opt("level"),
        "name": opt("name"),
        "path": path,
    }


def _rule(doc: dict[str, Any], path: Path | None) -> Rule:
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise RuleError("missing 'detection' section")

    condition = detection.get("condition")
    if isinstance(condition, str):
        conditions: tuple[str, ...] = (condition,)
    elif isinstance(condition, list) and condition and all(isinstance(c, str) for c in condition):
        conditions = tuple(condition)
    else:
        raise RuleError("missing or invalid 'detection.condition'")

    searches = {str(k): v for k, v in detection.items() if k not in ("condition", "timeframe")}
    if not searches:
        raise RuleError("detection has no searches")

    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, dict):
        raise RuleError("'logsource' must be a map")

    rule = Rule(
        searches=searches,
        conditions=conditions,
        logsource={str(k): str(v) for k, v in logsource.items() if v is not None},
        **_meta(doc, path),
    )
    if not any("|" in c for c in conditions):
        return rule
    if len(conditions) != 1:
        raise UnsupportedRule("aggregations need a single condition")
    base, aggregation = (part.strip() for part in conditions[0].split("|", 1))
    timeframe = detection.get("timeframe")
    rule = replace(rule, conditions=(base,))
    return replace(rule, aggregation=_aggregation(rule, aggregation, timeframe))


def _aggregation(rule: Rule, text: str, timeframe: Any) -> Correlation:
    m = AGGREGATION.match(text)
    if not m:
        raise UnsupportedRule(f"aggregation {text!r} is not supported (only count)")
    by = tuple(g.strip() for g in m["by"].split(",")) if m["by"] else ()
    return Correlation(
        title=rule.title,
        id=rule.id,
        level=rule.level,
        type="value_count" if m["field"] else "event_count",
        rules=(rule.ref,),
        group_by=by,
        timespan=_timespan(timeframe) if timeframe is not None else None,
        condition=((LEGACY_OPS[m["op"]], float(m["value"])),),
        field=m["field"] or None,
        path=rule.path,
    )


def _correlation(doc: dict[str, Any], path: Path | None) -> Correlation:
    spec = doc["correlation"]
    if not isinstance(spec, dict):
        raise RuleError("'correlation' must be a map")
    kind = spec.get("type")
    if kind not in CORRELATION_TYPES:
        raise UnsupportedRule(f"correlation type {kind!r} is not supported")

    rules = spec.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not isinstance(rules, list) or not rules:
        raise RuleError("correlation needs a list of 'rules'")
    if kind == "temporal_ordered" and len(rules) < 2:
        raise RuleError("a temporal_ordered correlation needs two or more rules")

    group_by = spec.get("group-by") or []
    if isinstance(group_by, str):
        group_by = [group_by]

    raw_condition = spec.get("condition") or {}
    if not isinstance(raw_condition, dict):
        raise RuleError("correlation 'condition' must be a map")
    value_field = raw_condition.get("field", spec.get("field"))
    condition: list[tuple[str, float]] = []
    if kind == "temporal_ordered":
        # The order of the events is the condition; the spec has no count for it,
        # and silently ignoring one would make a rule mean something else.
        if raw_condition:
            raise RuleError("a temporal_ordered correlation takes no condition")
        if value_field:
            raise RuleError("a temporal_ordered correlation counts no field")
    else:
        for op, value in raw_condition.items():
            if op == "field":
                continue
            if op not in OPS or isinstance(value, bool) or not isinstance(value, int | float):
                raise RuleError(f"invalid correlation condition {op}: {value!r}")
            condition.append((op, float(value)))
        if kind == "temporal" and not condition:
            condition = [("gte", float(len(rules)))]
        if not condition:
            raise RuleError("correlation needs a condition")
        if kind in ("value_count", "value_sum", "value_avg") and not value_field:
            raise RuleError(f"{kind} correlations need a condition field")

    aliases = spec.get("aliases") or {}
    if not isinstance(aliases, dict) or not all(isinstance(v, dict) for v in aliases.values()):
        raise RuleError("correlation 'aliases' must map names to {rule: field}")

    timespan = spec.get("timespan")
    return Correlation(
        type=kind,
        rules=tuple(str(r) for r in rules),
        group_by=tuple(str(g) for g in group_by),
        timespan=_timespan(timespan) if timespan is not None else None,
        condition=tuple(condition),
        field=str(value_field) if value_field else None,
        aliases={str(k): {str(r): str(f) for r, f in v.items()} for k, v in aliases.items()},
        generate=bool(spec.get("generate", False)),
        **_meta(doc, path),
    )


def _timespan(value: Any) -> int:
    m = TIMESPAN.match(str(value))
    if not m:
        raise RuleError(f"invalid timespan {value!r}; use e.g. 30s, 5m, 1h, 1d")
    return int(m[1]) * UNIT[m[2]]
