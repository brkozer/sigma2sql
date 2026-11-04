from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sigma2sql.condition import compile_condition
from sigma2sql.detection import compile_search
from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.expr import Expr, any_of


@dataclass(frozen=True)
class Rule:
    title: str
    id: str | None
    level: str | None
    searches: dict[str, Any]
    conditions: tuple[str, ...]
    path: Path | None = field(default=None, compare=False)

    def compile(self) -> Expr:
        """Build the match tree. Searches the condition never uses are not compiled."""
        cache: dict[str, Expr] = {}

        def resolve(name: str) -> Expr:
            if name not in cache:
                cache[name] = compile_search(name, self.searches[name])
            return cache[name]

        names = list(self.searches)
        return any_of([compile_condition(c, names, resolve) for c in self.conditions])


def load_rule(text: str, path: Path | None = None) -> Rule:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RuleError(f"invalid YAML: {exc}") from exc
    if len(docs) != 1:
        raise UnsupportedRule("multi-document rule collections are not supported")
    doc = docs[0]
    if not isinstance(doc, dict):
        raise RuleError("a rule must be a YAML map")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise RuleError("missing 'detection' section")
    if "timeframe" in detection:
        raise UnsupportedRule("timeframe rules are not supported")

    condition = detection.get("condition")
    if isinstance(condition, str):
        conditions: tuple[str, ...] = (condition,)
    elif isinstance(condition, list) and condition and all(isinstance(c, str) for c in condition):
        conditions = tuple(condition)
    else:
        raise RuleError("missing or invalid 'detection.condition'")

    searches = {str(k): v for k, v in detection.items() if k != "condition"}
    if not searches:
        raise RuleError("detection has no searches")

    rule_id = doc.get("id")
    level = doc.get("level")
    return Rule(
        title=str(doc.get("title") or (path.stem if path else "untitled")),
        id=str(rule_id) if rule_id is not None else None,
        level=str(level) if level is not None else None,
        searches=searches,
        conditions=conditions,
        path=path,
    )


def load_rule_file(path: Path) -> Rule:
    return load_rule(path.read_text(encoding="utf-8"), path)
