"""Compile Sigma search identifiers (the maps and lists under `detection`) into Expr trees."""

from __future__ import annotations

import ipaddress
from typing import Any, Literal

from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.expr import (
    Cidr,
    Compare,
    Exists,
    Expr,
    FieldRef,
    NullMatch,
    NumMatch,
    Regex,
    SigmaString,
    StrMatch,
    all_of,
    any_of,
)

POSITION = {"contains", "startswith", "endswith"}
COMPARE: dict[str, Literal["<", "<=", ">", ">="]] = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
KNOWN = (
    POSITION | set(COMPARE) | {"all", "cased", "windash", "re", "i", "cidr", "exists", "fieldref"}
)

# Characters Windows command-line tools accept in place of a leading dash.
WINDASH = ("-", "/", "–", "—", "―")


def compile_search(name: str, value: Any) -> Expr:
    if isinstance(value, dict):
        return _compile_map(name, value)
    if isinstance(value, list) and value:
        if all(isinstance(v, dict) for v in value):
            return any_of([_compile_map(name, v) for v in value])
        if all(_is_scalar(v) for v in value):
            return any_of([_keyword(name, v) for v in value])
    if _is_scalar(value) and value is not None:
        return _keyword(name, value)
    raise RuleError(f"search {name!r} must be a map, a list of maps or a list of keywords")


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _keyword(name: str, value: Any) -> Expr:
    if value is None:
        raise RuleError(f"search {name!r} has a null keyword")
    # Keywords match anywhere in the event, so they behave like `contains`.
    return StrMatch(None, SigmaString.parse(_as_text(value)).wrap(before=True, after=True))


def _compile_map(name: str, mapping: dict[Any, Any]) -> Expr:
    if not mapping:
        raise RuleError(f"search {name!r} is an empty map")
    return all_of([_compile_field(str(key), value) for key, value in mapping.items()])


def _compile_field(key: str, value: Any) -> Expr:
    field, *mods = key.split("|")
    if not field:
        raise UnsupportedRule("keyword lists with modifiers are not supported")
    for mod in mods:
        if mod not in KNOWN:
            raise UnsupportedRule(f"modifier {mod!r} is not supported")

    values = value if isinstance(value, list) else [value]
    if not values:
        raise RuleError(f"field {field!r} has an empty value list")
    for v in values:
        if not _is_scalar(v):
            raise RuleError(f"field {field!r} has a nested value")

    if "exists" in mods:
        if len(values) != 1 or not isinstance(values[0], bool):
            raise RuleError(f"{field}|exists expects true or false")
        return Exists(field, values[0])

    if "fieldref" in mods:
        items: list[Expr] = [FieldRef(field, _as_text(v)) for v in values]
    elif "re" in mods:
        items = [Regex(field, _as_text(v), ignore_case="i" in mods) for v in values]
    elif "cidr" in mods:
        items = [Cidr(field, _network(field, v)) for v in values]
    elif compare := [m for m in mods if m in COMPARE]:
        if len(compare) > 1:
            raise RuleError(f"field {field!r} has more than one comparison modifier")
        items = [Compare(field, COMPARE[compare[0]], _number(field, v)) for v in values]
    else:
        position = [m for m in mods if m in POSITION]
        if len(position) > 1:
            raise RuleError(f"field {field!r} has more than one of contains/startswith/endswith")
        items = [
            _value(field, v, position[0] if position else None, "windash" in mods, "cased" in mods)
            for v in values
        ]

    return all_of(items) if "all" in mods else any_of(items)


def _value(field: str, value: Any, position: str | None, windash: bool, cased: bool) -> Expr:
    if value is None:
        return NullMatch(field)
    is_number = isinstance(value, int | float) and not isinstance(value, bool)
    if is_number and not position and not windash:
        return NumMatch(field, value)

    raw = _as_text(value)
    variants = _windash(raw) if windash else [raw]
    matches: list[Expr] = []
    for variant in variants:
        s = SigmaString.parse(variant)
        s = s.wrap(
            before=position in ("contains", "endswith"),
            after=position in ("contains", "startswith"),
        )
        matches.append(StrMatch(field, s, cased))
    return any_of(matches)


def _windash(raw: str) -> list[str]:
    """Return one variant per dash character, replacing every dash that starts a word."""
    out: list[str] = []
    for dash in WINDASH:
        chars = list(raw)
        for i, ch in enumerate(chars):
            if ch == "-" and (i == 0 or chars[i - 1] == " "):
                chars[i] = dash
        variant = "".join(chars)
        if variant not in out:
            out.append(variant)
    return out


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _number(field: str, value: Any) -> int | float:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return value
    raise RuleError(f"field {field!r} needs a number for comparison, got {value!r}")


def _network(field: str, value: Any) -> str:
    try:
        return str(ipaddress.ip_network(_as_text(value), strict=False))
    except ValueError as exc:
        raise RuleError(f"field {field!r} has an invalid CIDR {value!r}") from exc
