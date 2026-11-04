"""Compile Sigma search identifiers (the maps and lists under `detection`) into Expr trees."""

from __future__ import annotations

import base64
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
# Text encodings applied before base64; `utf16` adds the little-endian byte order mark.
ENCODINGS = {"wide": "utf-16-le", "utf16le": "utf-16-le", "utf16be": "utf-16-be", "utf16": "utf-16"}
BASE64 = {"base64", "base64offset"}
KNOWN = (
    POSITION
    | set(COMPARE)
    | set(ENCODINGS)
    | BASE64
    | {"all", "cased", "windash", "re", "i", "cidr", "exists", "fieldref"}
)
# Modifiers that make sense on keywords (searches over the whole event).
KEYWORD_MODS = POSITION | set(ENCODINGS) | BASE64 | {"all", "cased", "windash", "re", "i"}

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
    name, *mods = key.split("|")
    for mod in mods:
        if mod not in KNOWN:
            raise UnsupportedRule(f"modifier {mod!r} is not supported")
    # `'|all': [a, b]` is a keyword search: no field, matched anywhere in the event.
    field: str | None = name or None
    label = name or "keywords"
    if field is None:
        extra = [m for m in mods if m not in KEYWORD_MODS]
        if extra:
            raise UnsupportedRule(f"modifier {extra[0]!r} is not supported on keywords")

    values = value if isinstance(value, list) else [value]
    if not values:
        raise RuleError(f"field {label!r} has an empty value list")
    for v in values:
        if not _is_scalar(v):
            raise RuleError(f"field {label!r} has a nested value")

    items: list[Expr]
    if field is None and "re" in mods:
        items = [Regex(None, _as_text(v), ignore_case="i" in mods) for v in values]
    elif field is None:
        items = [
            _strings(None, v, mods, "contains", "cased" in mods) for v in values if v is not None
        ]
        if len(items) != len(values):
            raise RuleError("keywords cannot be null")
    elif "exists" in mods:
        if len(values) != 1 or not isinstance(values[0], bool):
            raise RuleError(f"{field}|exists expects true or false")
        return Exists(field, values[0])
    elif "fieldref" in mods:
        items = [FieldRef(field, _as_text(v)) for v in values]
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
            _value(field, v, mods, position[0] if position else None, "cased" in mods)
            for v in values
        ]

    return all_of(items) if "all" in mods else any_of(items)


def _value(field: str, value: Any, mods: list[str], position: str | None, cased: bool) -> Expr:
    if value is None:
        return NullMatch(field)
    is_number = isinstance(value, int | float) and not isinstance(value, bool)
    if is_number and not position and not (set(mods) & (BASE64 | {"windash"})):
        return NumMatch(field, value)
    return _strings(field, value, mods, position, cased)


def _strings(
    field: str | None, value: Any, mods: list[str], position: str | None, cased: bool
) -> Expr:
    """Match a string value after windash/encoding/base64 transformations."""
    raw = _as_text(value)
    encoding = [m for m in mods if m in ENCODINGS]
    b64 = [m for m in mods if m in BASE64]
    if len(encoding) > 1 or len(b64) > 1:
        raise RuleError(f"{field or 'keywords'} has conflicting encoding modifiers")
    if encoding and not b64:
        raise UnsupportedRule(f"{encoding[0]} is only supported together with base64")

    patterns: list[SigmaString]
    if b64:
        plain = SigmaString.parse(raw)
        if plain.has_wildcards:
            raise UnsupportedRule("base64 modifiers cannot encode wildcards")
        data = _encode(plain.text, ENCODINGS[encoding[0]] if encoding else None)
        encoded = [base64.b64encode(data).decode()] if b64[0] == "base64" else _offsets(data)
        # Encoded text is literal and case-sensitive.
        patterns = [SigmaString((e,)) for e in encoded]
        cased = True
    else:
        variants = _windash(raw) if "windash" in mods else [raw]
        patterns = [SigmaString.parse(v) for v in variants]

    before = position in ("contains", "endswith")
    after = position in ("contains", "startswith")
    return any_of([StrMatch(field, p.wrap(before=before, after=after), cased) for p in patterns])


def _encode(text: str, encoding: str | None) -> bytes:
    if encoding == "utf-16":
        return b"\xff\xfe" + text.encode("utf-16-le")
    return text.encode(encoding or "utf-8")


def _offsets(data: bytes) -> list[str]:
    """The three base64 forms of `data` at byte offsets 0, 1 and 2 inside a longer blob,
    trimmed to the characters that do not depend on the surrounding bytes."""
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for i in range(3):
        encoded = base64.b64encode(i * b" " + data).decode()
        out.append(encoded[start[i] : end[(len(data) + i) % 3]])
    return out


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
