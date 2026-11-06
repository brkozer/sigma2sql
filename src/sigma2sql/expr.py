"""Dialect-independent match tree that detections compile into."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Literal


class Wildcard(Enum):
    MANY = "*"
    ONE = "?"


Part = str | Wildcard


@dataclass(frozen=True)
class SigmaString:
    parts: tuple[Part, ...]

    @classmethod
    def parse(cls, raw: str) -> SigmaString:
        """Split a Sigma value into literals and wildcards.

        `\\*`, `\\?` and `\\\\` are escapes; any other backslash is literal.
        """
        parts: list[Part] = []
        buf: list[str] = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == "\\" and i + 1 < len(raw) and raw[i + 1] in "*?\\":
                buf.append(raw[i + 1])
                i += 2
                continue
            if ch in "*?":
                if buf:
                    parts.append("".join(buf))
                    buf = []
                parts.append(Wildcard(ch))
            else:
                buf.append(ch)
            i += 1
        if buf:
            parts.append("".join(buf))
        return cls(tuple(parts))

    def wrap(self, *, before: bool, after: bool) -> SigmaString:
        parts = list(self.parts)
        if before and parts[:1] != [Wildcard.MANY]:
            parts.insert(0, Wildcard.MANY)
        if after and parts[-1:] != [Wildcard.MANY]:
            parts.append(Wildcard.MANY)
        return SigmaString(tuple(parts))

    @property
    def has_wildcards(self) -> bool:
        return any(isinstance(p, Wildcard) for p in self.parts)

    @property
    def text(self) -> str:
        """Literal text; only meaningful when there are no wildcards."""
        return "".join(p for p in self.parts if isinstance(p, str))


@dataclass(frozen=True)
class StrMatch:
    field: str | None  # None means a keyword search over the whole event
    value: SigmaString
    cased: bool = False


@dataclass(frozen=True)
class NumMatch:
    field: str
    value: int | float


@dataclass(frozen=True)
class NullMatch:
    field: str


@dataclass(frozen=True)
class Exists:
    field: str
    exists: bool


@dataclass(frozen=True)
class Regex:
    field: str | None  # None means the whole event
    pattern: str
    flags: str = ""  # any of i, m, s, as in Python's re


@dataclass(frozen=True)
class Cidr:
    field: str
    network: str


@dataclass(frozen=True)
class Compare:
    field: str
    op: Literal["<", "<=", ">", ">="]
    value: int | float


@dataclass(frozen=True)
class TimePart:
    field: str
    part: Literal["minute", "hour", "day", "week", "month", "year"]
    value: int


@dataclass(frozen=True)
class FieldRef:
    field: str
    other: str


@dataclass(frozen=True)
class And:
    items: tuple[Expr, ...]


@dataclass(frozen=True)
class Or:
    items: tuple[Expr, ...]


@dataclass(frozen=True)
class Not:
    item: Expr


Expr = (
    StrMatch
    | NumMatch
    | NullMatch
    | Exists
    | Regex
    | Cidr
    | Compare
    | TimePart
    | FieldRef
    | And
    | Or
    | Not
)


def regexes(expr: Expr) -> Iterator[Regex]:
    match expr:
        case Regex():
            yield expr
        case And(items) | Or(items):
            for item in items:
                yield from regexes(item)
        case Not(item):
            yield from regexes(item)


def all_of(items: list[Expr]) -> Expr:
    return items[0] if len(items) == 1 else And(tuple(items))


def any_of(items: list[Expr]) -> Expr:
    return items[0] if len(items) == 1 else Or(tuple(items))
