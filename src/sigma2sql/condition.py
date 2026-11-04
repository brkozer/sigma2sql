"""Parse `detection.condition` and resolve it into a single Expr.

Grammar (lowest precedence first):

    expr    := and ("or" and)*
    and     := not ("and" not)*
    not     := "not" not | primary
    primary := "(" expr ")" | quant "of" target | IDENT
    quant   := "1" | "all"
    target  := "them" | IDENT        (IDENT may contain * wildcards)
"""

from __future__ import annotations

import re
from collections.abc import Callable

from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.expr import Expr, Not, all_of, any_of

TOKEN = re.compile(r"\s*(?:(\()|(\))|(\|)|([A-Za-z0-9_*.\-]+))")
KEYWORDS = {"and", "or", "not", "of", "them", "all"}

Resolve = Callable[[str], Expr]


def compile_condition(condition: str, names: list[str], resolve: Resolve) -> Expr:
    parser = _Parser(_tokenize(condition), names, resolve)
    expr = parser.expr()
    if parser.peek() is not None:
        raise RuleError(f"unexpected {parser.peek()!r} in condition {condition!r}")
    return expr


def _tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    text = condition.rstrip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise RuleError(f"cannot parse condition {condition!r} at {text[pos:]!r}")
        if m.group(3):
            raise UnsupportedRule("aggregations after '|' in the condition are not supported")
        tokens.append(m.group(1) or m.group(2) or m.group(4))
        pos = m.end()
    if not tokens:
        raise RuleError("empty condition")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: list[str], resolve: Resolve) -> None:
        self.tokens = tokens
        self.pos = 0
        self.names = names
        self.resolve = resolve

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _keyword(self, word: str) -> bool:
        tok = self.peek()
        if tok is not None and tok.lower() == word:
            self.pos += 1
            return True
        return False

    def _take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise RuleError("condition ends too early")
        self.pos += 1
        return tok

    def expr(self) -> Expr:
        items = [self._and()]
        while self._keyword("or"):
            items.append(self._and())
        return any_of(items)

    def _and(self) -> Expr:
        items = [self._not()]
        while self._keyword("and"):
            items.append(self._not())
        return all_of(items)

    def _not(self) -> Expr:
        if self._keyword("not"):
            return Not(self._not())
        return self._primary()

    def _primary(self) -> Expr:
        tok = self._take()
        if tok == "(":
            inner = self.expr()
            if self._take() != ")":
                raise RuleError("missing ')' in condition")
            return inner
        if tok == "1" or tok.lower() == "all":
            if not self._keyword("of"):
                raise RuleError(f"expected 'of' after {tok!r}")
            matched = [self.resolve(n) for n in self._targets(self._take())]
            return any_of(matched) if tok == "1" else all_of(matched)
        if tok == ")" or tok.lower() in KEYWORDS:
            raise RuleError(f"unexpected {tok!r} in condition")
        if tok not in self.names:
            raise RuleError(f"condition refers to unknown search {tok!r}")
        return self.resolve(tok)

    def _targets(self, target: str) -> list[str]:
        if target.lower() == "them":
            found = [n for n in self.names if not n.startswith("_")]
        else:
            pattern = re.compile("^" + ".*".join(map(re.escape, target.split("*"))) + "$")
            found = [n for n in self.names if pattern.match(n)]
        if not found:
            raise RuleError(f"'{target}' does not match any search")
        return found
