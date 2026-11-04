"""Load many rule files and resolve the rules that correlations refer to."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.rule import Correlation, Rule, load_file


@dataclass
class Collection:
    rules: list[Rule] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)

    @classmethod
    def load(cls, paths: Iterable[Path]) -> Collection:
        col = cls()
        for path in rule_files(paths):
            try:
                docs = load_file(path)
            except (RuleError, UnsupportedRule, OSError) as exc:
                col.errors.append((path, str(exc)))
                continue
            for doc in docs:
                if isinstance(doc, Correlation):
                    col.correlations.append(doc)
                else:
                    col.rules.append(doc)
        return col

    def resolve(self, corr: Correlation) -> list[Rule]:
        """The rules a correlation counts over, looked up by name or id."""
        index: dict[str, Rule] = {}
        for rule in self.rules:
            for key in (rule.name, rule.id):
                if key:
                    index.setdefault(key, rule)
        missing = [r for r in corr.rules if r not in index]
        if missing:
            raise RuleError(f"correlation refers to unknown rules: {', '.join(missing)}")
        return [index[r] for r in corr.rules]

    def standalone(self) -> list[Rule]:
        """Rules that produce results of their own.

        A rule used by a correlation only feeds that correlation unless the correlation
        sets `generate: true`, as in the Sigma specification.
        """
        hidden = {ref for c in self.correlations if not c.generate for ref in c.rules}
        return [r for r in self.rules if not ({r.name, r.id} & hidden)]


def rule_files(paths: Iterable[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix in (".yml", ".yaml"))
        else:
            yield path
