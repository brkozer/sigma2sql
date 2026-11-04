"""Run many rules over log files with DuckDB, no database server needed."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from sigma2sql.collection import Collection
from sigma2sql.correlation import correlation_query
from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.rule import Correlation, Document
from sigma2sql.sql import Target, literal, to_query

LEVELS = ("critical", "high", "medium", "low", "informational")
TABLE = "events"
COLUMN = "data"


@dataclass
class Hit:
    rule: Document
    count: int
    examples: list[str] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return LEVELS.index(self.rule.level) if self.rule.level in LEVELS else len(LEVELS)


@dataclass
class Report:
    events: int
    hits: list[Hit]
    ran: int
    skipped: list[tuple[Document, str]]


def connect() -> Any:
    try:
        import duckdb
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise SystemExit("sigma2sql hunt needs DuckDB: pip install 'sigma2sql[duckdb]'") from exc
    con = duckdb.connect()
    con.create_function("cidr_match", _cidr_match, ["VARCHAR", "VARCHAR"], "BOOLEAN")
    con.execute(f"CREATE TABLE {TABLE} ({COLUMN} JSON)")
    return con


def load_logs(con: Any, paths: list[str]) -> int:
    """Load JSON/JSON Lines, Parquet or CSV files (globs allowed) as one JSON object per row."""
    for path in paths:
        source = literal(path)
        suffix = Path(path).suffix.lower()
        if suffix == ".parquet":
            select = f"SELECT to_json(t) FROM read_parquet({source}) t"
        elif suffix in (".csv", ".tsv"):
            select = f"SELECT to_json(t) FROM read_csv_auto({source}) t"
        elif suffix in (".json", ".jsonl", ".ndjson"):
            select = f"SELECT json FROM read_json_objects({source}, format = 'auto')"
        else:
            raise ValueError(f"{path}: expected .json, .jsonl, .ndjson, .parquet or .csv")
        con.execute(f"INSERT INTO {TABLE} {select}")
    count: int = con.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]
    return count


def hunt(
    rules: Collection, paths: list[str], base: Target | None = None, examples: int = 0
) -> Report:
    """Run every rule and correlation in `rules` over the logs in `paths`.

    `base` carries the field mapping and timestamp settings; table and dialect are set here.
    """
    con = connect()
    events = load_logs(con, paths)
    target = replace(base or Target(), dialect="duckdb", table=TABLE, json_column=COLUMN)
    items: list[Document] = [*rules.standalone(), *rules.correlations]
    hits: list[Hit] = []
    skipped: list[tuple[Document, str]] = []
    for item in items:
        try:
            query, as_rows = _query(item, rules, target)
        except (RuleError, UnsupportedRule) as exc:
            skipped.append((item, str(exc)))
            continue
        count = con.execute(f"SELECT COUNT(*) FROM ({query}) q").fetchone()[0]
        if not count:
            continue
        sample: list[str] = []
        if examples:
            shown = f"SELECT CAST(to_json(q) AS VARCHAR) FROM ({query}) q" if as_rows else query
            sample = [row[0] for row in con.execute(f"{shown} LIMIT {examples}").fetchall()]
        hits.append(Hit(item, count, sample))
    hits.sort(key=lambda h: (h.rank, -h.count, h.rule.title))
    return Report(events, hits, len(items) - len(skipped), skipped)


def _query(item: Document, rules: Collection, target: Target) -> tuple[str, bool]:
    """The SQL for one item and whether it returns result rows rather than events."""
    if isinstance(item, Correlation):
        return correlation_query(item, rules.resolve(item), target), True
    if item.aggregation is not None:
        return to_query(item, target), True
    return to_query(item, target, columns=f"CAST({COLUMN} AS VARCHAR)"), False


def _cidr_match(value: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(network)
    except ValueError:
        return False
