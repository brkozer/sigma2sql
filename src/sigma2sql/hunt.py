"""Run many rules over log files with DuckDB, no database server needed."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.rule import Rule
from sigma2sql.sql import Target, literal, to_query

LEVELS = ("critical", "high", "medium", "low", "informational")
TABLE = "events"
COLUMN = "data"


@dataclass
class Hit:
    rule: Rule
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
    skipped: list[tuple[Rule, str]]


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
    rules: list[Rule],
    paths: list[str],
    mapping: Mapping[str, str] | None = None,
    examples: int = 0,
) -> Report:
    con = connect()
    events = load_logs(con, paths)
    target = Target("duckdb", TABLE, dict(mapping or {}), json_column=COLUMN)
    hits: list[Hit] = []
    skipped: list[tuple[Rule, str]] = []
    for rule in rules:
        try:
            query = to_query(rule, target, columns=f"CAST({COLUMN} AS VARCHAR)")
        except (RuleError, UnsupportedRule) as exc:
            skipped.append((rule, str(exc)))
            continue
        count = con.execute(f"SELECT COUNT(*) FROM ({query})").fetchone()[0]
        if count:
            sample = con.execute(f"{query} LIMIT {examples}").fetchall() if examples else []
            hits.append(Hit(rule, count, [row[0] for row in sample]))
    hits.sort(key=lambda h: (h.rank, -h.count, h.rule.title))
    return Report(events, hits, len(rules) - len(skipped), skipped)


def _cidr_match(value: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(network)
    except ValueError:
        return False
