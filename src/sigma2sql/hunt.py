"""Run many rules over log files with DuckDB, no database server needed."""

from __future__ import annotations

import glob
import ipaddress
import json
import tempfile
from collections.abc import Callable, Iterator
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
# EVTX layout: a 4 KiB file header, then 64 KiB chunks.
EVTX_HEADER = 4096
EVTX_CHUNK = 65536
# Damaged chunks reported per file before giving up on the rest of it.
MAX_EVTX_ERRORS = 100


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
    # Rules left out because they are for another product than the profile's logs.
    other_logs: int = 0
    # Logs that could only be read in part.
    warnings: list[str] = field(default_factory=list)


def open_duckdb(path: str = ":memory:", read_only: bool = False) -> Any:
    try:
        import duckdb
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise SystemExit("sigma2sql hunt needs DuckDB: pip install 'sigma2sql[duckdb]'") from exc
    con = duckdb.connect(path, read_only=read_only)
    # A time without a zone must mean the same on every machine, as it does in `test`.
    con.execute("SET TimeZone = 'UTC'")
    con.create_function("cidr_match", _cidr_match, ["VARCHAR", "VARCHAR"], "BOOLEAN")
    return con


def connect() -> Any:
    con = open_duckdb()
    con.execute(f"CREATE TABLE {TABLE} ({COLUMN} JSON)")
    return con


def load_logs(con: Any, paths: list[str], warnings: list[str] | None = None) -> int:
    """Load JSON/JSON Lines, Parquet, CSV or EVTX files (globs allowed), one JSON object per row."""
    warnings = [] if warnings is None else warnings
    for path in paths:
        source = literal(path)
        suffix = Path(path).suffix.lower()
        if suffix == ".evtx":
            _load_evtx(con, path, warnings)
            continue
        if suffix == ".parquet":
            select = f"SELECT to_json(t) FROM read_parquet({source}) t"
        elif suffix in (".csv", ".tsv"):
            select = f"SELECT to_json(t) FROM read_csv_auto({source}) t"
        elif suffix in (".json", ".jsonl", ".ndjson"):
            select = f"SELECT json FROM read_json_objects({source}, format = 'auto')"
        else:
            raise ValueError(f"{path}: expected .json, .jsonl, .ndjson, .parquet, .csv or .evtx")
        con.execute(f"INSERT INTO {TABLE} {select}")
    count: int = con.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]
    if not count and warnings:
        raise ValueError(f"no event could be read: {warnings[0]}")
    return count


def _load_evtx(con: Any, pattern: str, warnings: list[str]) -> None:
    """Windows event logs, in the JSON layout of evtx_dump (see the `evtx` profile).

    Logs from an incident are often damaged, so everything readable is kept and whatever
    could not be read is reported. Only when nothing at all can be read is that an error.
    """
    files = sorted(glob.glob(pattern))
    if not files:
        raise ValueError(f"{pattern}: no such file")
    with tempfile.TemporaryDirectory() as tmp:
        lines = Path(tmp) / "events.jsonl"
        # replace: a lone surrogate has no UTF-8 form and must not end the hunt.
        with lines.open("w", encoding="utf-8", errors="replace") as out:
            for file in files:
                for event in _evtx_events(file, warnings):
                    out.write(event + "\n")
        source = literal(str(lines))
        select = f"SELECT json FROM read_json_objects({source}, format = 'newline_delimited')"
        con.execute(f"INSERT INTO {TABLE} {select}")


def _evtx_events(path: str, warnings: list[str]) -> Iterator[str]:
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise SystemExit("reading .evtx files needs: pip install 'sigma2sql[evtx]'") from exc
    try:
        records: Any = iter(PyEvtxParser(path).records_json())
    except (RuntimeError, OSError) as exc:  # not an EVTX file, or too short to be one
        warnings.append(f"{path}: {exc}")
        return
    # The parser silently drops a chunk that is cut off, so check for that ourselves.
    size = Path(path).stat().st_size
    if size > EVTX_HEADER and (size - EVTX_HEADER) % EVTX_CHUNK:
        warnings.append(f"{path}: file is truncated, events in its last chunk are not read")
    errors = found = 0
    while errors < MAX_EVTX_ERRORS:
        try:
            record = next(records)
        except StopIteration:
            break
        except RuntimeError as exc:  # one damaged chunk; the parser moves on to the next
            errors += 1
            warnings.append(f"{path}: {exc}")
            continue
        found += 1
        yield json.dumps(json.loads(record["data"]), ensure_ascii=False)
    if errors >= MAX_EVTX_ERRORS:
        warnings.append(f"{path}: gave up after {errors} damaged chunks")
    if not found and not errors and size > EVTX_HEADER:
        warnings.append(f"{path}: no events found")


def hunt(
    rules: Collection,
    paths: list[str],
    base: Target | None = None,
    examples: int = 0,
    progress: Callable[[int, int], None] | None = None,
) -> Report:
    """Run every rule and correlation in `rules` over the logs in `paths`.

    `base` carries the field mapping and timestamp settings; table and dialect are set here.
    """
    con = connect()
    warnings: list[str] = []
    events = load_logs(con, paths, warnings)
    base = base or Target()
    # All logs share one table here, so profile routes keep only their conditions.
    routes = tuple(replace(r, table=None) for r in base.routes)
    target = replace(base, dialect="duckdb", table=TABLE, json_column=COLUMN, routes=routes)

    def count(query: str) -> int:
        found: int = con.execute(f"SELECT COUNT(*) FROM ({query}) q").fetchone()[0]
        return found

    def sample(query: str, as_rows: bool) -> list[str]:
        shown = f"SELECT CAST(to_json(q) AS VARCHAR) FROM ({query}) q" if as_rows else query
        return [row[0] for row in con.execute(f"{shown} LIMIT {examples}").fetchall()]

    columns = f"CAST({COLUMN} AS VARCHAR)"
    return run_rules(rules, target, events, warnings, count, sample, columns, examples, progress)


def run_rules(
    rules: Collection,
    target: Target,
    events: int,
    warnings: list[str],
    count: Callable[[str], int],
    sample: Callable[[str, bool], list[str]],
    columns: str,
    examples: int,
    progress: Callable[[int, int], None] | None = None,
) -> Report:
    """Run each rule through `count`, and `sample` the ones that matched."""
    candidates: list[Document] = [*rules.standalone(), *rules.correlations]
    items = [item for item in candidates if _for_these_logs(item, rules, target)]
    hits: list[Hit] = []
    skipped: list[tuple[Document, str]] = []
    for done, item in enumerate(items):
        if progress:
            progress(done, len(items))
        try:
            query, as_rows = _query(item, rules, target, columns)
            found = count(query)
        except (RuleError, UnsupportedRule) as exc:
            skipped.append((item, str(exc)))
            continue
        except Exception as exc:  # the database's own errors: one bad rule must not end the hunt
            skipped.append((item, str(exc).splitlines()[0] if str(exc) else repr(exc)))
            continue
        if not found:
            continue
        shown: list[str] = []
        if examples:
            try:
                shown = sample(query, as_rows)
            except Exception as exc:  # e.g. a time value out of range in one result row
                warnings.append(f"{item.title}: no examples: {str(exc).splitlines()[0]}")
        hits.append(Hit(item, found, shown))
    hits.sort(key=lambda h: (h.rank, -h.count, h.rule.title))
    other_logs = len(candidates) - len(items)
    return Report(events, hits, len(items) - len(skipped), skipped, other_logs, warnings)


def _for_these_logs(item: Document, rules: Collection, target: Target) -> bool:
    """Whether a rule can apply. Without this, a Zeek rule of the form `not <address range>`
    would match every Windows event, as those have no such field."""
    if target.product is None:
        return True
    wanted = target.product.lower()
    if isinstance(item, Correlation):
        try:
            return any(
                r.logsource.get("product", "").lower() == wanted for r in rules.resolve(item)
            )
        except RuleError:
            return True  # reported as skipped when the query is built
    return item.logsource.get("product", "").lower() == wanted


def _query(item: Document, rules: Collection, target: Target, columns: str) -> tuple[str, bool]:
    """The SQL for one item and whether it returns result rows rather than events."""
    if isinstance(item, Correlation):
        return correlation_query(item, rules.resolve(item), target), True
    if item.aggregation is not None:
        return to_query(item, target), True
    return to_query(item, target, columns=columns), False


def _cidr_match(value: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(network)
    except ValueError:
        return False
