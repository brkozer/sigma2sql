"""SQL for correlation rules and legacy `| count()` aggregations.

Counts (`event_count`, `value_count`, `value_sum`, `value_avg`) and unordered sequences
(`temporal`) share one `base` CTE and an aggregate. Ordered sequences (`temporal_ordered`)
join one filtered copy of `base` per step instead, because the order is the condition.

Every referenced rule contributes rows to a `base` CTE (rule name, event time, group-by
values, the counted field). Without a timespan the result is a plain GROUP BY. With one,
each event closes a window `[t - timespan, t]` of its group; the window's events are found
with a self-join, which works the same on SQLite, PostgreSQL and DuckDB and allows
COUNT(DISTINCT ...), which window functions do not.
"""

from __future__ import annotations

from sigma2sql.rule import OPS, Correlation, Rule
from sigma2sql.sql import Renderer, Target, literal, quote_ident, source


def correlation_query(corr: Correlation, rules: list[Rule], target: Target) -> str:
    r = Renderer(target)
    groups = [quote_ident(f"g{i}") for i in range(len(corr.group_by))]

    branches: list[str] = []
    # A rule listed twice (`rules: [logon, logoff, logon]`) is one source of events, not two:
    # a branch per entry made every event count twice in `event_count` and `value_sum`.
    seen: set[str] = set()
    for rule in rules:
        if rule.ref in seen:
            continue
        seen.add(rule.ref)
        cols = [f"{literal(rule.ref)} AS sigma_rule", f"{r.epoch()} AS sigma_ts"]
        for name, alias in zip(corr.group_by, groups, strict=True):
            sigma_field = corr.aliases.get(name, {}).get(rule.ref, name)
            cols.append(f"{r.column(sigma_field)} AS {alias}")
        if corr.field:
            cols.append(f"{r.column(corr.field)} AS sigma_value")
        table, where = source(rule, target)
        branches.append(f"SELECT {', '.join(cols)} FROM {table} WHERE {where}")
    base = "\n  UNION ALL\n  ".join(branches)

    if corr.type == "temporal_ordered":
        return _ordered_query(corr, rules, r, groups, base)

    def aggregate(b: str) -> str:
        if corr.type == "event_count":
            return "COUNT(*)"
        if corr.type == "value_count":
            return f"COUNT(DISTINCT {b}sigma_value)"
        if corr.type == "temporal":
            return f"COUNT(DISTINCT {b}sigma_rule)"
        fn = "SUM" if corr.type == "value_sum" else "AVG"
        return f"{fn}({r.cast_number(b + 'sigma_value')})"

    def having(b: str) -> str:
        agg = aggregate(b)
        return " AND ".join(f"{agg} {OPS[op]} {_number(v)}" for op, v in corr.condition)

    def named(prefix: str) -> list[str]:
        pairs = zip(groups, corr.group_by, strict=True)
        return [f"{prefix}{g} AS {quote_ident(name)}" for g, name in pairs]

    if corr.timespan is None:
        select = named("") + [
            f"{r.from_epoch('MIN(sigma_ts)')} AS first_seen",
            f"{r.from_epoch('MAX(sigma_ts)')} AS last_seen",
            f"{aggregate('')} AS value",
        ]
        group_by = f"\nGROUP BY {', '.join(groups)}" if groups else ""
        return (
            f"WITH base AS (\n  {base}\n)\n"
            f"SELECT {', '.join(select)}\nFROM base{group_by}\nHAVING {having('')}"
        )

    window_keys = [*groups, "sigma_ts"]
    join = [r.same(f"b.{g}", f"w.{g}") for g in groups]
    join.append(f"b.sigma_ts BETWEEN w.sigma_ts - {corr.timespan} AND w.sigma_ts")
    select = named("w.") + [
        f"{r.from_epoch('MIN(b.sigma_ts)')} AS window_start",
        f"{r.from_epoch('w.sigma_ts')} AS window_end",
        f"{aggregate('b.')} AS value",
    ]
    return (
        f"WITH base AS (\n  {base}\n),\n"
        f"windows AS (SELECT DISTINCT {', '.join(window_keys)} FROM base"
        f" WHERE sigma_ts IS NOT NULL)\n"
        f"SELECT {', '.join(select)}\n"
        f"FROM windows w JOIN base b ON {' AND '.join(join)}\n"
        f"GROUP BY {', '.join('w.' + k for k in window_keys)}\n"
        f"HAVING {having('b.')}"
    )


def _number(value: float) -> str:
    return str(int(value)) if value.is_integer() else repr(value)


def _ordered_query(
    corr: Correlation, rules: list[Rule], r: Renderer, groups: list[str], base: str
) -> str:
    """The first time each group saw the rules' events in the order `rules` lists them.

    One row per group: the earliest complete sequence and its window. Each rule is a filtered
    copy of `base`; a chain is a join of those copies where every step is later than the one
    before it and no step is older than the timespan before the first. That is plain joins, so
    it runs the same on all three databases.
    """
    steps = []
    for i, rule in enumerate(rules):
        kept = ", ".join([*groups, "sigma_ts AS ts"])
        steps.append(
            f"step{i} AS (SELECT {kept} FROM base\n"
            f"  WHERE sigma_rule = {literal(rule.ref)} AND sigma_ts IS NOT NULL)"
        )

    joins: list[str] = []
    for i in range(1, len(rules)):
        # Group values must be equal for every step; the chain is then ordered and bounded.
        on = [r.same(f"t{i}.{g}", f"t0.{g}") for g in groups]
        on.append(f"t{i}.ts > t{i - 1}.ts")
        if corr.timespan is not None:
            on.append(f"t{i}.ts <= t0.ts + {corr.timespan}")
        joins.append(f"\n  JOIN step{i} t{i} ON {' AND '.join(on)}")

    last = len(rules) - 1
    selected = [*(f"t0.{g}" for g in groups), "t0.ts AS start_ts", f"MIN(t{last}.ts) AS end_ts"]
    grouped = [*(f"t0.{g}" for g in groups), "t0.ts"]
    chains = (
        f"chains AS (\n  SELECT {', '.join(selected)}\n  FROM step0 t0{''.join(joins)}"
        f"\n  GROUP BY {', '.join(grouped)})"
    )
    # The earliest sequence of each group; without group-by there is one group.
    partition = f"PARTITION BY {', '.join(groups)} " if groups else ""
    ranked = (
        "ranked AS (\n  SELECT chains.*,"
        f" ROW_NUMBER() OVER ({partition}ORDER BY start_ts) AS rn\n  FROM chains)"
    )
    out = [f"{g} AS {quote_ident(name)}" for g, name in zip(groups, corr.group_by, strict=True)]
    out += [
        f"{r.from_epoch('start_ts')} AS window_start",
        f"{r.from_epoch('end_ts')} AS window_end",
        f"{len(rules)} AS value",
    ]
    return (
        f"WITH base AS (\n  {base}\n),\n"
        + ",\n".join([*steps, chains, ranked])
        + f"\nSELECT {', '.join(out)}\nFROM ranked WHERE rn = 1"
    )
