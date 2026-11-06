"""SQL for correlation rules and legacy `| count()` aggregations.

Every referenced rule contributes rows to a `base` CTE (rule name, event time, group-by
values, the counted field). Without a timespan the result is a plain GROUP BY. With one,
each event closes a window `[t - timespan, t]` of its group; the window's events are found
with a self-join, which works the same on every database and allows
COUNT(DISTINCT ...), which window functions do not.

`temporal_ordered` follows the steps one CTE at a time instead and gives a row for every start
time of a complete sequence in a group, so repeated attacks are all reported.
"""

from __future__ import annotations

from collections.abc import Callable

from sigma2sql.rule import OPS, Correlation, Rule
from sigma2sql.sql import Renderer, Target, quote_ident, source


def correlation_query(corr: Correlation, rules: list[Rule], target: Target) -> str:
    r = Renderer(target)
    groups = [quote_ident(f"g{i}") for i in range(len(corr.group_by))]

    branches: list[str] = []
    # A rule listed twice must not count its events twice.
    for rule in {id(rule): rule for rule in rules}.values():
        cols = [f"{r.lit(rule.ref)} AS sigma_rule", f"{r.epoch()} AS sigma_ts"]
        for name, alias in zip(corr.group_by, groups, strict=True):
            sigma_field = corr.aliases.get(name, {}).get(rule.ref, name)
            cols.append(f"{r.column(sigma_field)} AS {alias}")
        if corr.field:
            cols.append(f"{r.column(corr.field)} AS sigma_value")
        table, where = source(rule, target)
        branches.append(f"SELECT {', '.join(cols)} FROM {table} WHERE {where}")
    base = "\n  UNION ALL\n  ".join(branches)

    def aggregate(b: str) -> str:
        if corr.type == "event_count":
            return "COUNT(*)"
        if corr.type == "value_count":
            return f"COUNT(DISTINCT {b}sigma_value)"
        if corr.type == "temporal":
            return f"COUNT(DISTINCT {b}sigma_rule)"
        value = r.cast_number(b + "sigma_value")
        if corr.type == "value_median":
            return r.percentile(value, 0.5)
        if corr.type == "value_percentile":
            assert corr.percentile is not None
            return r.percentile(value, corr.percentile / 100)
        return f"{'SUM' if corr.type == 'value_sum' else 'AVG'}({value})"

    def having(b: str) -> str:
        agg = aggregate(b)
        return " AND ".join(f"{agg} {OPS[op]} {_number(v)}" for op, v in corr.condition)

    def named(prefix: str) -> list[str]:
        pairs = zip(groups, corr.group_by, strict=True)
        return [f"{prefix}{g} AS {quote_ident(name)}" for g, name in pairs]

    if corr.timespan is None and corr.type != "temporal_ordered":
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

    if corr.type == "temporal_ordered":
        return _ordered(corr, rules, r, base, groups, named)

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


def _ordered(
    corr: Correlation,
    rules: list[Rule],
    r: Renderer,
    base: str,
    groups: list[str],
    named: Callable[[str], list[str]],
) -> str:
    """One CTE per step keeps one row per start: only the earliest next event is kept, which
    can do no worse than a later one, so the rows stay few however dense the events are.

    A step is no earlier than the step before it and within the timespan of the first. Equal
    timestamps count as in order, since logs often only have whole seconds, but a rule that
    comes back needs a later event than its last step, or one event would fill both."""
    names = ", ".join(groups + ["sigma_ts AS t0"])
    steps = [
        f"s0 AS (SELECT DISTINCT {names} FROM base"
        f" WHERE sigma_rule = {r.lit(rules[0].ref)} AND sigma_ts IS NOT NULL)"
    ]
    for i, rule in enumerate(rules[1:], 1):
        kept = [*(f"p.{g} AS {g}" for g in groups), *(f"p.t{j} AS t{j}" for j in range(i))]
        keys = [*(f"p.{g}" for g in groups), *(f"p.t{j}" for j in range(i))]
        on = [f"e.sigma_rule = {r.lit(rule.ref)}"]
        on += [r.same(f"e.{g}", f"p.{g}") for g in groups]
        on.append(f"e.sigma_ts >= p.t{i - 1}")
        same = [j for j in range(i) if rules[j].ref == rule.ref]
        if same:
            on.append(f"e.sigma_ts > p.t{same[-1]}")
        if corr.timespan is not None:
            on.append(f"e.sigma_ts <= p.t0 + {corr.timespan}")
        steps.append(
            f"s{i} AS (SELECT {', '.join(kept)}, MIN(e.sigma_ts) AS t{i}"
            f" FROM s{i - 1} p JOIN base e ON {' AND '.join(on)}"
            f" GROUP BY {', '.join(keys)})"
        )
    last = len(rules) - 1
    select = named("") + [
        f"{r.from_epoch('t0')} AS window_start",
        f"{r.from_epoch(f't{last}')} AS window_end",
        f"{len(rules)} AS value",
    ]
    return (
        f"WITH base AS (\n  {base}\n),\n" + ",\n".join(steps) + "\n"
        f"SELECT {', '.join(select)}\nFROM s{last}"
    )


def _number(value: float) -> str:
    return str(int(value)) if value.is_integer() else repr(value)
