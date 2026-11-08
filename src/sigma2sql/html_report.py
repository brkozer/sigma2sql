"""A `hunt` report as one HTML file that needs no network and runs no script.

Everything shown comes from rules or logs, and logs can be written by an attacker, so every
value goes through `_text` and the page forbids scripts and outside requests.
"""

from __future__ import annotations

import html
import json
import math
import re
import unicodedata
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from sigma2sql.hunt import LEVELS, Hit, Report
from sigma2sql.rule import Correlation

# Longest example shown, in characters; a few events can hold megabytes of script block text.
MAX_EXAMPLE = 20000
# A shell-expanded glob can name hundreds of files, which must not push the summary away.
MAX_LOGS_SHOWN = 5
_SHORT = {
    "critical": "crit",
    "high": "high",
    "medium": "med",
    "low": "low",
    "informational": "info",
    "unset": "none",
}
_NAME = {**{level: level.capitalize() for level in LEVELS}, "unset": "No level"}
# In the order an intrusion goes through them.
TACTICS = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "defense-evasion",  # split into the two above by ATT&CK; older rules still use it
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
_TECHNIQUE = re.compile(r"attack\.t\d{4}(\.\d{3})?")
# Characters of examples kept in total; past it the rest of the page lists matches only.
MAX_EXAMPLES_TOTAL = 20_000_000
# Everything that is not plain text is looked at; what displays as nothing, or changes how the
# text around it is displayed, is written out, since logs must not get to do either.
_NOT_PLAIN = re.compile("[^\t\n\x20-\x7e]")
_HIDDEN_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
_BLANK = frozenset(
    "\u034f\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180e\u180f\u2800\u3164\uffa0"
    + "".join(map(chr, range(0xFE00, 0xFE10)))
    + "".join(map(chr, range(0xE0100, 0xE01F0)))
)

_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

_RING = "box-shadow: 0 0 0 2px var(--bg), 0 0 0 4px var(--ink);"
_FILTER_STYLE = "".join(
    f"#f-{name}:checked ~ .panel label[for=f-{name}] {{ {_RING} }}\n"
    + (
        f"#f-{name}:checked ~ .list .rule:not(.{name}) {{ display: none; }}\n"
        if name != "all"
        else ""
    )
    for name in ("all", *LEVELS, "unset")
) + "".join(
    f"#t-{name}:checked ~ .panel label[for=t-{name}] {{ outline: 2px solid var(--ink);"
    " outline-offset: -2px; }\n"
    + (
        f"#t-{name}:checked ~ .list .rule:not(.tc-{name}) {{ display: none; }}\n"
        if name != "all"
        else ""
    )
    for name in ("all", *TACTICS)
)

_STYLE = (
    """
:root {
  color-scheme: light dark;
  --bg: #f1f3f6; --row: #fff; --open: #e9edf2; --line: #dce1e8; --ink: #1d2733; --soft: #647284;
  --code: #e4e9ef; --on: #141a22; --heat: #3f7bf0;
  --critical: #ff5c86; --high: #ff9a3d; --medium: #ffd23f; --low: #6cc4ff;
  --informational: #b8c4d2; --unset: #b8c4d2;
  --ui: "Segoe UI Variable Text", "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto,
    "Noto Sans", Ubuntu, sans-serif;
  --mono: "Cascadia Mono", "SF Mono", ui-monospace, Consolas, "DejaVu Sans Mono", monospace;
  --cols: 4.6rem 5.4rem minmax(0, 1fr) 9.5rem;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1f27; --row: #212731; --open: #2a313d; --line: #323a46; --ink: #dde3ea;
    --soft: #93a0b0; --code: #161b22; --heat: #4f8dff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 13.5px/1.45 var(--ui); font-variant-numeric: tabular-nums; }
main { max-width: 90rem; margin: 0 auto; }
a { color: inherit; text-underline-offset: .15em; }
code, pre { font-family: var(--mono); }
code { font-size: .92em; overflow-wrap: anywhere; }
.critical { --level: var(--critical); } .high { --level: var(--high); }
.medium { --level: var(--medium); } .low { --level: var(--low); }
.informational { --level: var(--informational); } .unset { --level: var(--unset); }

header { display: flex; flex-wrap: wrap; align-items: baseline; gap: .2rem 1.6rem;
  padding: .85rem 1rem .6rem; }
h1 { font-size: 15px; font-weight: 650; margin: 0; }
.facts { display: flex; flex-wrap: wrap; gap: .1rem 1.25rem; margin: 0; padding: 0;
  list-style: none; color: var(--soft); }
.facts b { color: var(--ink); font-weight: 600; }
.files { padding: 0 1rem .5rem; color: var(--soft); }
.files summary { cursor: pointer; }
.files ul, .logs { list-style: none; margin: .25rem 0 0; padding: 0; }
.files ul { max-height: 14rem; overflow: auto; }
.logs { padding: 0 1rem .5rem; color: var(--soft); }

.pick { position: absolute; opacity: 0; pointer-events: none; }
.pick:focus-visible ~ .panel { outline: 2px solid var(--low); outline-offset: -2px; }
.panel { padding: .2rem 1rem 1rem; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(7rem, 1fr)); gap: .4rem; }
.tiles label { cursor: pointer; padding: .55rem .8rem .6rem; color: var(--on);
  background: var(--level); }
.tiles label.all { background: var(--row); color: var(--ink); }
.tiles b { display: block; font-size: 1.95rem; line-height: 1.15; font-weight: 650; }
.panel h2 { font-size: inherit; font-weight: 400; color: var(--soft); margin: .95rem 0 .35rem; }
.strip { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(min-content, 1fr);
  gap: 2px; overflow-x: auto; }
.strip label, .strip .none { min-height: 4.3rem; padding: .4rem .5rem; font-size: 11.5px;
  line-height: 1.2;
  background: color-mix(in srgb, var(--heat) var(--x, 0%), var(--row)); }
.strip label { cursor: pointer; }
.strip label:hover { outline: 1px solid var(--soft); outline-offset: -1px; }
.strip .none { color: var(--soft); }
.strip b { display: block; font-size: 1.3rem; line-height: 1.2; font-weight: 600; }
.head { position: sticky; top: 0; z-index: 2; background: var(--bg); }
.cols { display: grid; grid-template-columns: var(--cols); padding: .25rem 1rem;
  color: var(--soft); border-block: 1px solid var(--line); }
.cols span:nth-child(2) { text-align: right; padding-right: 1.1rem; }

.rule { background: var(--row); border-bottom: 1px solid var(--line); }
.rule.critical { background: color-mix(in srgb, var(--critical) 13%, var(--row)); }
.rule.high { background: color-mix(in srgb, var(--high) 7%, var(--row)); }
.rule > summary { display: grid; grid-template-columns: var(--cols); align-items: center;
  padding: .32rem 1rem; cursor: pointer; list-style: none; }
.rule > summary::-webkit-details-marker { display: none; }
.rule > summary:hover, .rule[open] > summary { background: var(--open); }
.rule > summary:focus-visible { outline: 2px solid var(--low); outline-offset: -2px; }
.sev { justify-self: start; min-width: 3.1rem; text-align: center; padding: 0 .35rem;
  background: var(--level); color: var(--on); font-weight: 600; font-size: 12px; }
.hits { position: relative; text-align: right; padding-right: 1.1rem; font-weight: 600; }
.hits::before { content: ""; position: absolute; left: 0; right: 1.1rem; bottom: 0; height: 3px;
  background: linear-gradient(90deg, var(--level) var(--w), transparent var(--w)); }
.name { overflow-wrap: anywhere; padding-right: 1rem; }
.kind { color: var(--soft); margin-left: .6em; }
.tech { color: var(--soft); font-family: var(--mono); font-size: .9em; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; }

.body { display: grid; grid-template-columns: minmax(0, 24rem) minmax(0, 1fr); gap: 1.4rem;
  padding: .7rem 1rem 1rem calc(4.6rem + 1rem); background: var(--open);
  border-left: 3px solid var(--level); }
.about p { margin: 0 0 .7rem; overflow-wrap: anywhere; }
dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .1rem .9rem;
  margin: 0; }
dt { color: var(--soft); }
dd { margin: 0; overflow-wrap: anywhere; }
dd ul, .plain { list-style: none; margin: 0; padding: 0; }
h3 { font-size: inherit; font-weight: 400; color: var(--soft); margin: 0 0 .3rem; }
pre { background: var(--code); margin: 0 0 .5rem; padding: .55rem .7rem; font-size: 12px;
  line-height: 1.45; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 22rem;
  overflow: auto; }
.quiet { color: var(--soft); margin: 0; }
.empty { padding: 2.5rem 1rem; font-size: 15px; background: var(--row); margin: 0; }
h2 { font-size: 14px; font-weight: 600; margin: 1.5rem 1rem .4rem; }
.notes { background: var(--row); padding: .3rem 1rem; }
.plain li { padding: .25rem 0; overflow-wrap: anywhere; }
.skipped { padding: .4rem 1rem; background: var(--row); }
.skipped > summary { cursor: pointer; }
footer { padding: 1.1rem 1rem 2rem; color: var(--soft); }

@media (max-width: 760px) {
  :root { --cols: 3.5rem 3.2rem minmax(0, 1fr); }
  .tech, .cols span:nth-child(4) { display: none; }
  .hits, .cols span:nth-child(2) { padding-right: .7rem; }
  .hits::before { right: .7rem; }
  .body { grid-template-columns: minmax(0, 1fr); padding-left: 1rem; }
}
@media print {
  :root { --bg: #fff; --row: #fff; --open: #fff; --code: #fff; --ink: #000; --soft: #444; }
  * { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  .head { position: static; } pre { max-height: none; }
  details::details-content { content-visibility: visible; display: block; }
}
"""
    + _FILTER_STYLE
)


def _text(value: object) -> str:
    return html.escape(_NOT_PLAIN.sub(_visible, str(value)), quote=True)


def _visible(match: re.Match[str]) -> str:
    char = match[0]
    if char in _BLANK or unicodedata.category(char) in _HIDDEN_CATEGORIES:
        return f"\\u{ord(char):04x}"
    return char


class _NotExact(ValueError):
    """Parsing and printing this event would change what it says."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise _NotExact  # the query may have matched the value that would be dropped
    return dict(pairs)


def _exact_int(text: str) -> int:
    value = int(text)
    if str(value) != text:
        raise _NotExact
    return value


def _inexact(_: str) -> Any:
    raise _NotExact


def _pretty(event: str) -> str:
    if len(event) > MAX_EXAMPLE * 2:  # indenting it first can take gigabytes to keep 20000
        return f"{event[:MAX_EXAMPLE]}\n... cut at {MAX_EXAMPLE} characters"
    try:
        parsed = json.loads(
            event,
            object_pairs_hook=_pairs,
            parse_float=_inexact,
            parse_int=_exact_int,
            parse_constant=_inexact,
        )
        event = json.dumps(parsed, indent=2, ensure_ascii=False)
    except (ValueError, RecursionError):
        pass  # the event as it was written
    if len(event) > MAX_EXAMPLE:
        return f"{event[:MAX_EXAMPLE]}\n... cut at {MAX_EXAMPLE} characters"
    return event


def _level(hit: Hit) -> str:
    return LEVELS[hit.rank] if hit.rank < len(LEVELS) else "unset"


def _reference(url: str) -> str:
    if url[:8].lower().startswith(("https://", "http://")):
        return f'<a href="{_text(url)}" rel="noreferrer noopener">{_text(url)}</a>'
    return _text(url)


def _items(values: Sequence[str], render: type[str] | object = _text) -> str:
    assert callable(render)
    return "<ul>" + "".join(f"<li>{render(v)}</li>" for v in values) + "</ul>"


def _count(number: int, noun: str) -> str:
    return f"{number:,} {noun}{'' if number == 1 else 's'}"


def _techniques(tags: Sequence[str]) -> str:
    found = [t[7:].upper() for t in tags if _TECHNIQUE.fullmatch(t.lower())]
    return " ".join(found[:2])


def _tactics(tags: Sequence[str]) -> list[str]:
    named = {t.lower().removeprefix("attack.") for t in tags if t.lower().startswith("attack.")}
    return [t for t in TACTICS if t in named]


def _hit(hit: Hit, top: float, budget: list[int]) -> str:
    rule = hit.rule
    level = _level(hit)
    is_result = isinstance(rule, Correlation) or rule.aggregation is not None
    rows: list[tuple[str, str]] = []
    if rule.level and rule.level != level:
        rows.append(("Level", _text(rule.level)))
    if isinstance(rule, Correlation):
        rows.append(("Correlation", _text(rule.type)))
    if rule.id:
        rows.append(("Rule id", f"<code>{_text(rule.id)}</code>"))
    if rule.path:
        rows.append(("File", f"<code>{_text(rule.path)}</code>"))
    if rule.tags:
        rows.append(("Tags", _text(", ".join(rule.tags))))
    if rule.falsepositives:
        rows.append(("False positives", _items(rule.falsepositives)))
    if rule.references:
        rows.append(("References", _items(rule.references, _reference)))
    meta = "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in rows)
    examples: list[str] = []
    for event in hit.examples:
        block = f"<pre>{_text(_pretty(event))}</pre>"
        if len(block) > budget[0]:
            break
        budget[0] -= len(block)
        examples.append(block)
    proof = ""
    if examples:
        noun = "results" if is_result else "matches"
        proof = f"<h3>First {noun}, {len(examples)} of {hit.count:,}</h3>" + "".join(examples)
    if len(examples) < len(hit.examples):
        proof += '<p class="quiet">More examples left out: the report reached its size limit.</p>'
    description = f"<p>{_text(rule.description)}</p>" if rule.description else ""
    kind = '<span class="kind">correlation</span>' if is_result else ""
    width = round(100 * math.log1p(hit.count) / top)
    classes = " ".join([level, *(f"tc-{t}" for t in _tactics(rule.tags))])
    return (
        f'<details class="rule {classes}"><summary>'
        f'<span class="sev">{_SHORT[level]}</span>'
        f'<span class="hits" style="--w:{width}%">{hit.count:,}</span>'
        f'<span class="name">{_text(rule.title)}{kind}</span>'
        f'<span class="tech">{_text(_techniques(rule.tags))}</span></summary>'
        f'<div class="body"><div class="about">{description}<dl>{meta}</dl></div>'
        f'<div class="proof">{proof}</div></div></details>'
    )


def _panel(groups: dict[str, list[Hit]], hits: Sequence[Hit]) -> tuple[str, str]:
    """Radio buttons and the labels that pick them. CSS alone hides the rows, so no script runs."""
    pick = '<input class="pick" type="radio" name="{}" id="{}"{}>'
    picks = pick.format("level", "f-all", " checked")
    tiles = f'<label for="f-all" class="all"><b>{len(hits):,}</b>All rules</label>'
    for level, group in groups.items():
        picks += pick.format("level", f"f-{level}", "")
        tiles += (
            f'<label for="f-{level}" class="{level}"><b>{len(group):,}</b>{_NAME[level]}</label>'
        )
    counts = {t: 0 for t in TACTICS}
    for hit in hits:
        for tactic in _tactics(hit.rule.tags):
            counts[tactic] += 1
    busiest = max(counts.values())
    if not busiest:
        return picks, f'<div class="panel"><div class="tiles">{tiles}</div></div>'
    picks += pick.format("tactic", "t-all", " checked")
    cells = '<label for="t-all"><b>Any</b>tactic</label>'
    for tactic, count in counts.items():
        name = tactic.replace("-", " ").capitalize().replace(" and c", " and c")
        if not count and tactic == "defense-evasion":
            continue
        if not count:
            cells += f'<span class="none"><b>0</b>{name}</span>'
            continue
        picks += pick.format("tactic", f"t-{tactic}", "")
        heat = round(12 + 63 * math.sqrt(count / busiest))
        cells += f'<label for="t-{tactic}" style="--x:{heat}%"><b>{count:,}</b>{name}</label>'
    return picks, (
        f'<div class="panel"><div class="tiles">{tiles}</div>'
        f'<h2>Matching rules by ATT&amp;CK tactic</h2><div class="strip">{cells}</div></div>'
    )


def render(
    report: Report,
    load_errors: Sequence[tuple[Path, str]],
    logs: Sequence[str],
    version: str,
    generated: datetime,
) -> str:
    """The whole page. `load_errors` are rule files that never reached the hunt."""
    groups: dict[str, list[Hit]] = {}
    for hit in report.hits:
        groups.setdefault(_level(hit), []).append(hit)
    skipped = [(str(i.path or i.title), why) for i, why in report.skipped]
    skipped += [(str(path), why) for path, why in load_errors]
    budget = [MAX_EXAMPLES_TOTAL]
    if report.hits:
        top = math.log1p(max(h.count for h in report.hits))
        picks, panel = _panel(groups, report.hits)
        rows = "".join(_hit(h, top, budget) for h in report.hits)
        table = (
            f'{picks}{panel}<div class="head">'
            '<div class="cols"><span>Level</span><span>Hits</span><span>Rule</span>'
            f'<span>Technique</span></div></div><div class="list">{rows}</div>'
        )
    else:
        verdict = "No rule matched these logs."
        if not report.ran:
            verdict = "No rule could run." if skipped else "No rule applies to these logs."
        table = f'<p class="empty">{verdict}</p>'
    facts = [
        (report.events, "events"),
        (report.ran, "rules run"),
        (len(report.hits), "matched"),
        (len(skipped), "skipped"),
        (report.other_logs, "for other logs"),
    ]
    fact_items = "".join(f"<li><b>{n:,}</b> {label}</li>" for n, label in facts)
    other = ""
    if report.warnings:
        items = "".join(f"<li>{_text(w)}</li>" for w in report.warnings)
        other += f'<h2>Warnings</h2><div class="notes"><ul class="plain">{items}</ul></div>'
    if skipped:
        items = "".join(
            f'<li><code>{_text(what)}</code><br><span class="quiet">{_text(why)}</span></li>'
            for what, why in skipped
        )
        other += (
            f'<h2>Rules skipped</h2><details class="skipped"><summary>'
            f"{len(skipped):,} {'rule' if len(skipped) == 1 else 'rules'} did not run</summary>"
            f'<ul class="plain">{items}</ul></details>'
        )
    paths = "".join(f"<li><code>{_text(path)}</code></li>" for path in logs)
    log_list = f'<ul class="logs">{paths}</ul>'
    if len(logs) > MAX_LOGS_SHOWN:
        log_list = (
            f'<details class="files"><summary>{_count(len(logs), "log path")}</summary>'
            f"<ul>{paths}</ul></details>"
        )
    when = generated.strftime("%Y-%m-%d %H:%M UTC")
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>sigma2sql hunt report</title><style>{_STYLE}</style></head><body><main>"
        f'<header><h1>Hunt report</h1><ul class="facts">{fact_items}</ul></header>'
        f"{log_list}{table}{other}"
        f"<footer>Written by sigma2sql {_text(version)} on {when}.</footer>"
        "</main></body></html>\n"
    )
