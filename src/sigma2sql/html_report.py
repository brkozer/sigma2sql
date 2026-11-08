"""A `hunt` report as one HTML file that needs no network and runs no script.

Everything shown comes from rules or logs, and logs can be written by an attacker, so every
value goes through `_text` and the page forbids scripts and outside requests.
"""

from __future__ import annotations

import html
import json
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
OPEN_LEVELS = ("critical", "high")
# The most serious matches start open, but not so many that the page is one long scroll.
MAX_OPEN = 20
# A shell-expanded glob can name hundreds of files, which must not push the summary away.
MAX_LOGS_SHOWN = 5
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

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --panel: #fff; --text: #1c2128; --muted: #5b6673; --line: #dfe3e8;
  --code: #f0f2f5; --critical: #a4133c; --high: #c2410c; --medium: #a16207; --low: #1d4ed8;
  --informational: #4b5563; --unset: #6b7280;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1318; --panel: #171c23; --text: #e4e8ed; --muted: #98a4b3; --line: #2b333d;
    --code: #10151b; --critical: #fb7185; --high: #fb923c; --medium: #facc15; --low: #60a5fa;
    --informational: #a8b3c0; --unset: #a8b3c0;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 1000px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 10px; }
a { color: inherit; }
code, pre { font-family: ui-monospace, "Cascadia Code", Consolas, Menlo, monospace; }
.muted { color: var(--muted); }
.logs { margin: 8px 0 0; padding: 0; list-style: none; font-size: 13px; overflow-wrap: anywhere; }
details.files { background: none; border: 0; margin: 8px 0 0; font-size: 13px; }
details.files summary { display: list-item; padding: 0; color: var(--muted); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px; margin: 24px 0 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 14px; }
.card b { display: block; font-size: 24px; line-height: 1.2; }
.card span { color: var(--muted); font-size: 13px; }
.levels { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0 0; }
.levels a { text-decoration: none; font-size: 13px; padding: 2px 10px; border-radius: 99px;
  border: 1px solid currentColor; }
.critical { color: var(--critical); } .high { color: var(--high); }
.medium { color: var(--medium); } .low { color: var(--low); }
.informational { color: var(--informational); } .unset { color: var(--unset); }
details { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  margin: 0 0 8px; }
summary { cursor: pointer; padding: 10px 14px; display: flex; gap: 12px; align-items: baseline; }
summary .title { flex: 1; font-weight: 600; overflow-wrap: anywhere; }
summary .count { font-variant-numeric: tabular-nums; white-space: nowrap; }
.body { border-top: 1px solid var(--line); padding: 12px 14px; }
.body p { margin: 0 0 10px; overflow-wrap: anywhere; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 3px 14px; margin: 0 0 12px;
  font-size: 13px; }
dt { color: var(--muted); } dd { margin: 0; overflow-wrap: anywhere; }
dd ul { margin: 0; padding: 0; list-style: none; }
.tag { display: inline-block; background: var(--code); border-radius: 4px; padding: 0 6px;
  margin: 0 4px 2px 0; }
pre { background: var(--code); border-radius: 6px; padding: 10px 12px; margin: 0 0 8px;
  font-size: 12.5px; line-height: 1.45; white-space: pre-wrap; overflow-wrap: anywhere;
  max-height: 420px; overflow: auto; }
h3 { font-size: 13px; color: var(--muted); font-weight: 600; margin: 12px 0 6px; }
.plain { list-style: none; margin: 0; padding: 0; font-size: 13px; }
.plain li { padding: 6px 0; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
footer { margin-top: 40px; font-size: 13px; color: var(--muted); }
@media print {
  body { background: #fff; } pre { max-height: none; }
  details::details-content { content-visibility: visible; display: block; }
}
"""


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


def _hit(hit: Hit, opened: bool, budget: list[int]) -> str:
    rule = hit.rule
    level = _level(hit)
    is_result = isinstance(rule, Correlation) or rule.aggregation is not None
    noun = ("result" if is_result else "event") + ("" if hit.count == 1 else "s")
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
        rows.append(("Tags", "".join(f'<span class="tag">{_text(t)}</span>' for t in rule.tags)))
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
    shown = ""
    if examples:
        shown = f"<h3>First matches, {len(examples)} of {hit.count:,}</h3>" + "".join(examples)
    if len(examples) < len(hit.examples):
        shown += '<p class="muted">More examples left out: the report reached its size limit.</p>'
    description = f"<p>{_text(rule.description)}</p>" if rule.description else ""
    return (
        f"<details{' open' if opened else ''}><summary>"
        f'<span class="title">{_text(rule.title)}</span>'
        f'<span class="count {level}">{hit.count:,} {noun}</span></summary>'
        f'<div class="body">{description}<dl>{meta}</dl>{shown}</div></details>'
    )


def _card(value: int, label: str) -> str:
    return f'<div class="card"><b>{value:,}</b><span>{label}</span></div>'


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
    budget = [MAX_EXAMPLES_TOTAL]
    first = {id(h) for h in [h for h in report.hits if _level(h) in OPEN_LEVELS][:MAX_OPEN]}
    links = "".join(
        f'<a class="{level}" href="#level-{level}">{level} {len(hits)}</a>'
        for level, hits in groups.items()
    )
    sections = "".join(
        f'<h2 id="level-{level}" class="{level}">{level.capitalize()}</h2>'
        + "".join(_hit(h, id(h) in first, budget) for h in hits)
        for level, hits in groups.items()
    )
    if not report.hits:
        verdict = "No rule matched these logs."
        if not report.ran:
            couldnt = report.skipped or load_errors
            verdict = "No rule could run." if couldnt else "No rule applies to these logs."
        sections = f'<h2>Matches</h2><p class="muted">{verdict}</p>'
    skipped = [(str(i.path or i.title), why) for i, why in report.skipped]
    skipped += [(str(path), why) for path, why in load_errors]
    other = ""
    if report.warnings:
        rows = "".join(f"<li>{_text(w)}</li>" for w in report.warnings)
        other += f'<h2>Warnings</h2><ul class="plain">{rows}</ul>'
    if skipped:
        rows = "".join(
            f'<li><code>{_text(what)}</code><br><span class="muted">{_text(why)}</span></li>'
            for what, why in skipped
        )
        other += (
            f"<h2>Rules skipped</h2><details><summary>"
            f'<span class="title">{len(skipped):,} {"rule" if len(skipped) == 1 else "rules"}'
            " did not run</span></summary>"
            f'<div class="body"><ul class="plain">{rows}</ul></div></details>'
        )
    log_list = (
        f'<ul class="logs muted">{"".join(f"<li><code>{_text(p)}</code></li>" for p in logs)}</ul>'
    )
    if len(logs) > MAX_LOGS_SHOWN:
        log_list = (
            f'<details class="files"><summary>{len(logs):,} log paths</summary>{log_list}</details>'
        )
    when = generated.strftime("%Y-%m-%d %H:%M UTC")
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>sigma2sql hunt report</title><style>{_STYLE}</style></head><body><main>"
        f'<h1>Hunt report</h1><div class="muted">{when}</div>'
        f"{log_list}"
        '<div class="cards">'
        f"{_card(report.events, 'events read')}{_card(report.ran, 'rules run')}"
        f"{_card(len(report.hits), 'rules matched')}{_card(len(skipped), 'rules skipped')}"
        f"{_card(report.other_logs, 'for other log sources')}</div>"
        f'<div class="levels">{links}</div>{sections}{other}'
        f"<footer>Written by sigma2sql {_text(version)}.</footer>"
        "</main></body></html>\n"
    )
