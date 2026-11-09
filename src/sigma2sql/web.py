"""`sigma2sql serve`: the same work as the command line, in a page on this machine.

The page handles a database password and shows text from logs an attacker may have written, so
it only listens on the loopback address, every request needs a secret from the start URL, the
Host header is checked against DNS rebinding, and the pages run no script.
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import yaml

from sigma2sql import coverage, database, html_report
from sigma2sql.collection import Collection, rule_files
from sigma2sql.html_report import _text as esc
from sigma2sql.hunt import Report, hunt, parse_since
from sigma2sql.profile import apply_profile, builtin_profiles, load_profile
from sigma2sql.sql import Target

COOKIE = "sigma2sql_session"
MAX_BODY = 1024 * 1024
MAX_FIELDS_SHOWN = 40
MAX_SUGGESTIONS = 3000
EXAMPLES = 5
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)

_STYLE = (
    html_report._STYLE
    + """
main { max-width: 68rem; }
header { padding-bottom: .2rem; }
.steps { list-style: none; display: flex; flex-wrap: wrap; gap: .1rem 1.5rem; margin: 0;
  padding: 0; color: var(--soft); counter-reset: step; }
.steps li { counter-increment: step; }
.steps li::before { content: counter(step) ". "; }
.steps [aria-current] { color: var(--ink); font-weight: 600; }
.page { padding: 1.6rem 1rem 3rem; }
.page h1 { font-size: clamp(1.7rem, 3.6vw, 2.5rem); line-height: 1.18; font-weight: 600;
  letter-spacing: -.012em; margin: 0; max-width: 24em; }
.page h2 { font-size: 1.1rem; font-weight: 600; margin: 2.2rem 0 .15rem; }
.lead { color: var(--soft); margin: .55rem 0 0; max-width: 46em; }
a { text-underline-offset: .18em; }
input[type=text], input[type=password], textarea, select { width: 100%; font: inherit;
  color: var(--ink); background: var(--row); border: 1px solid var(--line);
  padding: .42rem .55rem; }
textarea, .socket input, input.mono { font-family: var(--mono); font-size: 12.5px; }
textarea { min-height: 4.4rem; resize: vertical; }
:focus-visible { outline: 2px solid var(--low); outline-offset: 1px; }
button { font: inherit; font-weight: 600; cursor: pointer; padding: .55rem 1.2rem; color: var(--on);
  background: var(--low); border: 0; }
button.quiet-button { background: var(--ink); color: var(--bg); }
.problem { border-left: 4px solid var(--critical); background: var(--row); padding: .7rem 1rem;
  margin: 0 0 1.4rem; overflow-wrap: anywhere; }

.setup { max-width: 44rem; }
.sources { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; margin: 1.1rem 0 0; }
.sources label { cursor: pointer; padding: .8rem .95rem; background: var(--row);
  border-left: 4px solid var(--line); }
.sources b { display: block; font-size: 1.05rem; font-weight: 600; }
.sources span { color: var(--soft); }
#src-files:checked ~ .sources label[for=src-files],
#src-database:checked ~ .sources label[for=src-database] { border-left-color: var(--low);
  background: var(--open); }
.src:focus-visible ~ .sources { outline: 2px solid var(--low); outline-offset: 2px; }
#src-files:checked ~ .for-database, #src-database:checked ~ .for-files { display: none; }
.field { margin: 1rem 0 0; }
.field > label { display: block; font-weight: 600; margin-bottom: .25rem; }
.hint { color: var(--soft); font-size: 12.5px; margin: .25rem 0 0; }
.pair { display: grid; grid-template-columns: 1fr 1fr; gap: 0 .9rem; }
.more { margin: 1.2rem 0 0; }
.more summary { cursor: pointer; color: var(--soft); }
.go { margin: 1.5rem 0 0; }

.meter { display: flex; height: 1.15rem; margin: 1.5rem 0 .55rem; background: var(--row); }
.meter span { background: var(--level); }
.key { list-style: none; display: flex; flex-wrap: wrap; gap: .2rem 1.6rem; margin: 0; padding: 0; }
.key b { font-weight: 650; }
.key i { display: inline-block; width: .68em; height: .68em; margin-right: .45em;
  background: var(--level); }
.next { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem 1.1rem;
  margin: 1.5rem 0 0; }

.patch { display: grid;
  grid-template-columns: minmax(9rem, 16rem) minmax(0, 1fr) minmax(12rem, 21rem);
  gap: 0 1.1rem; margin-top: .9rem; }
.row { display: contents; }
.row > * { padding: .3rem 0; border-bottom: 1px solid var(--line); }
.want { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; align-self: stretch;
  display: flex; align-items: center; }
.loss { display: flex; align-items: center; gap: .6rem; align-self: stretch; color: var(--soft);
  white-space: nowrap; }
.cable { display: flex; height: .62rem; flex: 0 0 auto; max-width: 70%; }
.cable span { background: var(--level); }
.socket { align-self: stretch; }
.head-row > * { color: var(--soft); border-bottom: 1px solid var(--line); padding: 0 0 .25rem; }
.apply { position: sticky; bottom: 0; background: var(--bg); padding: .8rem 0; margin-top: .2rem; }
.page pre { margin-top: .5rem; }

.running { padding-top: 2.5rem; }
.running progress { display: block; width: 100%; height: .9rem; margin-top: 1.4rem; }
@media (max-width: 720px) {
  .sources, .pair { grid-template-columns: 1fr; }
  .patch { grid-template-columns: minmax(0, 1fr); }
  .head-row { display: none; }
  .want, .loss { border-bottom: 0; padding-bottom: 0; }
  .socket { padding: .25rem 0 .7rem; }
}
"""
)


@dataclass
class Job:
    kind: str
    done: int = 0
    total: int = 0
    error: str | None = None
    finished: bool = False


@dataclass
class App:
    token: str
    rules: str = ""
    form: dict[str, str] = field(default_factory=dict)
    dsn: str = ""
    mapping: dict[str, str] = field(default_factory=dict)
    job: Job | None = None
    coverage: coverage.Coverage | None = None
    report: str | None = None
    problem: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def value(self, name: str, default: str = "") -> str:
        return self.form.get(name, default)

    def source(self) -> str:
        return self.value("source", "database" if self.dsn else "files")

    def logs(self) -> list[str]:
        return [line.strip() for line in self.value("logs").splitlines() if line.strip()]

    def target(self) -> Target:
        target = Target(
            table=self.value("table").strip() or "events",
            mapping=dict(self.mapping),
            json_column=self.value("json_column").strip() or None,
            keyword_column=self.value("keyword_column").strip() or None,
        )
        profile = self.value("profile").strip()
        if (
            not profile
            and self.source() == "files"
            and any(Path(p).suffix.lower() == ".evtx" for p in self.logs())
        ):
            profile = "evtx"
        if profile:
            target = apply_profile(target, load_profile(profile))
        since = self.value("since").strip()
        if since:
            target = replace(target, since=parse_since(since))
        return target

    def collection(self) -> Collection:
        paths = [Path(line.strip()) for line in self.value("rules", self.rules).splitlines()]
        paths = [p for p in paths if str(p) != "."]
        for path in paths:
            if not path.exists():
                raise ValueError(f"{path}: no such file or directory")
        if not any(True for _ in rule_files(paths)):
            raise ValueError("no .yml or .yaml files found in the rule paths")
        return Collection.load(paths)

    def check_source(self) -> None:
        if self.source() == "files" and not self.logs():
            raise ValueError("give at least one log file")
        if self.source() == "database" and not self.dsn:
            raise ValueError("give the database address")

    def start(self, kind: str, work: Callable[[Job], None]) -> None:
        job = Job(kind)
        self.job = job

        def run() -> None:
            try:
                work(job)
            except BaseException as exc:  # SystemExit from a missing driver included
                job.error = database.scrub(str(exc), self.dsn) or repr(exc)
            job.finished = True

        threading.Thread(target=run, daemon=True).start()

    def busy(self) -> bool:
        return self.job is not None and not self.job.finished

    def run_coverage(self, job: Job) -> None:
        col, target = self.collection(), self.target()
        sample = int(self.value("sample", "10000") or 10000)
        if self.source() == "files":
            self.coverage = coverage.of_files(col, self.logs(), sample, target)
        else:
            db = database.connect(self.dsn)
            try:
                self.coverage = coverage.of_database(col, db, sample, target)
            finally:
                db.close()
        if not self.coverage.sampled:
            raise ValueError("no events to look at")

    def run_hunt(self, job: Job) -> None:
        col, target = self.collection(), self.target()

        def progress(done: int, total: int) -> None:
            job.done, job.total = done, total

        result: Report
        if self.source() == "files":
            result = hunt(col, self.logs(), target, EXAMPLES, progress)
            shown = self.logs()
        else:
            db = database.connect(self.dsn)
            try:
                result = database.hunt_database(col, db, target, EXAMPLES, progress)
            finally:
                db.close()
            shown = [database.describe(self.dsn)]
        self.report = html_report.render(
            result, col.errors, shown, version("sigma2sql"), datetime.now(UTC)
        )


STEPS = ("Choose your logs", "Check coverage", "Read the report")


def _layout(title: str, body: str, step: int, refresh: int | None = None) -> str:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    steps = "".join(
        f"<li{' aria-current="step"' if i == step else ''}>{name}</li>"
        for i, name in enumerate(STEPS)
    )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">{meta}'
        f"<title>{esc(title)} - sigma2sql</title><style>{_STYLE}</style></head><body><main>"
        f'<header><h1>sigma2sql</h1><ol class="steps">{steps}</ol></header>'
        f'<div class="page">{body}</div></main></body></html>\n'
    )


def _field(app: App, name: str, label: str, hint: str = "", default: str = "") -> str:
    note = f'<p class="hint">{hint}</p>' if hint else ""
    value = esc(app.value(name, default))
    return (
        f'<div class="field"><label for="{name}">{label}</label>'
        f'<input type="text" id="{name}" name="{name}" value="{value}">{note}</div>'
    )


def setup_page(app: App) -> str:
    problem = f'<p class="problem">{esc(app.problem)}</p>' if app.problem else ""
    source = app.source()
    files = " checked" if source == "files" else ""
    base = " checked" if source == "database" else ""
    chosen = app.value("profile")
    options = "".join(
        f'<option value="{esc(n)}"{" selected" if chosen == n else ""}>{esc(n)}</option>'
        for n in builtin_profiles()
    )
    kept = (
        f"Kept in memory for {esc(database.describe(app.dsn))}. Leave empty to keep using it."
        if app.dsn
        else "postgresql://, clickhouse://, sqlite: or duckdb:. Use a user that can only read."
    )
    return _layout(
        "Choose your logs",
        f"""{problem}<h1>Where are your logs?</h1>
<form class="setup" method="post" action="/coverage">
<input type="hidden" name="csrf" value="{esc(app.token)}">
<input class="pick src" type="radio" name="source" value="files" id="src-files"{files}>
<input class="pick src" type="radio" name="source" value="database" id="src-database"{base}>
<div class="sources">
<label for="src-files"><b>In files</b><span>EVTX, JSON, CSV or Parquet</span></label>
<label for="src-database"><b>In a database</b>
<span>PostgreSQL, ClickHouse, SQLite, DuckDB</span></label>
</div>
<div class="field for-files"><label for="logs">Log files</label>
<textarea id="logs" name="logs">{esc(app.value("logs"))}</textarea>
<p class="hint">One path or glob on each line.</p></div>
<div class="for-database">
<div class="field"><label for="dsn">Database address</label>
<input type="password" id="dsn" name="dsn" autocomplete="off"><p class="hint">{kept}</p></div>
<div class="pair">{_field(app, "table", "Table", default="events")}
{_field(app, "json_column", "JSON column", "Leave empty if each field is a column.")}</div>
</div>
<div class="field"><label for="rules">Rules</label>
<textarea id="rules" name="rules">{esc(app.value("rules", app.rules))}</textarea>
<p class="hint">Files or folders, one on each line.</p></div>
<div class="field"><label for="profile">Log format</label>
<select id="profile" name="profile">
<option value="">Detect or use the field names as they are</option>{options}</select></div>
<details class="more"><summary>More options</summary>
{_field(app, "since", "Only events since", "For example 7d, 12h or 2026-11-01.")}
{_field(app, "sample", "Events to look at for fields", default="10000")}
{_field(app, "keyword_column", "Keyword column", "Only for a table with no JSON column.")}
</details>
<div class="go"><button type="submit">Check coverage</button></div>
</form>""",
        0,
    )


def job_page(job: Job) -> str:
    if job.total:
        title = f"Rule {job.done:,} of {job.total:,}"
        bar = f'<progress max="{job.total}" value="{job.done}"></progress>'
    else:
        title = "Reading your logs"
        bar = "<progress></progress>"
    step = 1 if job.kind == "coverage" else 2
    return _layout(
        title,
        f'<div class="running"><h1>{title}</h1>{bar}'
        '<p class="lead">This page updates by itself.</p></div>',
        step,
        refresh=1,
    )


def _suggest(name: str, seen: set[str]) -> str:
    wanted = re.sub(r"[-_ ]", "", name).lower()
    exact = [s for s in seen if re.sub(r"[-_ ]", "", s.rsplit(".", 1)[-1]).lower() == wanted]
    return min(exact, key=len) if exact else ""


def _headline(blind: int, partial: int, total: int) -> str:
    if blind:
        return f"{blind:,} of {total:,} rules can never match these logs."
    if partial:
        return f"{partial:,} of {total:,} rules are missing some fields."
    return f"All {total:,} rules have the fields they need."


def _patch_row(
    index: int, name: str, blind: int, weak: int, top: int, app: App, seen: set[str]
) -> str:
    count = blind + weak
    width = max(1, round(70 * count / top))
    parts = "".join(
        f'<span class="{level}" style="width:{round(100 * n / count)}%"></span>'
        for level, n in (("critical", blind), ("medium", weak))
        if n
    )
    word = "rule" if count == 1 else "rules"
    value = esc(app.mapping.get(name) or _suggest(name, seen))
    return (
        f'<div class="row"><div class="want">{esc(name)}'
        f'<input type="hidden" name="field{index}" value="{esc(name)}"></div>'
        f'<div class="loss"><div class="cable" style="width:{width}%">{parts}</div>'
        f"{count:,} {word}</div>"
        f'<div class="socket"><input type="text" name="to{index}" list="seen" '
        f'aria-label="Field in your logs for {esc(name)}" value="{value}"></div></div>'
    )


def coverage_page(app: App) -> str:
    result = app.coverage
    assert result is not None
    ready = result.count(coverage.READY)
    partial = result.count(coverage.PARTIAL)
    blind = result.count(coverage.BLIND)
    total = max(ready + partial + blind, 1)
    meter = "".join(
        f'<span class="{level}" style="width:{100 * n / total:.2f}%"></span>'
        for level, n in (("low", ready), ("medium", partial), ("critical", blind))
        if n
    )
    key = "".join(
        f'<li class="{level}"><i></i><b>{n:,}</b> {label}</li>'
        for level, n, label in (
            ("low", ready, "have every field"),
            ("medium", partial, "miss some fields"),
            ("critical", blind, "can never match"),
        )
    )
    missing = result.missing_fields()
    top = max([b + w for _, b, w in missing] or [1])
    rows = "".join(
        _patch_row(i, name, b, w, top, app, result.seen)
        for i, (name, b, w) in enumerate(missing[:MAX_FIELDS_SHOWN])
    )
    options = "".join(
        f'<option value="{esc(name)}">' for name in sorted(result.seen)[:MAX_SUGGESTIONS]
    )
    more = len(missing) - MAX_FIELDS_SHOWN
    extra = f'<p class="hint">{more:,} more fields are not shown.</p>' if more > 0 else ""
    fixes = '<p class="lead">No rule is missing a field.</p>'
    if missing:
        fixes = f"""<h2>Missing fields that cost the most rules</h2>
<p class="lead">If your logs keep one of these under another name, enter it and check again.</p>
<form method="post" action="/map"><input type="hidden" name="csrf" value="{esc(app.token)}">
<datalist id="seen">{options}</datalist>
<div class="patch"><div class="row head-row"><div>Field the rules use</div>
<div>Rules affected</div><div>Field in your logs</div></div>{rows}</div>{extra}
<div class="apply">
<button class="quiet-button" type="submit">Check again with these fields</button></div>
</form>"""
    saved = ""
    if app.mapping:
        text = yaml.safe_dump({"fields": app.mapping}, sort_keys=True, allow_unicode=True)
        saved = (
            "<h2>Your fields, ready to use as a profile</h2>"
            '<p class="lead">Save this as a YAML file and pass it with <code>-p</code>.</p>'
            f"<pre>{esc(text)}</pre>"
        )
    left_out = (
        f" {result.other_logs:,} rules for other log sources are left out."
        if result.other_logs
        else ""
    )
    return _layout(
        "Coverage",
        f"""<h1>{_headline(blind, partial, ready + partial + blind)}</h1>
<div class="meter" aria-hidden="true">{meter}</div>
<ul class="key">{key}</ul>
<p class="lead">Judged from the fields of {result.sampled:,} events.{left_out}</p>
<form class="next" method="post" action="/hunt">
<input type="hidden" name="csrf" value="{esc(app.token)}">
<button type="submit">Run {ready + partial + blind:,} rules</button>
<a href="/">Change the logs or rules</a></form>{fixes}{saved}""",
        1,
    )


def forbidden_host(host: str | None, port: int) -> bool:
    return host not in (f"127.0.0.1:{port}", f"localhost:{port}")


class Handler(BaseHTTPRequestHandler):
    server_version = "sigma2sql"
    sys_version = ""
    app: App
    port: int

    def log_message(self, format: str, *args: Any) -> None:
        pass  # request lines can hold the start URL's secret

    def _send(
        self,
        status: int,
        body: str = "",
        location: str | None = None,
        cookie: str | None = None,
    ) -> None:
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", f"{COOKIE}={cookie}; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def _deny(self) -> None:
        self._send(HTTPStatus.FORBIDDEN, "Open the address that sigma2sql serve printed.")

    def _cookie_ok(self) -> bool:
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE and hmac.compare_digest(value.encode(), self.app.token.encode()):
                return True
        return False

    def do_GET(self) -> None:
        if forbidden_host(self.headers.get("Host"), self.port):
            return self._deny()
        url = urlsplit(self.path)
        offered = parse_qs(url.query).get("token", [""])[0]
        if offered:
            if hmac.compare_digest(offered.encode(), self.app.token.encode()):
                return self._send(HTTPStatus.SEE_OTHER, location=url.path, cookie=self.app.token)
            return self._deny()
        if not self._cookie_ok():
            return self._deny()
        app = self.app
        if url.path == "/":
            return self._send(HTTPStatus.OK, setup_page(app))
        if url.path == "/job":
            return self._job()
        if url.path == "/coverage" and app.coverage is not None:
            return self._send(HTTPStatus.OK, coverage_page(app))
        if url.path == "/report" and app.report is not None:
            return self._send(HTTPStatus.OK, app.report)
        return self._send(
            HTTPStatus.NOT_FOUND, _layout("Not found", '<a href="/">Start again</a>', 0)
        )

    def _job(self) -> None:
        app = self.app
        job = app.job
        if job is None:
            return self._send(HTTPStatus.SEE_OTHER, location="/")
        if not job.finished:
            return self._send(HTTPStatus.OK, job_page(job))
        if job.error:
            app.problem = job.error
            return self._send(HTTPStatus.SEE_OTHER, location="/")
        app.problem = None
        return self._send(
            HTTPStatus.SEE_OTHER, location=f"/{'report' if job.kind == 'hunt' else 'coverage'}"
        )

    def do_POST(self) -> None:
        if forbidden_host(self.headers.get("Host"), self.port) or not self._cookie_ok():
            return self._deny()
        origin = self.headers.get("Origin")
        if origin and forbidden_host(urlsplit(origin).netloc, self.port):
            return self._deny()
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Too large.")
        fields = parse_qs(
            self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True
        )
        form = {name: values[0] for name, values in fields.items()}
        if not hmac.compare_digest(form.get("csrf", "").encode(), self.app.token.encode()):
            return self._deny()
        app = self.app
        path = urlsplit(self.path).path
        with app.lock:
            if app.busy():
                return self._send(HTTPStatus.SEE_OTHER, location="/job")
            if path == "/coverage":
                self._save(form)
                return self._begin("coverage", app.run_coverage)
            if path == "/map":
                self._map(form)
                return self._begin("coverage", app.run_coverage)
            if path == "/hunt":
                return self._begin("hunt", app.run_hunt)
        return self._send(HTTPStatus.NOT_FOUND, "Not found.")

    def _save(self, form: dict[str, str]) -> None:
        app = self.app
        address = form.pop("dsn", "").strip()
        form.pop("csrf", None)
        if address:
            app.dsn = address
        app.form = form

    def _map(self, form: dict[str, str]) -> None:
        for name, value in form.items():
            match = re.fullmatch(r"field(\d+)", name)
            if not match:
                continue
            chosen = form.get(f"to{match[1]}", "").strip()
            if chosen:
                self.app.mapping[value] = chosen
            else:
                self.app.mapping.pop(value, None)

    def _begin(self, kind: str, work: Callable[[Job], None]) -> None:
        app = self.app
        try:
            app.check_source()
        except ValueError as exc:
            app.problem = str(exc)
            return self._send(HTTPStatus.SEE_OTHER, location="/")
        app.problem = None
        app.start(kind, work)
        return self._send(HTTPStatus.SEE_OTHER, location="/job")


def make_server(rules: list[str], port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """A server on the loopback address, and the secret URL that opens it."""
    app = App(
        secrets.token_urlsafe(32), rules="\n".join(rules), dsn=os.environ.get(database.ENV, "")
    )

    class Bound(Handler):
        pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Bound)
    Bound.app = app
    Bound.port = server.server_address[1]
    return server, f"http://127.0.0.1:{Bound.port}/?token={app.token}"


def serve(rules: list[str], port: int, open_browser: bool) -> int:
    server, url = make_server(rules, port)
    print(f"sigma2sql is running at\n\n  {url}\n\nPress Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
