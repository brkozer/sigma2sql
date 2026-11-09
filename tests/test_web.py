from __future__ import annotations

import http.client
import threading
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from time import monotonic, sleep

import pytest

from sigma2sql.web import CSP, Handler, make_server

pytest.importorskip("duckdb")

RULES = """title: ready
level: high
detection: {s: {A: 1}, condition: s}
---
title: needs mapping
level: critical
detection: {s: {ParentImage: x}, condition: s}
"""


class Client:
    def __init__(self, url: str) -> None:
        parts = urllib.parse.urlsplit(url)
        self.port = parts.port
        self.token = urllib.parse.parse_qs(parts.query)["token"][0]
        self.cookie = ""
        self.host = f"127.0.0.1:{self.port}"

    def send(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], str]:
        con = http.client.HTTPConnection("127.0.0.1", self.port)
        sent = {"Host": self.host, **(headers or {})}
        if self.cookie:
            sent["Cookie"] = self.cookie
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            sent["Content-Type"] = "application/x-www-form-urlencoded"
        con.request(method, path, body, sent)
        response = con.getresponse()
        text = response.read().decode()
        got = dict(response.getheaders())
        con.close()
        return response.status, got, text

    def login(self) -> None:
        status, headers, _ = self.send("GET", f"/?token={self.token}")
        assert status == 303
        self.cookie = headers["Set-Cookie"].split(";")[0]

    def post(self, path: str, **form: str) -> str:
        status, headers, _ = self.send("POST", path, {"csrf": self.token, **form})
        assert status == 303
        return headers["Location"]

    def wait(self) -> str:
        end = monotonic() + 30
        while monotonic() < end:
            status, headers, text = self.send("GET", "/job")
            if status == 303:
                return headers["Location"]
            sleep(0.05)
        raise AssertionError("job did not finish")


@pytest.fixture
def client(tmp_path: Path) -> Iterator[Client]:
    server, url = make_server([])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield Client(url)
    server.shutdown()
    server.server_close()


def form(tmp_path: Path, line: str = '{"A": 1, "Parent_Image": "x"}\n') -> dict[str, str]:
    (tmp_path / "r.yml").write_text(RULES)
    (tmp_path / "e.jsonl").write_text(line)
    return {
        "rules": str(tmp_path / "r.yml"),
        "source": "files",
        "logs": str(tmp_path / "e.jsonl"),
        "sample": "100",
    }


def test_nothing_without_the_secret(client: Client) -> None:
    assert client.send("GET", "/")[0] == 403
    assert client.send("GET", "/?token=wrong")[0] == 403
    assert client.send("POST", "/coverage", {"csrf": client.token})[0] == 403


def test_other_hosts_are_refused(client: Client) -> None:
    client.login()
    assert client.send("GET", "/", headers={"Host": "evil.example"})[0] == 403
    assert (
        client.send(
            "GET", f"/?token={client.token}", headers={"Host": f"evil.example:{client.port}"}
        )[0]
        == 403
    )


def test_a_post_needs_the_form_secret_and_origin(client: Client) -> None:
    client.login()
    assert client.send("POST", "/coverage", {"csrf": "no"})[0] == 403
    form_ok = {"csrf": client.token}
    assert client.send("POST", "/coverage", form_ok, {"Origin": "http://evil.example"})[0] == 403


def test_headers_forbid_scripts(client: Client) -> None:
    client.login()
    status, headers, text = client.send("GET", "/")
    assert status == 200 and headers["Content-Security-Policy"] == CSP
    assert "<script" not in text
    assert headers["Referrer-Policy"] == "same-origin"  # no-referrer makes the Origin null


def test_the_cookie_is_http_only() -> None:
    assert (
        "HttpOnly; SameSite=Lax"
        in Path(__import__("sigma2sql.web", fromlist=["x"]).__file__).read_text()
    )


def test_only_loopback_is_used(client: Client) -> None:
    assert Handler.server_version == "sigma2sql"
    server, _ = make_server([])
    assert server.server_address[0] == "127.0.0.1"
    server.server_close()


def test_coverage_mapping_and_hunt(client: Client, tmp_path: Path) -> None:
    client.login()
    assert client.post("/coverage", **form(tmp_path)) == "/job"
    assert client.wait() == "/coverage"
    page = client.send("GET", "/coverage")[2]
    assert "1 of 2 rules can never match" in page and "ParentImage" in page
    assert 'value="Parent_Image"' in page  # offered, because only the separator differs

    assert client.post("/map", field0="ParentImage", to0="Parent_Image") == "/job"
    assert client.wait() == "/coverage"
    page = client.send("GET", "/coverage")[2]
    assert "No rule is missing a field" in page and "ParentImage: Parent_Image" in page

    assert client.post("/hunt") == "/job"
    assert client.wait() == "/report"
    assert "ready" in client.send("GET", "/report")[2]


def test_problems_come_back_to_the_setup(client: Client, tmp_path: Path) -> None:
    client.login()
    values = form(tmp_path)
    values["logs"] = str(tmp_path / "missing.jsonl")
    client.post("/coverage", **values)
    assert client.wait() == "/"
    assert 'class="problem"' in client.send("GET", "/")[2]


def test_a_missing_source_is_a_message(client: Client) -> None:
    client.login()
    assert client.post("/coverage", source="files", rules="x") == "/"
    assert "at least one log file" in client.send("GET", "/")[2]


def test_hostile_field_names_are_escaped(client: Client, tmp_path: Path) -> None:
    client.login()
    attack = "<script>alert(1)</script>"
    values = form(tmp_path, '{"A": 1, "' + attack + '": 2}\n')
    (tmp_path / "r.yml").write_text(
        f'title: t\ndetection: {{s: {{"{attack}x": 1}}, condition: s}}\n'
    )
    client.post("/coverage", **values)
    assert client.wait() == "/coverage"
    page = client.send("GET", "/coverage")[2]
    assert "<script>" not in page and "&lt;script&gt;" in page


def test_the_address_is_never_shown_with_its_password(client: Client, tmp_path: Path) -> None:
    client.login()
    values = form(tmp_path)
    values.update(source="database", dsn="clickhouse://u:hunter2@127.0.0.1:1/x")
    client.post("/coverage", **values)
    assert client.wait() == "/"
    page = client.send("GET", "/")[2]
    assert "hunter2" not in page and "clickhouse://127.0.0.1:1/x" in page
