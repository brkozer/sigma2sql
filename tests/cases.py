"""Behaviour cases shared by the SQLite and PostgreSQL tests.

Each case is (name, detection YAML, events, indexes of the events that must match).
"""

from __future__ import annotations

import base64
from typing import Any

from sigma2sql import Rule, load_rule

Case = tuple[str, str, list[dict[str, Any]], list[int]]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


PROCS = [
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"},
    {"Image": "C:\\Windows\\System32\\CMD.EXE", "CommandLine": "CMD.EXE /C dir"},
    {"Image": "C:\\Tools\\cmd.exe.bak", "CommandLine": "copy a b"},
    {"Image": "C:\\Windows\\notepad.exe"},
]

LINES = [{"A": "one\ntwo"}, {"A": "three"}]
TIMES = [{"When": "2026-11-01T03:12:45Z"}, {"When": "2027-01-01T23:59:00Z"}, {"Other": 1}]

ESCAPED = [
    {"Image": "C:\\Windows\\cmd.exe"},
    {"Line": 'say "hello" now'},
    {"Line": "one\ttwo"},
    {"Line": "first\nsecond"},
    {"Other": "plain"},
]

CASES: list[Case] = [
    (
        "regex word boundaries work on every database",
        "sel: {A|re: '\\bcmd\\b'}\ncondition: sel",
        [{"A": "run cmd now"}, {"A": "runcmdnow"}],
        [0],
    ),
    (
        "a JSON boolean equals the word",
        "sel: {A: 'true'}\ncondition: sel",
        [{"A": True}, {"A": False}, {"A": "true"}],
        [0, 2],
    ),
    (
        "keyword with a backslash finds the value",
        "keywords: ['C:\\Windows\\cmd.exe']\ncondition: keywords",
        ESCAPED,
        [0],
    ),
    (
        "keyword with a wildcard and a backslash",
        "keywords: ['C:\\Win*\\cmd']\ncondition: keywords",
        ESCAPED,
        [0],
    ),
    ("keyword with a quote", "keywords: ['\"hello\"']\ncondition: keywords", ESCAPED, [1]),
    ("keyword with a tab", 'keywords: ["one\\ttwo"]\ncondition: keywords', ESCAPED, [2]),
    ("keyword with a newline", 'keywords: ["first\\nsecond"]\ncondition: keywords', ESCAPED, [3]),
    (
        "keyword with cased and a backslash",
        "keywords:\n  '|cased': ['C:\\Windows']\ncondition: keywords",
        ESCAPED,
        [0],
    ),
    (
        "keyword list longer than one test",
        "keywords: ["
        + ", ".join(f"'C:\\nothing{i}'" for i in range(60))
        + ", 'C:\\Windows']\ncondition: keywords",
        ESCAPED,
        [0],
    ),
    (
        "text that only looks like a number is not one",
        "sel: {Port|lt: 100}\ncondition: sel",
        [
            {"Port": "10.0.0.1"},
            {"Port": "1.2.3"},
            {"Port": "1-2"},
            {"Port": "1e"},
            {"Port": "e5"},
            {"Port": "-e5"},
            {"Port": "1e2e3"},
            {"Port": "50"},
            {"Port": "-5"},
            {"Port": "1e1"},
            {"Port": "1.5"},
            {"Port": "2.5E+1"},
        ],
        [7, 8, 9, 10, 11],
    ),
    (
        "endswith is case-insensitive",
        "sel: {Image|endswith: '\\cmd.exe'}\ncondition: sel",
        PROCS,
        [0, 1],
    ),
    (
        "startswith",
        "sel: {CommandLine|startswith: 'cmd.exe /c'}\ncondition: sel",
        PROCS,
        [0, 1],
    ),
    (
        "contains with a list is OR",
        "sel: {CommandLine|contains: [whoami, ' dir']}\ncondition: sel",
        PROCS,
        [0, 1],
    ),
    (
        "contains|all is AND",
        "sel: {CommandLine|contains|all: [cmd, whoami]}\ncondition: sel",
        PROCS,
        [0],
    ),
    (
        "plain value is an exact, case-insensitive match",
        "sel: {Image: 'c:\\windows\\notepad.exe'}\ncondition: sel",
        PROCS,
        [3],
    ),
    (
        "cased keeps case",
        "sel: {Image|cased|endswith: '\\cmd.exe'}\ncondition: sel",
        PROCS,
        [0],
    ),
    (
        "wildcards in values",
        "sel: {Image: 'C:\\Windows\\System32\\c?d.*'}\ncondition: sel",
        PROCS,
        [0, 1],
    ),
    (
        "not on a missing field still matches",
        "sel: {Image|contains: Windows}\nhas_cmd: {CommandLine|contains: cmd}\n"
        "condition: sel and not has_cmd",
        PROCS,
        [3],
    ),
    (
        "1 of / all of patterns and them",
        "sel_a: {Image|endswith: .exe}\nsel_b: {CommandLine|contains: whoami}\n"
        "_note: {Image|contains: nothing}\ncondition: 1 of sel_* and all of them",
        PROCS,
        [0],
    ),
    (
        "null means the field is missing",
        "sel: {CommandLine: null}\ncondition: sel",
        PROCS,
        [3],
    ),
    (
        "exists",
        "sel: {CommandLine|exists: true}\ncondition: sel",
        PROCS,
        [0, 1, 2],
    ),
    (
        "keywords search the whole event",
        "keywords: [whoami, NOTEPAD]\ncondition: keywords",
        PROCS,
        [0, 3],
    ),
    (
        "escaped wildcard is literal",
        # \\ is a literal backslash and \* a literal star, so this is C:\temp\*.txt exactly.
        "sel: {Path: 'C:\\temp\\\\\\*.txt'}\ncondition: sel",
        [{"Path": "C:\\temp\\*.txt"}, {"Path": "C:\\temp\\a.txt"}, {"Path": "C:\\temp*.txt"}],
        [0],
    ),
    (
        "SQL wildcards in values are literal",
        "sel: {Name|contains: '50%_off'}\ncondition: sel",
        [{"Name": "get 50%_off now"}, {"Name": "get 50XXoff now"}],
        [0],
    ),
    (
        "quotes cannot break out of the literal",
        'sel: {Name: "O\'Brien"}\ncondition: sel',
        [{"Name": "O'Brien"}, {"Name": "OBrien"}],
        [0],
    ),
    (
        "numbers match whether stored as number or string",
        "sel: {EventID: 4624}\ncondition: sel",
        [{"EventID": 4624}, {"EventID": "4624"}, {"EventID": 4625}],
        [0, 1],
    ),
    (
        "comparisons",
        "sel: {Size|gte: 100}\nsmall: {Size|lt: 1000}\ncondition: sel and small",
        [{"Size": 50}, {"Size": 100}, {"Size": 999}, {"Size": 1000}],
        [1, 2],
    ),
    (
        "regex is case-sensitive unless |i",
        "a: {User|re: '^adm.n$'}\nb: {User|re|i: '^ROOT$'}\ncondition: a or b",
        [{"User": "admin"}, {"User": "ADMIN"}, {"User": "root"}, {"User": "rooted"}],
        [0, 2],
    ),
    (
        "cidr",
        "sel: {Ip|cidr: ['10.0.0.0/8', '192.168.0.0/16']}\ncondition: sel",
        [{"Ip": "10.1.2.3"}, {"Ip": "192.168.5.5"}, {"Ip": "8.8.8.8"}],
        [0, 1],
    ),
    (
        "windash accepts / and unicode dashes",
        "sel: {CommandLine|windash|contains: ' -enc '}\ncondition: sel",
        [
            {"CommandLine": "powershell -enc AA"},
            {"CommandLine": "powershell /enc AA"},
            {"CommandLine": "powershell \u2013enc AA"},
            {"CommandLine": "powershell enc AA"},
        ],
        [0, 1, 2],
    ),
    (
        "fieldref compares two fields",
        "sel: {User|fieldref: Owner}\ncondition: sel",
        [{"User": "a", "Owner": "a"}, {"User": "a", "Owner": "b"}],
        [0],
    ),
    (
        "list of maps is OR, map is AND",
        "sel:\n  - {A: 1, B: 2}\n  - {C: 3}\ncondition: sel",
        [{"A": 1, "B": 2}, {"A": 1, "B": 9}, {"C": 3}],
        [0, 2],
    ),
    (
        "not binds tighter than and, and tighter than or",
        "a: {X: 1}\nb: {Y: 1}\nc: {Z: 1}\ncondition: not a and b or c",
        [{"X": 1, "Y": 1}, {"X": 0, "Y": 1}, {"Z": 1}],
        [1, 2],
    ),
    (
        "windash also expands values written with a slash, and every flag in a value",
        "sel: {CommandLine|windash|contains: ' /accepteula -ma '}\ncondition: sel",
        [
            {"CommandLine": "pd.exe -accepteula -ma 123"},
            {"CommandLine": "pd.exe /accepteula /ma 123"},
            {"CommandLine": "pd.exe –accepteula /ma 123"},
            {"CommandLine": "pd.exe accepteula ma 123"},
        ],
        [0, 1, 2],
    ),
    (
        "base64 is case-sensitive",
        "sel: {CommandLine|base64|contains: 'IEX'}\ncondition: sel",
        [{"CommandLine": f"powershell -e {b64(b'IEX')}"}, {"CommandLine": "powershell -e suvy"}],
        [0],
    ),
    (
        "base64offset finds the text at any byte offset",
        "sel: {CommandLine|base64offset|contains: 'Invoke-Expression'}\ncondition: sel",
        [{"CommandLine": f"-enc {b64(pad * b'x' + b'Invoke-Expression;')}"} for pad in range(3)]
        + [{"CommandLine": f"-enc {b64(b'Invoke-WebRequest')}"}],
        [0, 1, 2],
    ),
    (
        "utf16 text inside base64 (wide)",
        "sel: {CommandLine|wide|base64offset|contains: 'DownloadString'}\ncondition: sel",
        [
            {"CommandLine": f"-enc {b64(pad * b'x' + 'x.DownloadString('.encode('utf-16-le'))}"}
            for pad in range(3)
        ]
        + [{"CommandLine": f"-enc {b64(b'x.DownloadString(')}"}],
        [0, 1, 2],
    ),
    (
        "keyword lists with modifiers",
        "keywords:\n  '|all': [mimikatz, sekurlsa]\ncondition: keywords",
        [
            {"msg": "mimikatz # sekurlsa::logonpasswords"},
            {"msg": "mimikatz # lsadump::sam"},
        ],
        [0],
    ),
    (
        "regex keywords",
        "keywords:\n  '|re': 'lsadump::(sam|secrets)'\ncondition: keywords",
        [{"msg": "mimikatz # sekurlsa::logonpasswords"}, {"msg": "mimikatz # lsadump::sam"}],
        [1],
    ),
    (
        "neq negates the match and is true on a missing field",
        "sel: {CommandLine|contains|neq: [whoami, dir]}\ncondition: sel",
        PROCS,
        [2, 3],
    ),
    (
        "neq on a plain value",
        "sel: {Image|neq: 'c:\\windows\\notepad.exe'}\ncondition: sel",
        PROCS,
        [0, 1, 2],
    ),
    (
        "long value lists",
        "sel:\n  A|contains:\n"
        + "".join(f"    - needle{i}\n" for i in range(60))
        + "    - 'x%y_z'\n    - 'back\\slash'\ncondition: sel",
        [
            {"A": "..NEEDLE59.."},
            {"A": "no"},
            {"A": "x%y_z"},
            {"A": "xayb_z"},
            {"A": "back\\slash"},
            {"B": "needle1"},
        ],
        [0, 2, 4],
    ),
    (
        "long value lists under not",
        "sel:\n  A:\n" + "".join(f"    - v{i}\n" for i in range(60)) + "condition: not sel",
        [{"A": "V7"}, {"A": "other"}, {"B": 1}],
        [1, 2],
    ),
    (
        "long lists next to cased and other fields",
        "a:\n  A|contains:\n"
        + "".join(f"    - n{i}x\n" for i in range(60))
        + "b: {A|cased: Exact}\nc: {B: 1}\ncondition: 1 of them",
        [{"A": "N3X"}, {"A": "Exact"}, {"A": "exact"}, {"B": 1}],
        [0, 1, 3],
    ),
    (
        "cidr skips values that are not addresses",
        "sel: {Ip|cidr: 10.0.0.0/8}\ncondition: sel",
        [{"Ip": "-"}, {"Ip": ""}, {"Ip": "server1"}, {"Ip": "10.1.2.3"}, {"Other": 1}],
        [3],
    ),
    (
        "not cidr keeps values that are not addresses",
        "sel: {Ip|cidr: 10.0.0.0/8}\ncondition: not sel",
        [{"Ip": "-"}, {"Ip": "10.1.2.3"}, {"Ip": "8.8.8.8"}],
        [0, 2],
    ),
    (
        "number comparisons skip text",
        "sel: {Port|gt: 100}\ncondition: sel",
        [{"Port": "n/a"}, {"Port": 443}, {"Port": "8080"}, {"Port": 22}],
        [1, 2],
    ),
    (
        "text is not a small number",
        "sel: {Port|lt: 100}\ncondition: sel",
        [{"Port": "n/a"}, {"Port": 22}, {"Port": "80"}, {"Port": 443}, {"Port": "-"}],
        [1, 2],
    ),
    (
        "timestamp parts skip text",
        "sel: {When|hour: 3}\ncondition: sel",
        [{"When": "-"}, {"When": "2026-11-01T03:12:45Z"}],
        [1],
    ),
    ("regex anchors stop at the start", "sel: {A|re: '^two'}\ncondition: sel", LINES, []),
    ("regex m flag", "sel: {A|re|m: '^two'}\ncondition: sel", LINES, [0]),
    ("regex multiline name", "sel: {A|re|multiline: '^two'}\ncondition: sel", LINES, [0]),
    ("regex s flag", "sel: {A|re|s: 'one.two'}\ncondition: sel", LINES, [0]),
    ("regex dotall name", "sel: {A|re|dotall: 'one.two'}\ncondition: sel", LINES, [0]),
    ("regex i and m", "sel: {A|re|i|m: '^TWO'}\ncondition: sel", LINES, [0]),
    ("regex m and s", "sel: {A|re|m|s: '^one.two$'}\ncondition: sel", LINES, [0]),
    (
        "inline flags merge with modifiers",
        "sel: {A|re|i: '(?s)ONE.TWO'}\ncondition: sel",
        LINES,
        [0],
    ),
    ("repeated inline flag", "sel: {A|re|i: '(?i)ONE'}\ncondition: sel", LINES, [0]),
    ("timestamp minute", "sel: {When|minute: 12}\ncondition: sel", TIMES, [0]),
    ("timestamp hour", "sel: {When|hour: [3, 23]}\ncondition: sel", TIMES, [0, 1]),
    ("timestamp day", "sel: {When|day: 1}\ncondition: sel", TIMES, [0, 1]),
    ("timestamp month", "sel: {When|month: 11}\ncondition: sel", TIMES, [0]),
    ("timestamp year", "sel: {When|year: 2027}\ncondition: sel", TIMES, [1]),
    ("timestamp ISO week", "sel: {When|week: 44}\ncondition: sel", TIMES, [0]),
    ("ISO week spanning new year", "sel: {When|week: 53}\ncondition: sel", TIMES, [1]),
]


def rule_for(detection: str) -> Rule:
    body = "\n".join("  " + line for line in detection.splitlines())
    return load_rule(f"title: case\ndetection:\n{body}\n")
