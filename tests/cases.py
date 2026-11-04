"""Behaviour cases shared by the SQLite and PostgreSQL tests.

Each case is (name, detection YAML, events, indexes of the events that must match).
"""

from __future__ import annotations

from typing import Any

from sigma2sql import Rule, load_rule

Case = tuple[str, str, list[dict[str, Any]], list[int]]

PROCS = [
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"},
    {"Image": "C:\\Windows\\System32\\CMD.EXE", "CommandLine": "CMD.EXE /C dir"},
    {"Image": "C:\\Tools\\cmd.exe.bak", "CommandLine": "copy a b"},
    {"Image": "C:\\Windows\\notepad.exe"},
]

CASES: list[Case] = [
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
]


def rule_for(detection: str) -> Rule:
    body = "\n".join("  " + line for line in detection.splitlines())
    return load_rule(f"title: case\ndetection:\n{body}\n")
