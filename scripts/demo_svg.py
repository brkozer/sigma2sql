"""Render the README terminal screenshot from real command output.

uv run python scripts/demo_svg.py docs/demo.svg
"""

from __future__ import annotations

import subprocess
import sys

from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

COMMANDS = [
    "sigma2sql hunt examples/rules --logs examples/events.jsonl",
    "sigma2sql check examples/rules --require-tests",
    "sigma2sql convert examples/rules/office_spawns_shell.yml -d postgres --json-column data",
]


def main(out: str) -> None:
    console = Console(record=True, width=112, force_terminal=True)
    for command in COMMANDS:
        console.print(Text("$ ", style="bold green") + Text(command, style="bold"))
        result = subprocess.run(command.split(), capture_output=True, text=True, check=False)
        if command.startswith("sigma2sql convert"):
            console.print(Syntax(result.stdout.strip(), "sql", theme="monokai", word_wrap=True))
        else:
            for line in result.stdout.splitlines():
                console.print(Text(line, style="cyan"), overflow="fold")
        if result.stderr.strip():
            console.print(Text(result.stderr.strip(), style="yellow"))
        console.print(Text(f"exit {result.returncode}", style="dim"))
        console.print()
    console.save_svg(out, title="sigma2sql")


if __name__ == "__main__":
    main(sys.argv[1])
