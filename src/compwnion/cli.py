# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

import argparse
import os
import shutil
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path

import lief

from compwnion.impacts import Severity, impact_of, severity_of
from compwnion.scan import ScanReport, UnsupportedBinaryError, scan

TABLE_BORDERS = len("| " + " | " + " | " + " |")
MIN_IMPACT_WIDTH = 30

ANSI_RESET = "\033[0m"
ANSI_COLORS = {
    Severity.GOOD: "\033[32m",
    Severity.WARNING: "\033[33m",
    Severity.BAD: "\033[31m",
}


def paint(text: str, severity: Severity) -> str:
    code = ANSI_COLORS.get(severity)
    return f"{code}{text}{ANSI_RESET}" if code else text


def use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def format_report(report: ScanReport, color: bool = False) -> str:
    header = ("Security", "Status", "Impact", Severity.NEUTRAL)
    rows = [
        (
            check.name,
            str(check.status),
            impact_of(check.name, check.status),
            severity_of(check.name, check.status) if color else Severity.NEUTRAL,
        )
        for check in report.checks
    ]
    name_width = max(len(row[0]) for row in [header, *rows])
    status_width = max(len(row[1]) for row in [header, *rows])

    available = shutil.get_terminal_size().columns - 1 - name_width - status_width - TABLE_BORDERS
    impact_width = min(
        max(len(row[2]) for row in [header, *rows]), max(available, MIN_IMPACT_WIDTH)
    )

    # The status is padded before being painted, as color codes have no width.
    def format_row(name: str, status: str, impact: str, severity: Severity) -> list[str]:
        impact_lines = textwrap.wrap(impact, impact_width) or [""]
        cells = [(name, paint(f"{status:<{status_width}}", severity), impact_lines[0])]
        cells += [("", " " * status_width, line) for line in impact_lines[1:]]
        return [
            f"| {left:<{name_width}} | {middle} | {right:<{impact_width}} |"
            for left, middle, right in cells
        ]

    separator = f"+-{'-' * name_width}-+-{'-' * status_width}-+-{'-' * impact_width}-+"
    body = [line for row in rows for line in format_row(*row)]
    return "\n".join(
        [f"Format: {report.binary_format}", separator, *format_row(*header), separator, *body, separator]
    )


def resolve_binary(binary: Path) -> int | None:
    if binary.is_dir():
        print(f"compwnion: expected a file, got a directory: {binary}", file=sys.stderr)
        return 1
    if not binary.is_file():
        print(f"compwnion: file not found: {binary}", file=sys.stderr)
        return 1
    return None


def enable_windows_ansi() -> None:
    if sys.platform == "win32":
        # An empty command makes cmd.exe enable ANSI sequences in the console.
        os.system("")


def run_scan(args: argparse.Namespace) -> int:
    error_code = resolve_binary(args.binary)
    if error_code is not None:
        return error_code

    try:
        report = scan(args.binary)
    except UnsupportedBinaryError as error:
        print(f"compwnion: {error}", file=sys.stderr)
        return 1

    color = use_color()
    if color:
        enable_windows_ansi()

    print(format_report(report, color))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    lief.logging.disable()

    parser = argparse.ArgumentParser(prog="compwnion")
    commands = parser.add_subparsers(required=True)

    scan_parser = commands.add_parser("scan", help="summarize the security features of a binary")
    scan_parser.add_argument("binary", type=Path)
    scan_parser.set_defaults(run=run_scan)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
