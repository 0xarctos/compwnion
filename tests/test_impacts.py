# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

import re
from pathlib import Path

import pytest

from compwnion.cli import format_report, main, use_color
from compwnion.impacts import SEARCH_PATH_SET, Severity, impact_of, severity_of
from compwnion.scan import Status, scan

ANSI_ESCAPE = re.compile(r"\033\[\d+m")
ELF_FIXTURES = Path(__file__).parent / "fixtures" / "elf"
FIXTURES = sorted(
    path for path in ELF_FIXTURES.iterdir() if path.name.startswith(("hello-", "static-"))
)


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda path: path.name)
def test_every_protection_has_an_impact(fixture: Path) -> None:
    for check in scan(fixture).checks:
        if check.name != "Arch":
            assert impact_of(check.name, check.status), f"{check.name}: {check.status}"


def test_arch_has_no_impact() -> None:
    assert impact_of("Arch", "amd64-64-little") == ""


@pytest.mark.parametrize("name", ["RPATH", "RUNPATH"])
def test_search_path_impact_applies_to_any_path(name: str) -> None:
    assert impact_of(name, "/opt/compwnion") == SEARCH_PATH_SET
    assert impact_of(name, Status.NONE) != SEARCH_PATH_SET


def test_impact_depends_on_status() -> None:
    assert impact_of("RELRO", Status.FULL) != impact_of("RELRO", Status.PARTIAL)


@pytest.mark.parametrize(
    ("name", "status", "severity"),
    [
        ("Arch", "amd64-64-little", Severity.NEUTRAL),
        ("RELRO", Status.FULL, Severity.GOOD),
        ("RELRO", Status.PARTIAL, Severity.WARNING),
        ("RELRO", Status.DISABLED, Severity.BAD),
        ("Canary", Status.ENABLED, Severity.GOOD),
        ("NX", Status.UNKNOWN, Severity.WARNING),
        ("Exec stack", Status.YES, Severity.BAD),
        ("Exec stack", Status.NO, Severity.GOOD),
        ("RWX segments", Status.YES, Severity.BAD),
        ("RPATH", Status.NONE, Severity.GOOD),
        ("RPATH", "/opt/compwnion", Severity.BAD),
        ("RUNPATH", "/opt/compwnion", Severity.BAD),
        ("Stripped", Status.YES, Severity.GOOD),
        ("Stripped", Status.NO, Severity.BAD),
        ("Debuginfo", Status.YES, Severity.BAD),
        ("Debuginfo", Status.NO, Severity.GOOD),
    ],
)
def test_severity_of(name: str, status: str, severity: Severity) -> None:
    assert severity_of(name, status) == severity


def test_color_keeps_table_aligned() -> None:
    report = scan(ELF_FIXTURES / "hello-partial-relro")

    colored = format_report(report, color=True)

    assert "\033[33mPartial" in colored
    assert ANSI_ESCAPE.sub("", colored) == format_report(report)


def test_cli_has_no_color_when_not_a_terminal(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(ELF_FIXTURES / "hello-hardened")]) == 0

    assert "\033[" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("isatty", "no_color", "expected"),
    [(True, None, True), (True, "1", False), (False, None, False)],
)
def test_use_color(
    monkeypatch: pytest.MonkeyPatch, isatty: bool, no_color: str | None, expected: bool
) -> None:
    monkeypatch.setattr("sys.stdout.isatty", lambda: isatty)
    if no_color is None:
        monkeypatch.delenv("NO_COLOR", raising=False)
    else:
        monkeypatch.setenv("NO_COLOR", no_color)

    assert use_color() is expected


def test_cli_prints_impact_on_wide_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("COLUMNS", "200")

    assert main(["scan", str(ELF_FIXTURES / "hello-hardened")]) == 0

    output = capsys.readouterr().out
    assert "| Impact" in output
    assert impact_of("RELRO", Status.FULL) in output


def test_cli_wraps_impact_on_narrow_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("COLUMNS", "80")

    assert main(["scan", str(ELF_FIXTURES / "hello-hardened")]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert all(len(line) < 80 for line in lines)
    assert len({len(line) for line in lines[1:]}) == 1
    assert any(line.startswith("|              |") for line in lines)
