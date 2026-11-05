# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

import re
from pathlib import Path

import lief
import pytest

from compwnion.cli import main
from compwnion.scan import SecurityCheck, Status, UnsupportedBinaryError, scan

ELF_FIXTURES = Path(__file__).parent / "fixtures" / "elf"

HARDENED: dict[str, str] = {
    "Arch": "amd64-64-little",
    "RELRO": Status.FULL,
    "Canary": Status.ENABLED,
    "NX": Status.ENABLED,
    "PIE": Status.ENABLED,
    "Exec stack": Status.NO,
    "RWX segments": Status.NO,
    "RPATH": Status.NONE,
    "RUNPATH": Status.NONE,
    "Fortify": Status.ENABLED,
    "SHSTK": Status.ENABLED,
    "IBT": Status.ENABLED,
    "Stripped": Status.YES,
    "Debuginfo": Status.NO,
}

# An executable stack leaves NX undecided on amd64, see check_nx.
EXEC_STACK: dict[str, str] = {
    "NX": Status.UNKNOWN,
    "Exec stack": Status.YES,
    "RWX segments": Status.YES,
}


def scan_statuses(fixture: str) -> dict[str, str]:
    return {check.name: check.status for check in scan(ELF_FIXTURES / fixture).checks}


@pytest.mark.parametrize(
    ("fixture", "enabled"),
    [("hello-pie", True), ("hello-no-pie", False)],
)
def test_scan_detects_pie(fixture: str, enabled: bool) -> None:
    report = scan(ELF_FIXTURES / fixture)

    assert report.binary_format == "ELF"
    assert SecurityCheck("PIE", Status.ENABLED if enabled else Status.DISABLED) in report.checks


@pytest.mark.parametrize(
    ("fixture", "differences"),
    [
        ("hello-hardened", {}),
        ("hello-old-dtags", {}),
        ("hello-partial-relro", {"RELRO": Status.PARTIAL}),
        ("hello-no-relro", {"RELRO": Status.DISABLED}),
        ("hello-no-canary", {"Canary": Status.DISABLED}),
        ("hello-no-fortify", {"Fortify": Status.DISABLED}),
        ("hello-execstack", EXEC_STACK),
        ("hello-not-stripped", {"Stripped": Status.NO}),
        ("hello-debuginfo", {"Stripped": Status.NO, "Debuginfo": Status.YES}),
        ("hello-rpath", {"RPATH": "/opt/compwnion"}),
        ("hello-runpath", {"RUNPATH": "/opt/compwnion"}),
        ("hello-no-cet", {"SHSTK": Status.DISABLED, "IBT": Status.DISABLED}),
        ("hello-ibt-only", {"SHSTK": Status.DISABLED}),
        ("hello-shstk-only", {"IBT": Status.DISABLED}),
        (
            "hello-unhardened",
            {
                **EXEC_STACK,
                "RELRO": Status.DISABLED,
                "Canary": Status.DISABLED,
                "PIE": Status.DISABLED,
                "Fortify": Status.DISABLED,
                "SHSTK": Status.DISABLED,
                "IBT": Status.DISABLED,
            },
        ),
    ],
)
def test_scan_reports_each_protection(fixture: str, differences: dict[str, str]) -> None:
    assert scan_statuses(fixture) == {**HARDENED, **differences}


def test_scan_shared_library_protections() -> None:
    statuses = scan_statuses("hello-lib")

    assert statuses["RELRO"] == Status.FULL
    assert statuses["Canary"] == Status.ENABLED
    assert statuses["NX"] == Status.ENABLED
    assert statuses["PIE"] == Status.ENABLED
    assert statuses["Fortify"] == Status.ENABLED


def test_scan_reports_disabled_when_compiler_had_nothing_to_protect() -> None:
    statuses = scan_statuses("hello-puts-only")

    assert statuses["Canary"] == Status.DISABLED
    assert statuses["Fortify"] == Status.DISABLED


@pytest.mark.parametrize(
    ("fixture", "arch", "pie"),
    [
        ("static-nostdlib", "amd64-64-little", Status.DISABLED),
        ("static-nostdlib-32", "i386-32-little", Status.DISABLED),
        ("static-pie-nostdlib", "amd64-64-little", Status.ENABLED),
    ],
)
def test_scan_static_binary_has_unknown_symbol_checks(fixture: str, arch: str, pie: Status) -> None:
    statuses = scan_statuses(fixture)

    assert statuses["Arch"] == arch
    assert statuses["Canary"] == Status.UNKNOWN
    assert statuses["Fortify"] == Status.UNKNOWN
    assert statuses["PIE"] == pie


@pytest.mark.parametrize(
    ("fixture", "nx"),
    [("static-no-gnustack", Status.UNKNOWN), ("static-no-gnustack-32", Status.DISABLED)],
)
def test_scan_missing_gnu_stack(fixture: str, nx: Status) -> None:
    statuses = scan_statuses(fixture)

    assert statuses["NX"] == nx
    assert statuses["Exec stack"] == Status.YES
    assert statuses["RWX segments"] == Status.NO


def test_scan_rwx_load_segment_with_nx() -> None:
    statuses = scan_statuses("static-rwx-load")

    assert statuses["NX"] == Status.ENABLED
    assert statuses["Exec stack"] == Status.NO
    assert statuses["RWX segments"] == Status.YES


def test_scan_ignores_non_utf8_symbol_names() -> None:
    binary = lief.parse(str(ELF_FIXTURES / "hello-bad-symbol"))
    assert isinstance(binary, lief.ELF.Binary)
    assert any(isinstance(symbol.name, bytes) for symbol in binary.imported_symbols)

    statuses = scan_statuses("hello-bad-symbol")

    assert statuses["Canary"] == Status.ENABLED
    assert statuses["Fortify"] == Status.DISABLED


def test_scan_rejects_non_binary_file() -> None:
    with pytest.raises(UnsupportedBinaryError):
        scan(ELF_FIXTURES / "hello.c")


@pytest.mark.parametrize("size", [0, 64, 2000])
def test_scan_rejects_truncated_elf(tmp_path: Path, size: int) -> None:
    truncated = tmp_path / "truncated"
    truncated.write_bytes((ELF_FIXTURES / "hello-hardened").read_bytes()[:size])

    with pytest.raises(UnsupportedBinaryError):
        scan(truncated)


@pytest.mark.parametrize(
    ("fixture", "status"),
    [("hello-pie", "Enabled"), ("hello-no-pie", "Disabled")],
)
def test_cli_prints_pie_status(
    fixture: str, status: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["scan", str(ELF_FIXTURES / fixture)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Format: ELF" in output
    assert re.search(rf"\| PIE +\| {status} +\|", output)


def test_cli_reports_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["scan", str(ELF_FIXTURES / "does-not-exist")])

    assert exit_code == 1
    assert "file not found" in capsys.readouterr().err


def test_cli_reports_directory(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["scan", str(ELF_FIXTURES)])

    assert exit_code == 1
    assert "got a directory" in capsys.readouterr().err
