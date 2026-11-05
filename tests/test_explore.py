# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

from pathlib import Path

import capstone
import lief
import pytest

from compwnion.cli import main
from compwnion.explore import (
    canonical_name,
    disassembler_for,
    explore,
)
from compwnion.impacts import Severity
from compwnion.scan import UnsupportedBinaryError

ELF_FIXTURES = Path(__file__).parent / "fixtures" / "elf"

# Every risky call in vuln.c, with the severity explore should assign.
EXPECTED = {
    "strcpy": Severity.BAD,
    "strcat": Severity.BAD,
    "sprintf": Severity.BAD,
    "scanf": Severity.BAD,
    "system": Severity.BAD,
    "printf": Severity.WARNING,
    "read": Severity.WARNING,
}


def findings_by_name(fixture: str) -> dict[str, object]:
    return {call.function: call for call in explore(ELF_FIXTURES / fixture)}


@pytest.mark.parametrize("fixture", ["vuln-pie", "vuln-no-pie"])
def test_explore_finds_every_risky_call(fixture: str) -> None:
    found = findings_by_name(fixture)

    assert {name: found[name].severity for name in found} == EXPECTED


@pytest.mark.parametrize("fixture", ["vuln-pie", "vuln-no-pie"])
def test_explore_locates_call_sites(fixture: str) -> None:
    found = findings_by_name(fixture)

    # scanf is called exactly once in main; its site must be a real .text address.
    scanf = found["scanf"]
    assert len(scanf.call_sites) == 1
    assert all(site.address > 0 for site in scanf.call_sites)


def test_explore_masks_constant_format_string() -> None:
    # fmt.c only calls printf with a constant format: nothing to flag.
    assert explore(ELF_FIXTURES / "vuln-fmt-const") == []


def test_explore_keeps_attacker_controlled_format_string() -> None:
    # vuln.c calls printf(input) where input comes from read().
    printf = findings_by_name("vuln-pie")["printf"]

    assert len(printf.call_sites) == 1


def test_explore_annotates_read_length() -> None:
    # vuln.c calls read(0, local, 256); the length is a constant.
    read = findings_by_name("vuln-pie")["read"]

    assert [site.note for site in read.call_sites] == ["n=0x100"]


def test_explore_orders_critical_before_conditional() -> None:
    severities = [call.severity for call in explore(ELF_FIXTURES / "vuln-pie")]

    assert severities == sorted(severities, key=[Severity.BAD, Severity.WARNING].index)


def test_explore_does_not_flag_fortified_or_safe_binary() -> None:
    # hello-hardened only calls printf through the fortified __printf_chk variant.
    assert explore(ELF_FIXTURES / "hello-hardened") == []


def test_explore_ignores_stack_chk() -> None:
    functions = {call.function for call in explore(ELF_FIXTURES / "hello-no-fortify")}

    assert "__stack_chk_fail" not in functions


def test_canonical_name_strips_versioned_isoc_prefix() -> None:
    assert canonical_name("__isoc99_scanf") == "scanf"
    assert canonical_name("__isoc23_scanf") == "scanf"
    assert canonical_name("printf") == "printf"


def test_disassembler_matches_architecture() -> None:
    binary64 = lief.parse(str(ELF_FIXTURES / "vuln-pie"))
    binary32 = lief.parse(str(ELF_FIXTURES / "static-nostdlib-32"))
    assert isinstance(binary64, lief.ELF.Binary)
    assert isinstance(binary32, lief.ELF.Binary)

    assert disassembler_for(binary64).mode & capstone.CS_MODE_64
    assert disassembler_for(binary32).mode & capstone.CS_MODE_32


def test_explore_on_binary_without_plt_returns_nothing() -> None:
    # A -nostdlib binary has no PLT, so no library call can be resolved.
    assert explore(ELF_FIXTURES / "static-nostdlib-32") == []


def test_explore_rejects_non_elf(tmp_path: Path) -> None:
    text = tmp_path / "note.txt"
    text.write_text("not an ELF")

    with pytest.raises(UnsupportedBinaryError):
        explore(text)


def test_cli_explore_lists_findings(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", str(ELF_FIXTURES / "vuln-pie")])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "CRITICAL" in output
    assert "scanf" in output
    assert "unbounded" in output


def test_cli_explore_reports_clean_binary(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", str(ELF_FIXTURES / "hello-hardened")])

    assert exit_code == 0
    assert "No risky library calls found." in capsys.readouterr().out


def test_cli_explore_reports_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", str(ELF_FIXTURES / "does-not-exist")])

    assert exit_code == 1
    assert "file not found" in capsys.readouterr().err
