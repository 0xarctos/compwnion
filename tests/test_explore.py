# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

from pathlib import Path

import capstone
import lief
import pytest

import lief as _lief

from compwnion.cli import main
from compwnion.explore import (
    call_target,
    canonical_name,
    disassembler_for,
    explore,
    format_is_sole_argument,
    plt_targets,
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


@pytest.mark.parametrize("fixture", ["vuln-pie", "vuln-no-pie"])
def test_explore_flags_single_argument_format(fixture: str) -> None:
    # vuln.c calls printf(input): the format is the only argument, the textbook
    # format-string signature. Note that a naive check would be fooled by the
    # rsi left over from the preceding sprintf; the detection must stop at the
    # call boundary.
    printf = findings_by_name(fixture)["printf"]

    assert [site.note for site in printf.call_sites] == ["single-arg"]


def _calls_by_function(fixture: str):
    """Map each resolved libc function to the index of its call instruction."""
    binary = _lief.parse(str(ELF_FIXTURES / fixture))
    assert isinstance(binary, _lief.ELF.Binary)
    disassembler = disassembler_for(binary)
    names = plt_targets(binary, disassembler)
    text = binary.get_section(".text")
    instructions = list(disassembler.disasm(bytes(text.content), text.virtual_address))
    found: dict[str, int] = {}
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic.endswith("call"):
            target = call_target(instruction)
            if target in names:
                found[canonical_name(names[target])] = index
    return found, instructions


def test_format_is_sole_argument_detects_the_only_argument() -> None:
    # printf(input): format in rdi (arg 0), no variadic register set up.
    calls, instructions = _calls_by_function("vuln-pie")

    assert format_is_sole_argument(instructions, calls["printf"], 0) is True


def test_format_is_sole_argument_sees_further_arguments() -> None:
    # sprintf(global, "value=%s", input): format in rsi (arg 1), with the first
    # variadic argument in rdx. The call is not single-argument.
    calls, instructions = _calls_by_function("vuln-pie")

    assert format_is_sole_argument(instructions, calls["sprintf"], 1) is False


@pytest.mark.skipif(
    not (ELF_FIXTURES / "fmt-vararg").exists(),
    reason="fmt-vararg fixture is built by the Makefile on Linux/WSL",
)
def test_explore_does_not_tag_variadic_format_as_single_arg() -> None:
    # fmt_vararg.c calls printf(buffer, 1): non-constant format, so it is still
    # flagged, but with a variadic argument it is not the single-arg signature.
    printf = findings_by_name("fmt-vararg")["printf"]

    assert all(site.note != "single-arg" for site in printf.call_sites)


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


@pytest.mark.skipif(
    not (ELF_FIXTURES / "vuln-no-pie-32").exists(),
    reason="vuln-no-pie-32 fixture needs gcc-multilib; built by the Makefile on Linux/WSL",
)
def test_explore_resolves_absolute_plt_on_x86_32() -> None:
    # A 32-bit non-PIE binary reaches the GOT through an absolute memory operand
    # (jmp [0x804xxxx]), not the x86-64 RIP-relative form. explore must still
    # resolve the PLT and flag the risky calls, printf among them.
    found = findings_by_name("vuln-no-pie-32")

    assert "printf" in found
    assert "scanf" in found


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


def test_cli_explore_auto_is_silent_without_triton(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import compwnion.deep as deep

    def unavailable(_path: Path) -> list[object]:
        raise deep.DeepUnavailable("deep analysis needs triton")

    monkeypatch.setattr(deep, "taint_report", unavailable)

    exit_code = main(["explore", str(ELF_FIXTURES / "vuln-pie")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "CONFIRMED" not in captured.out
    assert "triton" not in captured.err.lower()


def test_cli_explore_no_deep_stays_local(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", "--no-deep", str(ELF_FIXTURES / "vuln-pie")])

    assert exit_code == 0
    assert "CONFIRMED" not in capsys.readouterr().out


def test_cli_explore_deep_reports_missing_triton(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import compwnion.deep as deep

    def unavailable(_path: Path) -> list[object]:
        raise deep.DeepUnavailable("deep analysis needs triton")

    monkeypatch.setattr(deep, "taint_report", unavailable)

    exit_code = main(["explore", "--deep", str(ELF_FIXTURES / "vuln-pie")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "triton" in captured.err.lower()


def test_cli_explore_reports_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", str(ELF_FIXTURES / "does-not-exist")])

    assert exit_code == 1
    assert "file not found" in capsys.readouterr().err
