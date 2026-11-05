# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

from pathlib import Path

import pytest

pytest.importorskip("triton", reason="deep analysis needs the optional triton-library")

from compwnion.cli import main  # noqa: E402
from compwnion.deep import taint_report  # noqa: E402
from compwnion.scan import UnsupportedBinaryError  # noqa: E402

ELF_FIXTURES = Path(__file__).parent / "fixtures" / "elf"


def tainted(fixture: str) -> dict[str, bool]:
    # Collapse per-site verdicts to "is this function tainted at any call site".
    report: dict[str, bool] = {}
    for verdict in taint_report(ELF_FIXTURES / fixture):
        report[verdict.function] = report.get(verdict.function, False) or verdict.tainted
    return report


@pytest.mark.parametrize("fixture", ["vuln-pie", "vuln-no-pie"])
def test_deep_confirms_taint_across_functions(fixture: str) -> None:
    report = tainted(fixture)

    # scanf feeds handle(), which calls these: the input reaches every one.
    assert report["printf"] is True
    assert report["strcpy"] is True
    assert report["strcat"] is True
    assert report["system"] is True
    # read's length is the constant 256, not attacker-controlled.
    assert report["read"] is False


def test_deep_confirms_direct_format_string() -> None:
    assert tainted("fmt-taint")["printf"] is True


def test_deep_clears_constant_format_string() -> None:
    assert tainted("vuln-fmt-const").get("printf", False) is False


def test_deep_rejects_non_amd64() -> None:
    with pytest.raises(UnsupportedBinaryError):
        taint_report(ELF_FIXTURES / "static-nostdlib-32")


def test_cli_explore_deep_marks_confirmed(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", "--deep", str(ELF_FIXTURES / "vuln-pie")])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "CONFIRMED" in output
    # printf is confirmed as a real format-string bug here.
    assert "printf" in output


def test_cli_explore_auto_confirms_when_triton_available(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # No flag: auto mode runs deep because triton is installed here.
    exit_code = main(["explore", str(ELF_FIXTURES / "vuln-pie")])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "CONFIRMED" in output


def test_cli_explore_deep_on_safe_binary(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["explore", "--deep", str(ELF_FIXTURES / "vuln-fmt-const")])

    assert exit_code == 0
    assert "No risky library calls found." in capsys.readouterr().out
