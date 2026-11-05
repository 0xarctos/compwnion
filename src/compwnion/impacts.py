# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

from enum import Enum

from compwnion.scan import Status


class Severity(Enum):
    NEUTRAL = "neutral"
    GOOD = "good"
    WARNING = "warning"
    BAD = "bad"


STATIC_BINARY = "Statically linked: check the disassembly, imports cannot tell"
SEARCH_PATH_SET = "Searched for libraries: if writable, allows library hijacking"
NO_SEARCH_PATH = "No extra library search path"

# The status of RPATH and RUNPATH is the path itself, hence the OTHER fallback.
OTHER = "*"

IMPACTS: dict[str, dict[str, str]] = {
    "RELRO": {
        Status.FULL: "GOT is read-only: no GOT overwrite",
        Status.PARTIAL: "GOT entries stay writable: GOT overwrite is possible",
        Status.DISABLED: "GOT, .dynamic and .fini_array are writable: many overwrite targets",
    },
    "Canary": {
        Status.ENABLED: "Stack overflows must leak or brute-force the canary",
        Status.DISABLED: "Stack overflows can reach the return address unchecked",
        Status.UNKNOWN: STATIC_BINARY,
    },
    "NX": {
        Status.ENABLED: "Data pages are not executable: prefer ROP or ret2libc to shellcode",
        Status.DISABLED: "Readable pages are executable: shellcode can run from data",
        Status.UNKNOWN: "Depends on the kernel: check /proc/<pid>/maps at runtime",
    },
    "PIE": {
        Status.ENABLED: "Code base is randomized: leak a code address before using gadgets",
        Status.DISABLED: "Code is at a fixed address: gadgets, PLT and GOT are directly usable",
    },
    "Exec stack": {
        Status.YES: "Shellcode on the stack can run once its address is known",
        Status.NO: "Shellcode on the stack cannot run",
    },
    "RWX segments": {
        Status.YES: "Writable memory may be executable: check /proc/<pid>/maps at runtime",
        Status.NO: "No segment is both writable and executable",
    },
    "RPATH": {Status.NONE: NO_SEARCH_PATH, OTHER: SEARCH_PATH_SET},
    "RUNPATH": {Status.NONE: NO_SEARCH_PATH, OTHER: SEARCH_PATH_SET},
    "Fortify": {
        Status.ENABLED: "Some libc calls are checked at runtime and abort on overflow",
        Status.DISABLED: "No checked libc call imported: their overflows go undetected",
        Status.UNKNOWN: STATIC_BINARY,
    },
    "SHSTK": {
        Status.ENABLED: "Marked for shadow stack: blocks ROP only if the system enforces it",
        Status.DISABLED: "No shadow stack: return addresses have no hardware protection",
    },
    "IBT": {
        Status.ENABLED: "Marked for IBT: limits JOP/COP only if the system enforces it",
        Status.DISABLED: "No IBT: indirect branches can target any address",
    },
    "Stripped": {
        Status.YES: "No symbol table: function names must be recovered when reversing",
        Status.NO: "Symbol names are available for reversing",
    },
    "Debuginfo": {
        Status.YES: "Types and source lines are available for reversing",
        Status.NO: "No debug information to help reversing",
    },
}


def impact_of(name: str, status: str) -> str:
    impacts = IMPACTS.get(name, {})
    return impacts.get(status, impacts.get(OTHER, ""))


def severity_of(name: str, status: str) -> Severity:
    if name == "Arch":
        return Severity.NEUTRAL

    if name in ("RPATH", "RUNPATH"):
        return Severity.GOOD if status == Status.NONE else Severity.BAD

    if status in (Status.YES, Status.NO):
        good_answer = Status.YES if name == "Stripped" else Status.NO
        return Severity.GOOD if status == good_answer else Severity.BAD

    if status in (Status.PARTIAL, Status.UNKNOWN):
        return Severity.WARNING
    return Severity.BAD if status == Status.DISABLED else Severity.GOOD
