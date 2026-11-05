# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import lief

Arch = lief.ELF.ARCH
Tag = lief.ELF.DynamicEntry.TAG
Flag = lief.ELF.DynamicEntryFlags.FLAG
SegmentFlag = lief.ELF.Segment.FLAGS


class UnsupportedBinaryError(ValueError):
    pass


class Status(StrEnum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    FULL = "Full"
    PARTIAL = "Partial"
    UNKNOWN = "Unknown"
    YES = "Yes"
    NO = "No"
    NONE = "None"


@dataclass(frozen=True)
class SecurityCheck:
    name: str
    status: str


@dataclass(frozen=True)
class ScanReport:
    binary_format: str
    checks: list[SecurityCheck]


def enabled_if(condition: bool) -> Status:
    return Status.ENABLED if condition else Status.DISABLED


def yes_if(condition: bool) -> Status:
    return Status.YES if condition else Status.NO


def check_arch(binary: lief.ELF.Binary) -> str:
    header = binary.header
    name = "amd64" if header.machine_type == Arch.X86_64 else header.machine_type.name.lower()
    bits = 64 if header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32
    endian = "little" if header.identity_data == lief.ELF.Header.ELF_DATA.LSB else "big"
    return f"{name}-{bits}-{endian}"


def has_bind_now(binary: lief.ELF.Binary) -> bool:
    if binary.has(Tag.BIND_NOW):
        return True

    for tag, flag in ((Tag.FLAGS, Flag.BIND_NOW), (Tag.FLAGS_1, Flag.NOW)):
        entry = binary.get(tag)
        if isinstance(entry, lief.ELF.DynamicEntryFlags) and entry.has(flag):
            return True

    return False


def check_relro(binary: lief.ELF.Binary) -> Status:
    if not binary.has(lief.ELF.Segment.TYPE.GNU_RELRO):
        return Status.DISABLED
    return Status.FULL if has_bind_now(binary) else Status.PARTIAL


def is_stack_chk(name: str) -> bool:
    return name.startswith("__stack_chk_")


# LIEF returns bytes for names that are not valid UTF-8, which cannot match
# the libc symbols checked here.
def imported_names(binary: lief.ELF.Binary) -> list[str]:
    names = (symbol.name for symbol in binary.imported_symbols)
    return [name for name in names if isinstance(name, str)]


# A statically linked binary embeds libc, whose own code uses these symbols
# whatever the protections of the program, and it has no imports to inspect.
def check_canary(binary: lief.ELF.Binary) -> Status:
    if not binary.libraries:
        return Status.UNKNOWN
    return enabled_if(any(is_stack_chk(name) for name in imported_names(binary)))


def check_fortify(binary: lief.ELF.Binary) -> Status:
    if not binary.libraries:
        return Status.UNKNOWN
    return enabled_if(
        any(name.endswith("_chk") and not is_stack_chk(name) for name in imported_names(binary))
    )


def is_executable(binary: lief.ELF.Binary) -> bool:
    return binary.header.file_type == lief.ELF.Header.FILE_TYPE.EXEC or binary.has_interpreter


# Same rules as pwntools: NX here means that the kernel does not make all
# readable pages executable. For an executable PT_GNU_STACK, that depends on
# the kernel version (it changed in Linux 5.8), which the binary does not tell.
def check_nx(binary: lief.ELF.Binary) -> Status:
    if not is_executable(binary):
        return Status.ENABLED

    stack = binary.get(lief.ELF.Segment.TYPE.GNU_STACK)
    if stack is not None and not stack.has(SegmentFlag.X):
        return Status.ENABLED

    machine = binary.header.machine_type
    if stack is None and machine in (Arch.I386, Arch.ARM, Arch.AARCH64, Arch.MIPS):
        return Status.DISABLED
    return Status.UNKNOWN


def check_exec_stack(binary: lief.ELF.Binary) -> Status:
    if not is_executable(binary):
        return Status.NO

    stack = binary.get(lief.ELF.Segment.TYPE.GNU_STACK)
    if stack is not None:
        return yes_if(stack.has(SegmentFlag.X))

    # Without PT_GNU_STACK, glibc falls back on the default of the architecture.
    return yes_if(binary.header.machine_type not in (Arch.AARCH64, Arch.IA_64, Arch.RISCV))


# Same rule as pwntools: unless NX is known to be enabled, readable pages may be
# executable, so every writable segment counts as RWX.
def check_rwx(binary: lief.ELF.Binary) -> Status:
    writable = [segment for segment in binary.segments if segment.has(SegmentFlag.W)]
    if check_nx(binary) != Status.ENABLED and writable:
        return Status.YES
    return yes_if(any(segment.has(SegmentFlag.X) for segment in writable))


def to_text(value: str | bytes) -> str:
    return value if isinstance(value, str) else value.decode("utf-8", "backslashreplace")


def check_rpath(binary: lief.ELF.Binary) -> str:
    entry = binary.get(Tag.RPATH)
    return to_text(entry.rpath) if isinstance(entry, lief.ELF.DynamicEntryRpath) else Status.NONE


def check_runpath(binary: lief.ELF.Binary) -> str:
    entry = binary.get(Tag.RUNPATH)
    return (
        to_text(entry.runpath) if isinstance(entry, lief.ELF.DynamicEntryRunPath) else Status.NONE
    )


def x86_features(binary: lief.ELF.Binary) -> list[lief.ELF.X86Features.FEATURE]:
    note = binary.get(lief.ELF.Note.TYPE.GNU_PROPERTY_TYPE_0)
    if not isinstance(note, lief.ELF.NoteGnuProperty):
        return []

    prop = note.find(lief.ELF.NoteGnuProperty.Property.TYPE.X86_FEATURE)
    if not isinstance(prop, lief.ELF.X86Features):
        return []

    return [feature for _, feature in prop.features]


def scan_elf(binary: lief.ELF.Binary) -> ScanReport:
    features = x86_features(binary)
    return ScanReport(
        "ELF",
        [
            SecurityCheck("Arch", check_arch(binary)),
            SecurityCheck("RELRO", check_relro(binary)),
            SecurityCheck("Canary", check_canary(binary)),
            SecurityCheck("NX", check_nx(binary)),
            SecurityCheck(
                "PIE", enabled_if(binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN)
            ),
            SecurityCheck("Exec stack", check_exec_stack(binary)),
            SecurityCheck("RWX segments", check_rwx(binary)),
            SecurityCheck("RPATH", check_rpath(binary)),
            SecurityCheck("RUNPATH", check_runpath(binary)),
            SecurityCheck("Fortify", check_fortify(binary)),
            SecurityCheck("SHSTK", enabled_if(lief.ELF.X86Features.FEATURE.SHSTK in features)),
            SecurityCheck("IBT", enabled_if(lief.ELF.X86Features.FEATURE.IBT in features)),
            SecurityCheck("Stripped", yes_if(not binary.has(lief.ELF.Section.TYPE.SYMTAB))),
            SecurityCheck("Debuginfo", yes_if(binary.has_section(".debug_info"))),
        ],
    )


# LIEF still returns a binary when it fails to read part of a truncated file,
# and the checks would then report wrong statuses from what is left.
def is_truncated(binary: lief.ELF.Binary, file_size: int) -> bool:
    header = binary.header
    headers_end = (
        header.program_header_offset + header.numberof_segments * header.program_header_size
    )
    return headers_end > file_size or any(
        segment.file_offset + segment.physical_size > file_size for segment in binary.segments
    )


def scan(path: Path) -> ScanReport:
    binary = lief.parse(str(path))

    if isinstance(binary, lief.ELF.Binary):
        if is_truncated(binary, path.stat().st_size):
            raise UnsupportedBinaryError(f"Truncated ELF binary: {path}")
        return scan_elf(binary)

    raise UnsupportedBinaryError(f"Unsupported binary format: {path}")
