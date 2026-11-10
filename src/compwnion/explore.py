# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

import re
from dataclasses import dataclass
from pathlib import Path

import capstone
import lief
from capstone import x86

from compwnion.impacts import Severity
from compwnion.scan import UnsupportedBinaryError

Arch = lief.ELF.ARCH

# These are hints, not proof of a bug: explore reports that a call to one of
# these functions exists, not that its arguments are actually attacker-controlled.
CRITICAL = Severity.BAD
CONDITIONAL = Severity.WARNING

CATALOG: dict[str, tuple[Severity, str]] = {
    "gets": (CRITICAL, "No bounds checking on stdin: textbook stack overflow."),
    "strcpy": (CRITICAL, "Copies until a NUL with no bound: overflows a shorter destination."),
    "stpcpy": (CRITICAL, "Copies until a NUL with no bound: overflows a shorter destination."),
    "strcat": (CRITICAL, "Appends with no bound: overflows the destination."),
    "sprintf": (CRITICAL, "Formats into a buffer with no size limit: overflows on long output."),
    "vsprintf": (CRITICAL, "Formats into a buffer with no size limit: overflows on long output."),
    "scanf": (CRITICAL, "%s or %[ without a width writes unbounded input into a buffer."),
    "sscanf": (CRITICAL, "%s or %[ without a width writes unbounded input into a buffer."),
    "fscanf": (CRITICAL, "%s or %[ without a width writes unbounded input into a buffer."),
    "system": (CRITICAL, "Runs a shell command: command injection if the argument is influenced."),
    "popen": (CRITICAL, "Runs a shell command: command injection if the argument is influenced."),
    "execl": (CRITICAL, "Executes a program: dangerous if the path or arguments are influenced."),
    "execlp": (CRITICAL, "Executes a program: dangerous if the path or arguments are influenced."),
    "execle": (CRITICAL, "Executes a program: dangerous if the path or arguments are influenced."),
    "execv": (CRITICAL, "Executes a program: dangerous if the path or arguments are influenced."),
    "execvp": (CRITICAL, "Executes a program: dangerous if the path or arguments are influenced."),
    "execve": (CRITICAL, "Executes a program: dangerous if the path or arguments are influenced."),
    "printf": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "fprintf": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "dprintf": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "vprintf": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "vfprintf": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "snprintf": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "syslog": (CONDITIONAL, "Format string bug if the format argument is attacker-controlled."),
    "read": (CONDITIONAL, "Overflows the buffer if the length argument is attacker-controlled."),
    "recv": (CONDITIONAL, "Overflows the buffer if the length argument is attacker-controlled."),
    "memcpy": (CONDITIONAL, "Overflows the destination if the length is attacker-controlled."),
    "memmove": (CONDITIONAL, "Overflows the destination if the length is attacker-controlled."),
    "alloca": (CONDITIONAL, "Moves the stack pointer by a caller-provided size."),
    "strncpy": (CONDITIONAL, "Bounded but may leave the destination without a terminating NUL."),
    "strncat": (CONDITIONAL, "Bounded but off-by-one prone: the size excludes the NUL it adds."),
}

# The System V AMD64 argument registers, in order.
ARG_REGISTERS = [x86.X86_REG_RDI, x86.X86_REG_RSI, x86.X86_REG_RDX, x86.X86_REG_RCX]

# Each general-purpose register with its sub-register names, so that a write to
# edi, di or dil counts as writing rdi when tracing an argument's provenance.
_REGISTER_GROUPS = [
    ("RAX", "EAX", "AX", "AL", "AH"),
    ("RBX", "EBX", "BX", "BL", "BH"),
    ("RCX", "ECX", "CX", "CL", "CH"),
    ("RDX", "EDX", "DX", "DL", "DH"),
    ("RSI", "ESI", "SI", "SIL"),
    ("RDI", "EDI", "DI", "DIL"),
    ("RBP", "EBP", "BP", "BPL"),
    ("RSP", "ESP", "SP", "SPL"),
    *(
        (f"R{n}", f"R{n}D", f"R{n}W", f"R{n}B")
        for n in range(8, 16)
    ),
]


def _canonical_registers() -> dict[int, int]:
    mapping: dict[int, int] = {}
    for group in _REGISTER_GROUPS:
        canonical = getattr(x86, f"X86_REG_{group[0]}")
        for name in group:
            register = getattr(x86, f"X86_REG_{name}", None)
            if register is not None:
                mapping[register] = canonical
    return mapping


# Maps every sub-register to its 64-bit parent, so writes and copies can be
# matched regardless of the width the instruction uses.
CANONICAL_REGISTER = _canonical_registers()


def canonical_register(register: int) -> int:
    return CANONICAL_REGISTER.get(register, register)

# The argument index holding the format string, resp. the length, for the
# functions whose risk hinges on that one argument.
FORMAT_ARGUMENT = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "dprintf": 1,
    "syslog": 1,
    "snprintf": 2,
}
LENGTH_ARGUMENT = {"read": 2, "recv": 2, "memcpy": 2, "memmove": 2}

# How far back to look for the instruction that set an argument register. The
# compiler sets it just before the call, so a short window is enough.
PROVENANCE_WINDOW = 16


@dataclass(frozen=True)
class CallSite:
    address: int
    note: str | None = None


@dataclass(frozen=True)
class RiskyCall:
    function: str
    severity: Severity
    risk: str
    call_sites: list[CallSite]


# glibc exposes the scanf family under a versioned prefix (__isoc99_scanf on
# older libcs, __isoc23_scanf on newer ones). The hardened _chk variants are the
# FORTIFY-protected calls and are deliberately not flagged.
ISOC_PREFIX = re.compile(r"^__isoc\d+_")


def canonical_name(name: str) -> str:
    return ISOC_PREFIX.sub("", name)


def disassembler_for(binary: lief.ELF.Binary) -> capstone.Cs:
    machine = binary.header.machine_type
    modes = {
        Arch.X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        Arch.I386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    }
    if machine not in modes:
        raise UnsupportedBinaryError(f"explore supports x86 binaries only, not {machine.name}")

    arch, mode = modes[machine]
    disassembler = capstone.Cs(arch, mode | capstone.CS_MODE_LITTLE_ENDIAN)
    disassembler.detail = True
    return disassembler


def got_symbols(binary: lief.ELF.Binary) -> dict[int, str]:
    return {
        reloc.address: reloc.symbol.name
        for reloc in binary.relocations
        if reloc.has_symbol and reloc.symbol is not None and reloc.symbol.name
    }


def rip_target(instruction: capstone.CsInsn) -> int | None:
    for operand in instruction.operands:
        if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
            return instruction.address + instruction.size + operand.mem.disp
    return None


# The address a PLT stub's indirect jump reads its GOT slot from. x86-64 PIE
# stubs are RIP-relative (jmp [rip+disp]); x86 non-PIE stubs use an absolute
# operand (jmp [disp]) with no base or index register. A register-relative stub
# (e.g. a 32-bit PIE jmp [ebx+off]) needs a resolved GOT base, so return None.
def plt_slot_target(instruction: capstone.CsInsn) -> int | None:
    for operand in instruction.operands:
        if operand.type != capstone.x86.X86_OP_MEM:
            continue
        mem = operand.mem
        if mem.base == capstone.x86.X86_REG_RIP:
            return instruction.address + instruction.size + mem.disp
        if mem.base == capstone.x86.X86_REG_INVALID and mem.index == capstone.x86.X86_REG_INVALID:
            return mem.disp
    return None


# Maps each PLT stub to the symbol it jumps to, so that a direct call to the
# stub in .text can be named. Modern stubs open with endbr64; older ones do not.
def plt_targets(binary: lief.ELF.Binary, disassembler: capstone.Cs) -> dict[int, str]:
    got = got_symbols(binary)
    targets: dict[int, str] = {}

    for name in (".plt", ".plt.sec", ".plt.got"):
        section = binary.get_section(name)
        if section is None:
            continue

        stub_start: int | None = None
        for instruction in disassembler.disasm(bytes(section.content), section.virtual_address):
            if instruction.mnemonic == "endbr64":
                stub_start = instruction.address
            elif "jmp" in instruction.mnemonic:
                slot = plt_slot_target(instruction)
                if slot in got:
                    # Without a leading endbr64 the stub is just the jmp itself.
                    start = stub_start if stub_start is not None else instruction.address
                    targets[start] = got[slot]
                stub_start = None

    return targets


def call_target(instruction: capstone.CsInsn) -> int | None:
    operand = instruction.operands[0] if instruction.operands else None
    if operand is not None and operand.type == capstone.x86.X86_OP_IMM:
        return operand.imm
    return None


def readonly_ranges(binary: lief.ELF.Binary) -> list[tuple[int, int]]:
    alloc = lief.ELF.Section.FLAGS.ALLOC
    write = lief.ELF.Section.FLAGS.WRITE
    return [
        (section.virtual_address, section.virtual_address + section.size)
        for section in binary.sections
        if section.size and section.has(alloc) and not section.has(write)
    ]


def in_readonly(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(low <= address < high for low, high in ranges)


@dataclass(frozen=True)
class Provenance:
    kind: str  # "readonly" (constant pointer), "immediate", or "dynamic"
    value: int | None = None


# Index of the instruction that last wrote `register` within the window before
# `index`, or None. regs_access() reports sub-register writes too.
def last_writer_index(instructions: list[capstone.CsInsn], index: int, register: int) -> int | None:
    want = canonical_register(register)
    for offset in range(1, min(PROVENANCE_WINDOW, index) + 1):
        _, written = instructions[index - offset].regs_access()
        if any(canonical_register(reg) == want for reg in written):
            return index - offset
    return None


# Follows a register back to whatever set it, through register-to-register moves
# (a little copy propagation), which -O0 code inserts, e.g. lea rax, [rip+fmt];
# mov rdi, rax. depth bounds the chase.
def trace_register(
    instructions: list[capstone.CsInsn],
    index: int,
    register: int,
    ranges: list[tuple[int, int]],
    depth: int = 4,
) -> Provenance:
    writer = last_writer_index(instructions, index, register)
    if writer is None:
        return Provenance("dynamic")

    instruction = instructions[writer]
    if instruction.mnemonic == "lea":
        target = rip_target(instruction)
        if target is not None and in_readonly(target, ranges):
            return Provenance("readonly", target)
        return Provenance("dynamic")

    if instruction.mnemonic in ("mov", "movabs"):
        source = instruction.operands[1]
        if source.type == capstone.x86.X86_OP_IMM:
            kind = "readonly" if in_readonly(source.imm, ranges) else "immediate"
            return Provenance(kind, source.imm)
        if source.type == capstone.x86.X86_OP_REG and depth > 0:
            return trace_register(instructions, writer, source.reg, ranges, depth - 1)
        return Provenance("dynamic")

    # xor reg, reg zeroes the register.
    operands = instruction.operands
    if instruction.mnemonic == "xor" and operands[0].type == operands[1].type == x86.X86_OP_REG:
        if operands[0].reg == operands[1].reg:
            return Provenance("immediate", 0)

    return Provenance("dynamic")


def argument_provenance(
    instructions: list[capstone.CsInsn], index: int, argument: int, ranges: list[tuple[int, int]]
) -> Provenance:
    return trace_register(instructions, index, ARG_REGISTERS[argument], ranges)


# Index just before `index` where this call's argument setup can begin. The
# argument registers are caller-saved, so only writes since the most recent
# preceding call belong to this call. Bounding the search there (and by the
# provenance window) stops a value left in a register by an earlier call's
# setup from being mistaken for an argument to this one.
def setup_region_start(instructions: list[capstone.CsInsn], index: int) -> int:
    low = max(0, index - PROVENANCE_WINDOW)
    for position in range(index - 1, low - 1, -1):
        if instructions[position].mnemonic.endswith("call"):
            return position + 1
    return low


def register_written_between(
    instructions: list[capstone.CsInsn], start: int, index: int, register: int
) -> bool:
    want = canonical_register(register)
    for position in range(start, index):
        _, written = instructions[position].regs_access()
        if any(canonical_register(reg) == want for reg in written):
            return True
    return False


# True when the format is the call's only argument: printf(user) rather than
# printf("%s", user). The first variadic argument always lands in the register
# right after the format, so if that register is never set up for this call
# there are no variadic arguments. A non-constant format passed alone is the
# textbook format-string signature.
def format_is_sole_argument(
    instructions: list[capstone.CsInsn], index: int, format_argument: int
) -> bool:
    first_variadic = format_argument + 1
    if first_variadic >= len(ARG_REGISTERS):
        return True
    start = setup_region_start(instructions, index)
    return not register_written_between(instructions, start, index, ARG_REGISTERS[first_variadic])


def explore(path: Path) -> list[RiskyCall]:
    binary = lief.parse(str(path))
    if not isinstance(binary, lief.ELF.Binary):
        raise UnsupportedBinaryError(f"Unsupported binary format: {path}")

    disassembler = disassembler_for(binary)
    names = plt_targets(binary, disassembler)
    ranges = readonly_ranges(binary)
    # The provenance analysis assumes the System V AMD64 register convention.
    refine = binary.header.machine_type == Arch.X86_64

    text = binary.get_section(".text")
    instructions = (
        list(disassembler.disasm(bytes(text.content), text.virtual_address))
        if text is not None
        else []
    )

    sites: dict[str, list[CallSite]] = {}
    for index, instruction in enumerate(instructions):
        if not instruction.mnemonic.endswith("call"):
            continue
        target = call_target(instruction)
        if target is None or target not in names:
            continue
        function = canonical_name(names[target])
        if function not in CATALOG:
            continue

        note: str | None = None
        if refine and function in FORMAT_ARGUMENT:
            format_argument = FORMAT_ARGUMENT[function]
            fmt = argument_provenance(instructions, index, format_argument, ranges)
            # A constant format cannot carry an attacker's specifiers: not a bug.
            if fmt.kind == "readonly":
                continue
            # A non-constant format passed as the only argument is the textbook
            # format-string bug; flag that stronger signal.
            if format_is_sole_argument(instructions, index, format_argument):
                note = "single-arg"
        elif refine and function in LENGTH_ARGUMENT:
            length = argument_provenance(instructions, index, LENGTH_ARGUMENT[function], ranges)
            note = f"n={length.value:#x}" if length.kind == "immediate" else "n=computed"

        sites.setdefault(function, []).append(CallSite(instruction.address, note))

    findings = [
        RiskyCall(function, *CATALOG[function], sorted(addresses, key=lambda site: site.address))
        for function, addresses in sites.items()
    ]
    # Most severe first, then most call sites, then name, for a stable order.
    order = [Severity.BAD, Severity.WARNING]
    findings.sort(key=lambda call: (order.index(call.severity), -len(call.call_sites), call.function))
    return findings
