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


# The constant address a `lea` computes, for the two position-independent forms
# that load a pointer to a read-only string: x86-64 RIP-relative (lea [rip+disp])
# and x86-32 PIC (lea [ebx+disp], with ebx holding a resolved GOT base from
# `pic`). Returns None for a genuinely dynamic address.
def lea_target(instruction: capstone.CsInsn, pic: dict[int, int]) -> int | None:
    mem = next(
        (op.mem for op in instruction.operands if op.type == capstone.x86.X86_OP_MEM), None
    )
    if mem is None:
        return None
    if mem.base == capstone.x86.X86_REG_RIP:
        return instruction.address + instruction.size + mem.disp
    if mem.index == capstone.x86.X86_REG_INVALID:
        base = pic.get(canonical_register(mem.base))
        if base is not None:
            return base + mem.disp
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


# True when `target` is a get-PC thunk that loads the return address into `reg`
# (mov reg, [esp]; ret), the body gcc calls to establish the PIC base on x86-32.
def _is_pc_thunk(
    instructions: list[capstone.CsInsn], by_address: dict[int, int], target: int, reg: int
) -> bool:
    index = by_address.get(target)
    if index is None or index + 1 >= len(instructions):
        return False
    load, ret = instructions[index], instructions[index + 1]
    if load.mnemonic != "mov" or len(load.operands) != 2 or ret.mnemonic != "ret":
        return False
    dest, source = load.operands
    return (
        dest.type == capstone.x86.X86_OP_REG
        and canonical_register(dest.reg) == canonical_register(reg)
        and source.type == capstone.x86.X86_OP_MEM
        and source.mem.base == capstone.x86.X86_REG_ESP
        and source.mem.index == capstone.x86.X86_REG_INVALID
        and source.mem.disp == 0
    )


# Maps each register gcc pins the PIC base into (usually ebx) to that base, by
# recognizing `call <get-PC thunk>; add reg, imm`. The base is the GOT address,
# so a later `lea reg2, [reg - disp]` resolves to a concrete read-only pointer.
def pic_bases(instructions: list[capstone.CsInsn]) -> dict[int, int]:
    by_address = {instruction.address: index for index, instruction in enumerate(instructions)}
    bases: dict[int, int] = {}
    for index in range(1, len(instructions)):
        instruction, previous = instructions[index], instructions[index - 1]
        operands = instruction.operands
        if (
            instruction.mnemonic != "add"
            or not previous.mnemonic.endswith("call")
            or len(operands) != 2
            or operands[0].type != capstone.x86.X86_OP_REG
            or operands[1].type != capstone.x86.X86_OP_IMM
        ):
            continue
        target = call_target(previous)
        if target is None or not _is_pc_thunk(instructions, by_address, target, operands[0].reg):
            continue
        base = previous.address + previous.size + operands[1].imm
        bases.setdefault(canonical_register(operands[0].reg), base)
    return bases


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
# mov rdi, rax. depth bounds the chase. pic resolves x86-32 PIC pointers.
def trace_register(
    instructions: list[capstone.CsInsn],
    index: int,
    register: int,
    ranges: list[tuple[int, int]],
    pic: dict[int, int],
    depth: int = 4,
) -> Provenance:
    writer = last_writer_index(instructions, index, register)
    if writer is None:
        return Provenance("dynamic")

    instruction = instructions[writer]
    if instruction.mnemonic == "lea":
        target = lea_target(instruction, pic)
        if target is not None and in_readonly(target, ranges):
            return Provenance("readonly", target)
        return Provenance("dynamic")

    if instruction.mnemonic in ("mov", "movabs"):
        source = instruction.operands[1]
        if source.type == capstone.x86.X86_OP_IMM:
            kind = "readonly" if in_readonly(source.imm, ranges) else "immediate"
            return Provenance(kind, source.imm)
        if source.type == capstone.x86.X86_OP_REG and depth > 0:
            return trace_register(instructions, writer, source.reg, ranges, pic, depth - 1)
        return Provenance("dynamic")

    # xor reg, reg zeroes the register.
    operands = instruction.operands
    if instruction.mnemonic == "xor" and operands[0].type == operands[1].type == x86.X86_OP_REG:
        if operands[0].reg == operands[1].reg:
            return Provenance("immediate", 0)

    return Provenance("dynamic")


# How far back to scan for a cdecl call's stack argument setup. Wider than the
# register window: pushes and stack-slot moves can span more instructions.
STACK_ARGUMENT_WINDOW = 48


# Maps each outgoing cdecl stack argument (0, 1, 2, ...) to the index of the
# instruction that last set it, for an x86-32 call. It tracks esp relative to
# the call across pushes and explicit stack moves, covering both the push style
# (push arg; call) and the accumulated style (sub esp; mov [esp+k], arg; call).
# Returns (args, reliable); reliable is False when esp moves in a way the model
# does not understand, so callers do not trust a half-built picture.
def outgoing_stack_args(
    instructions: list[capstone.CsInsn], index: int
) -> tuple[dict[int, int], bool]:
    esp = canonical_register(x86.X86_REG_ESP)
    start = setup_region_start(instructions, index, STACK_ARGUMENT_WINDOW)
    offset = 0
    writes: list[tuple[int, int]] = []
    for position in range(start, index):
        instruction = instructions[position]
        mnemonic, operands = instruction.mnemonic, instruction.operands
        if mnemonic == "push":
            offset -= 4
            writes.append((offset, position))
            continue
        if mnemonic == "pop":
            offset += 4
            continue
        if (
            mnemonic in ("sub", "add")
            and operands
            and operands[0].type == x86.X86_OP_REG
            and canonical_register(operands[0].reg) == esp
            and operands[1].type == x86.X86_OP_IMM
        ):
            offset += -operands[1].imm if mnemonic == "sub" else operands[1].imm
            continue
        if mnemonic == "mov" and len(operands) == 2 and operands[0].type == x86.X86_OP_MEM:
            memory = operands[0].mem
            if canonical_register(memory.base) == esp and memory.index == x86.X86_REG_INVALID:
                writes.append((offset + memory.disp, position))
                continue
        # Anything else that moves esp (alignment, a computed adjustment) desyncs
        # the model: report unreliable rather than mislabel the arguments.
        _, written = instruction.regs_access()
        if any(canonical_register(register) == esp for register in written):
            return {}, False

    args: dict[int, int] = {}
    for slot_offset, position in writes:
        slot = slot_offset - offset
        if slot >= 0 and slot % 4 == 0:
            args[slot // 4] = position
    return args, True


# The operand a push or a stack-slot mov takes its value from.
def _argument_source(instruction: capstone.CsInsn):
    if instruction.mnemonic == "push" and instruction.operands:
        return instruction.operands[0]
    if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
        return instruction.operands[1]
    return None


def _operand_provenance(
    instructions: list[capstone.CsInsn],
    writer: int,
    operand,
    ranges: list[tuple[int, int]],
    pic: dict[int, int],
) -> Provenance:
    if operand.type == capstone.x86.X86_OP_IMM:
        kind = "readonly" if in_readonly(operand.imm, ranges) else "immediate"
        return Provenance(kind, operand.imm)
    if operand.type == capstone.x86.X86_OP_REG:
        return trace_register(instructions, writer, operand.reg, ranges, pic)
    return Provenance("dynamic")


def stack_argument_provenance(
    instructions: list[capstone.CsInsn],
    index: int,
    argument: int,
    ranges: list[tuple[int, int]],
    pic: dict[int, int],
) -> Provenance:
    args, reliable = outgoing_stack_args(instructions, index)
    writer = args.get(argument) if reliable else None
    if writer is None:
        return Provenance("dynamic")
    source = _argument_source(instructions[writer])
    if source is None:
        return Provenance("dynamic")
    return _operand_provenance(instructions, writer, source, ranges, pic)


# Where a call's `argument` (0-based) comes from, for either calling convention:
# the x86-64 argument registers, or the x86-32 cdecl stack.
def argument_provenance(
    instructions: list[capstone.CsInsn],
    index: int,
    argument: int,
    ranges: list[tuple[int, int]],
    bits: int = 64,
    pic: dict[int, int] | None = None,
) -> Provenance:
    pic = pic or {}
    if bits == 32:
        return stack_argument_provenance(instructions, index, argument, ranges, pic)
    return trace_register(instructions, index, ARG_REGISTERS[argument], ranges, pic)


# Index just before `index` where this call's argument setup can begin. The
# argument registers are caller-saved, so only writes since the most recent
# preceding call belong to this call. Bounding the search there (and by the
# provenance window) stops a value left in a register by an earlier call's
# setup from being mistaken for an argument to this one.
def setup_region_start(
    instructions: list[capstone.CsInsn], index: int, window: int = PROVENANCE_WINDOW
) -> int:
    low = max(0, index - window)
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
# printf("%s", user). The first variadic argument always lands in the slot right
# after the format -- the next register on x86-64, the next stack slot on x86-32
# -- so if that slot is never set up for this call there are no variadic
# arguments. A non-constant format passed alone is the textbook format-string
# signature. On x86-32 an esp model it could not follow yields False, so the
# stronger claim is only made when the setup was understood.
def format_is_sole_argument(
    instructions: list[capstone.CsInsn], index: int, format_argument: int, bits: int = 64
) -> bool:
    first_variadic = format_argument + 1
    if bits == 32:
        args, reliable = outgoing_stack_args(instructions, index)
        return reliable and first_variadic not in args
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
    # Provenance refinement handles both conventions: x86-64 argument registers
    # and the x86-32 cdecl stack.
    bits = {Arch.X86_64: 64, Arch.I386: 32}.get(binary.header.machine_type)
    refine = bits is not None

    text = binary.get_section(".text")
    instructions = (
        list(disassembler.disasm(bytes(text.content), text.virtual_address))
        if text is not None
        else []
    )
    # On x86-32, resolve the PIC base so lea-loaded constant strings are known.
    pic = pic_bases(instructions) if bits == 32 else {}

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
            fmt = argument_provenance(instructions, index, format_argument, ranges, bits, pic)
            # A constant format cannot carry an attacker's specifiers: not a bug.
            if fmt.kind == "readonly":
                continue
            # A non-constant format passed as the only argument is the textbook
            # format-string bug; flag that stronger signal.
            if format_is_sole_argument(instructions, index, format_argument, bits):
                note = "single-arg"
        elif refine and function in LENGTH_ARGUMENT:
            length = argument_provenance(
                instructions, index, LENGTH_ARGUMENT[function], ranges, bits, pic
            )
            note = f"n={length.value:#x}" if length.kind == "immediate" else "n=computed"

        sites.setdefault(function, []).append(CallSite(instruction.address, note))

    findings = []
    for function, addresses in sites.items():
        severity, risk = CATALOG[function]
        # A non-constant format passed as the sole argument is a full
        # format-string primitive -- arbitrary read via %s/%p and an arbitrary
        # write via %n -- not a merely conditional risk, so raise it to
        # critical rather than leaving it a warning.
        if function in FORMAT_ARGUMENT and any(site.note == "single-arg" for site in addresses):
            severity = Severity.BAD
        findings.append(
            RiskyCall(function, severity, risk, sorted(addresses, key=lambda site: site.address))
        )
    return order_findings(findings)


# Most severe first, then most call sites, then name, for a stable order.
def order_findings(findings: list[RiskyCall]) -> list[RiskyCall]:
    order = [Severity.BAD, Severity.WARNING]
    return sorted(
        findings, key=lambda call: (order.index(call.severity), -len(call.call_sites), call.function)
    )
