# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.
#
# Deep taint analysis: emulate the binary from main with Triton, taint the
# buffers that input functions fill, and report whether each risky call receives
# attacker-tainted data. This follows the real control flow (into local calls),
# so taint is tracked across functions, along one concrete path.

from dataclasses import dataclass
from pathlib import Path

import lief

from compwnion.explore import call_target, canonical_name, disassembler_for, plt_targets
from compwnion.scan import UnsupportedBinaryError

Arch = lief.ELF.ARCH

# System V AMD64 argument registers.
ARGUMENT_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# Input function -> (buffer arg index, length arg index or None, default size).
INPUT_FUNCTIONS: dict[str, tuple[int, int | None, int]] = {
    "read": (1, 2, 4096),
    "recv": (1, 2, 4096),
    "fgets": (0, 2, 4096),
    "gets": (0, None, 512),
    "scanf": (1, None, 512),
    "sscanf": (2, None, 512),
}

# Risky function -> (argument index, "ptr" or "reg") whose taint confirms the
# bug: a pointer to attacker data, or a scalar the attacker controls.
CONFIRM_ARGUMENT: dict[str, tuple[int, str]] = {
    "printf": (0, "ptr"),
    "fprintf": (1, "ptr"),
    "dprintf": (1, "ptr"),
    "vprintf": (0, "ptr"),
    "vfprintf": (1, "ptr"),
    "snprintf": (2, "ptr"),
    "syslog": (1, "ptr"),
    "read": (2, "reg"),
    "recv": (2, "reg"),
    "memcpy": (2, "reg"),
    "memmove": (2, "reg"),
    "system": (0, "ptr"),
    "popen": (0, "ptr"),
    "execl": (0, "ptr"),
    "execlp": (0, "ptr"),
    "execle": (0, "ptr"),
    "execv": (0, "ptr"),
    "execvp": (0, "ptr"),
    "execve": (0, "ptr"),
    "strcpy": (1, "ptr"),
    "stpcpy": (1, "ptr"),
    "strcat": (1, "ptr"),
}

# Functions that end the program: stop emulating when one is called.
STOP_FUNCTIONS = {"exit", "_exit", "abort", "__stack_chk_fail", "__assert_fail"}

STACK_BASE = 0x7FFFFFF00000
RETURN_SENTINEL = 0x4B4B4B4B
INSTRUCTION_BUDGET = 100_000
# Bytes of a flagged pointer's target to test for taint, and the cap on how much
# of an input buffer to taint.
POINTER_PROBE = 8
MAX_TAINT = 4096


class DeepUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class TaintVerdict:
    function: str
    address: int
    tainted: bool


def _import_triton():
    try:
        import triton
    except ImportError as error:  # pragma: no cover - exercised without the extra
        raise DeepUnavailable(
            "deep analysis needs triton; install it with: uv sync --extra deep"
        ) from error
    return triton


class _Emulator:
    def __init__(self, triton, binary: lief.ELF.Binary, disassembler):
        self._t = triton
        self._md = disassembler
        self._stubs = plt_targets(binary, disassembler)
        self._executable = [
            (section.virtual_address, section.virtual_address + section.size)
            for section in binary.sections
            if section.size and section.has(lief.ELF.Section.FLAGS.EXECINSTR)
        ]
        self._binary = binary
        self._ctx = self._load()

    def _load(self):
        ctx = self._t.TritonContext(self._t.ARCH.X86_64)
        for segment in self._binary.segments:
            if segment.type == lief.ELF.Segment.TYPE.LOAD and segment.physical_size:
                ctx.setConcreteMemoryAreaValue(int(segment.virtual_address), bytes(segment.content))
        return ctx

    def _reg(self, name: str) -> int:
        return self._ctx.getConcreteRegisterValue(getattr(self._ctx.registers, name))

    def _set_reg(self, name: str, value: int) -> None:
        self._ctx.setConcreteRegisterValue(getattr(self._ctx.registers, name), value)

    def _decode(self, pc: int):
        data = self._ctx.getConcreteMemoryAreaValue(int(pc), 16)
        return next(self._md.disasm(bytes(data), int(pc)), None)

    def _process(self, instruction) -> None:
        self._ctx.processing(self._t.Instruction(instruction.address, bytes(instruction.bytes)))

    def _executable_pc(self, pc: int) -> bool:
        return any(low <= pc < high for low, high in self._executable)

    # main's address is whatever _start loads into rdi before its first call.
    def find_main(self) -> int | None:
        self._set_reg("rsp", STACK_BASE)
        self._set_reg("rip", int(self._binary.entrypoint))
        pc = int(self._binary.entrypoint)
        for _ in range(40):
            instruction = self._decode(pc)
            if instruction is None:
                return None
            if instruction.mnemonic.endswith("call"):
                return self._reg("rdi")
            self._process(instruction)
            pc = self._reg("rip")
        return None

    def _taint_memory(self, address: int, size: int) -> None:
        access = self._t.MemoryAccess
        for offset in range(min(size, MAX_TAINT)):
            self._ctx.taintMemory(access(address + offset, 1))

    def _argument_tainted(self, index: int, kind: str) -> bool:
        register = getattr(self._ctx.registers, ARGUMENT_REGISTERS[index])
        if kind == "reg":
            return self._ctx.isRegisterTainted(register)
        pointer = self._reg(ARGUMENT_REGISTERS[index])
        access = self._t.MemoryAccess
        return any(self._ctx.isMemoryTainted(access(pointer + i, 1)) for i in range(POINTER_PROBE))

    def _handle_external(self, name: str, address: int) -> list[TaintVerdict]:
        verdicts = []
        if name in CONFIRM_ARGUMENT:
            index, kind = CONFIRM_ARGUMENT[name]
            verdicts.append(TaintVerdict(name, address, self._argument_tainted(index, kind)))

        if name in INPUT_FUNCTIONS:
            buffer_arg, length_arg, default = INPUT_FUNCTIONS[name]
            buffer = self._reg(ARGUMENT_REGISTERS[buffer_arg])
            size = self._reg(ARGUMENT_REGISTERS[length_arg]) if length_arg is not None else default
            self._taint_memory(buffer, size)

        # Model the call's net effect: a fresh, untainted return value.
        self._ctx.untaintRegister(self._ctx.registers.rax)
        self._set_reg("rax", 0)
        return verdicts

    def run(self, main: int) -> list[TaintVerdict]:
        # Fresh frame: a sentinel return address marks the end of main.
        self._set_reg("rsp", STACK_BASE)
        self._ctx.setConcreteMemoryValue(self._t.MemoryAccess(STACK_BASE, 8), RETURN_SENTINEL)
        verdicts: list[TaintVerdict] = []

        pc = main
        for _ in range(INSTRUCTION_BUDGET):
            if pc == RETURN_SENTINEL or not self._executable_pc(pc):
                break
            instruction = self._decode(pc)
            if instruction is None:
                break

            if instruction.mnemonic.endswith("call"):
                target = call_target(instruction)
                if target in self._stubs:
                    name = canonical_name(self._stubs[target])
                    verdicts.extend(self._handle_external(name, instruction.address))
                    if name in STOP_FUNCTIONS:
                        break
                    pc = instruction.address + instruction.size  # step over the call
                    continue

            self._process(instruction)
            pc = self._reg("rip")

        return verdicts


def taint_report(path: Path) -> list[TaintVerdict]:
    triton = _import_triton()

    binary = lief.parse(str(path))
    if not isinstance(binary, lief.ELF.Binary):
        raise UnsupportedBinaryError(f"Unsupported binary format: {path}")
    if binary.header.machine_type != Arch.X86_64:
        raise UnsupportedBinaryError("deep analysis supports x86-64 binaries only")

    emulator = _Emulator(triton, binary, disassembler_for(binary))
    main = emulator.find_main()
    if main is None:
        return []
    return emulator.run(main)
