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

# Stack top, per word size (a 32-bit esp cannot hold the 64-bit value).
STACK_BASE = {64: 0x7FFFFFF00000, 32: 0xFFFFD000}
RETURN_SENTINEL = 0x4B4B4B4B
INSTRUCTION_BUDGET = 100_000
# A separate, unmapped region where a synthetic argv/envp is laid out, so the
# program's own command line counts as attacker input. Well clear of the code
# segments and the stack for both word sizes.
ARGS_BASE = 0x55000000
ARGC = 2
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
    def __init__(self, triton, binary: lief.ELF.Binary, disassembler, bits: int):
        self._t = triton
        self._md = disassembler
        self._bits = bits
        self._word = bits // 8
        # Names of the stack pointer, instruction pointer and return register.
        self._sp = "rsp" if bits == 64 else "esp"
        self._ip = "rip" if bits == 64 else "eip"
        self._ret = "rax" if bits == 64 else "eax"
        self._stack_base = STACK_BASE[bits]
        self._stubs = plt_targets(binary, disassembler)
        self._executable = [
            (section.virtual_address, section.virtual_address + section.size)
            for section in binary.sections
            if section.size and section.has(lief.ELF.Section.FLAGS.EXECINSTR)
        ]
        self._binary = binary
        self._ctx = self._load()

    def _load(self):
        arch = self._t.ARCH.X86_64 if self._bits == 64 else self._t.ARCH.X86
        ctx = self._t.TritonContext(arch)
        for segment in self._binary.segments:
            if segment.type == lief.ELF.Segment.TYPE.LOAD and segment.physical_size:
                ctx.setConcreteMemoryAreaValue(int(segment.virtual_address), bytes(segment.content))
        return ctx

    def _reg(self, name: str) -> int:
        return self._ctx.getConcreteRegisterValue(getattr(self._ctx.registers, name))

    def _set_reg(self, name: str, value: int) -> None:
        self._ctx.setConcreteRegisterValue(getattr(self._ctx.registers, name), value)

    def _read_word(self, address: int) -> int:
        return self._ctx.getConcreteMemoryValue(self._t.MemoryAccess(int(address), self._word))

    def _write_word(self, address: int, value: int) -> None:
        self._ctx.setConcreteMemoryValue(self._t.MemoryAccess(int(address), self._word), value)

    def _decode(self, pc: int):
        data = self._ctx.getConcreteMemoryAreaValue(int(pc), 16)
        return next(self._md.disasm(bytes(data), int(pc)), None)

    def _process(self, instruction) -> None:
        self._ctx.processing(self._t.Instruction(instruction.address, bytes(instruction.bytes)))

    def _executable_pc(self, pc: int) -> bool:
        return any(low <= pc < high for low, high in self._executable)

    # main's address: on x86-64 _start loads it into rdi before calling
    # __libc_start_main; on x86-32 it is pushed, so it sits at the top of the
    # stack at that call. The x86-32 _start first calls a get-PC thunk, which
    # must be stepped through, so stop only at the external (PLT) call.
    def find_main(self) -> int | None:
        self._set_reg(self._sp, self._stack_base)
        self._set_reg(self._ip, int(self._binary.entrypoint))
        pc = int(self._binary.entrypoint)
        for _ in range(200):
            instruction = self._decode(pc)
            if instruction is None:
                return None
            if instruction.mnemonic.endswith("call"):
                target = call_target(instruction)
                if self._bits == 64:
                    return self._reg("rdi")
                if target in self._stubs:
                    return self._read_word(self._reg("esp"))
            self._process(instruction)
            pc = self._reg(self._ip)
        return None

    def _taint_memory(self, address: int, size: int) -> None:
        access = self._t.MemoryAccess
        for offset in range(min(size, MAX_TAINT)):
            self._ctx.taintMemory(access(address + offset, 1))

    # Lay out a synthetic argv/envp in a scratch region and taint the strings,
    # so a format or command taken from the command line is confirmed. Returns
    # (argv, envp) pointers. Called before the main frame is built.
    def _install_arguments(self) -> tuple[int, int]:
        word = self._word
        argv, envp = ARGS_BASE, ARGS_BASE + 0x40
        program, attacker, environment = ARGS_BASE + 0x100, ARGS_BASE + 0x200, ARGS_BASE + 0x300
        self._write_word(argv + 0 * word, program)
        self._write_word(argv + 1 * word, attacker)  # argv[1], attacker-controlled
        self._write_word(argv + 2 * word, 0)
        self._write_word(envp + 0 * word, environment)
        self._write_word(envp + 1 * word, 0)
        for string in (program, attacker, environment):
            self._ctx.setConcreteMemoryAreaValue(string, b"A" * 64 + b"\x00")
        # The program name is not an injection vector; the rest is attacker input.
        self._taint_memory(attacker, 64)
        self._taint_memory(environment, 64)
        return argv, envp

    def _argument_pointer(self, index: int) -> int:
        if self._bits == 64:
            return self._reg(ARGUMENT_REGISTERS[index])
        # cdecl: at the intercepted call, esp points at the first argument.
        return self._read_word(self._reg("esp") + index * self._word)

    def _argument_tainted(self, index: int, kind: str) -> bool:
        access = self._t.MemoryAccess
        if kind == "reg":
            if self._bits == 64:
                return self._ctx.isRegisterTainted(getattr(self._ctx.registers, ARGUMENT_REGISTERS[index]))
            slot = self._reg("esp") + index * self._word
            return any(self._ctx.isMemoryTainted(access(slot + i, 1)) for i in range(self._word))
        pointer = self._argument_pointer(index)
        return any(self._ctx.isMemoryTainted(access(pointer + i, 1)) for i in range(POINTER_PROBE))

    def _handle_external(self, name: str, address: int) -> list[TaintVerdict]:
        verdicts = []
        if name in CONFIRM_ARGUMENT:
            index, kind = CONFIRM_ARGUMENT[name]
            verdicts.append(TaintVerdict(name, address, self._argument_tainted(index, kind)))

        if name in INPUT_FUNCTIONS:
            buffer_arg, length_arg, default = INPUT_FUNCTIONS[name]
            buffer = self._argument_pointer(buffer_arg)
            size = self._argument_pointer(length_arg) if length_arg is not None else default
            self._taint_memory(buffer, size)

        # Model the call's net effect: a fresh, untainted return value.
        self._ctx.untaintRegister(getattr(self._ctx.registers, self._ret))
        self._set_reg(self._ret, 0)
        return verdicts

    def run(self, main: int) -> list[TaintVerdict]:
        argv, envp = self._install_arguments()
        # Fresh frame: a sentinel return address marks the end of main, with
        # argc/argv/envp passed the way the ABI expects them.
        self._set_reg(self._sp, self._stack_base)
        self._write_word(self._stack_base, RETURN_SENTINEL)
        if self._bits == 64:
            self._set_reg("rdi", ARGC)
            self._set_reg("rsi", argv)
            self._set_reg("rdx", envp)
        else:
            self._write_word(self._stack_base + 1 * self._word, ARGC)
            self._write_word(self._stack_base + 2 * self._word, argv)
            self._write_word(self._stack_base + 3 * self._word, envp)
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
            pc = self._reg(self._ip)

        return verdicts


def taint_report(path: Path) -> list[TaintVerdict]:
    triton = _import_triton()

    binary = lief.parse(str(path))
    if not isinstance(binary, lief.ELF.Binary):
        raise UnsupportedBinaryError(f"Unsupported binary format: {path}")
    bits = {Arch.X86_64: 64, Arch.I386: 32}.get(binary.header.machine_type)
    if bits is None:
        raise UnsupportedBinaryError("deep analysis supports x86 and x86-64 binaries only")

    emulator = _Emulator(triton, binary, disassembler_for(binary), bits)
    main = emulator.find_main()
    if main is None:
        return []
    return emulator.run(main)
