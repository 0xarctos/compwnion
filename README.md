# Compwnion

Copyright 2026 0xarctos

This product is licensed under the Apache License, Version 2.0.
See the [LICENSE](LICENSE) file for the full license text.

## Installing uv

This project uses [uv](https://docs.astral.sh/uv/) to manage Python and its dependencies.

Windows:

```powershell
winget install --id=astral-sh.uv -e
```

Linux and macOS:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Open a new terminal afterwards, then check that uv is available:

```sh
uv --version
```

Other installation methods are listed in the
[uv documentation](https://docs.astral.sh/uv/getting-started/installation/).

## Installing the dependencies

From the root of the repository, run:

```sh
uv sync
```

This creates a `.venv` directory and installs the exact versions recorded in
`uv.lock`. If the Python version the project requires is missing, uv downloads it.

## Usage

Summarize the security features of a binary (ELF only for now):

```sh
uv run compwnion scan <binary>
```

It reports the same information as pwntools' `checksec`: architecture, RELRO,
stack canary, NX, PIE, executable stack, RWX segments, RPATH, RUNPATH, FORTIFY,
SHSTK, IBT, stripping and debug information.

The `Impact` column gives the usual meaning of each result for exploitation. It
is general guidance, not an analysis of what this particular binary allows.

Statuses are colored in a terminal: green for a protection in place, yellow for a
partial or uncertain result, and red for what is missing or helps an attacker. Set
the `NO_COLOR` environment variable to disable colors. They are also disabled when
the output is redirected.

Canary and FORTIFY are detected from imported symbols, so:

- `Unknown` means the binary is statically linked and has no imports to inspect.
- `Disabled` means no such symbol is imported. The compiler may have had nothing
  to protect, for example if no function called a fortifiable libc function.

`NX: Unknown` means the result depends on the kernel running the binary. On
amd64 with an executable stack, for example, Linux 5.8 and later keep NX enabled
for everything but the stack. `RWX segments` follows the `checksec` rule in that
case and counts every writable segment.

In VS Code, select `.venv` as the Python interpreter so that imports resolve.

## Listing risky calls

List calls to functions that are common sources of memory-safety bugs:

```sh
uv run compwnion explore <binary>
```

It disassembles the code, resolves each call through the PLT, and reports calls
to a catalog of risky libc functions (`gets`, `strcpy`, `sprintf`, `scanf`,
`system`, `printf`, `read`, ...), grouped by function with their call sites.

This is a heuristic: a call being listed means the function is used, not that its
arguments are actually attacker-controlled. `CRITICAL` marks calls that are
unsafe by construction (unbounded copies, shell execution); `WARNING` marks calls
that are a bug only under a condition (a user-controlled format or length). It
covers x86 and x86-64, and resolves names through the PLT, so statically linked
or non-x86 binaries report little or nothing.

On x86-64, each flagged call is refined by tracing where its key argument comes
from, within the function and following register copies:

- A `printf`-family call whose format string is a constant is **not** reported:
  a constant format cannot carry attacker-controlled specifiers.
- A `read`, `recv` or `memcpy` call is annotated with its length: `n=0x100` for a
  constant, or `n=computed` when the length comes from a register.

This tracing is local: it does not follow values through memory, across
functions or through loops, so a format string that is constant only after such
a path is still reported.

## Running the tests

```sh
uv run pytest
```

The test binaries are committed in `tests/fixtures/elf`, so no compiler is needed
to run the tests. To rebuild them on Linux or WSL, with gcc and make installed:

```sh
make -B -C tests/fixtures/elf
```
