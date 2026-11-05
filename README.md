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

## Running the tests

```sh
uv run pytest
```

The test binaries are committed in `tests/fixtures/elf`, so no compiler is needed
to run the tests. To rebuild them on Linux or WSL, with gcc and make installed:

```sh
make -B -C tests/fixtures/elf
```
