<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 0xarctos

Part of Compwnion - companion tools for pwn quests
Licensed under the Apache License, Version 2.0; see the LICENSE file.
-->

# Classic vulnerability catalog

This is the reference `explore` works from: the classic memory-safety and
injection bug classes that show up in CTF and reversing targets, each with a
concise description, its binary-level **signature**, and **how (or whether)
`explore` detects it**.

## Read this first: what "detection" means here

`explore` works on a compiled binary, not source. It disassembles `.text`,
resolves each call through the PLT, and matches it against a catalog of risky
libc functions (the *sinks* below). So:

- **A listed call is a candidate, not a proven bug.** It means the dangerous
  function is reached, not that its arguments are actually attacker-controlled.
- Detection is a **heuristic**, and is by nature incomplete. Deciding in general
  whether a program has a given bug is undecidable, so every static detector
  trades false positives against false negatives. `explore` deliberately errs
  toward reporting candidates and then *refining* confidence, rather than
  claiming certainty.
- Two refinements raise confidence on x86-64:
  - **Local provenance** (`explore.py`): traces where a call's key argument
    comes from within the function. It follows the x86-64 argument registers
    and the x86-32 cdecl stack (both the `push arg` and the `sub esp; mov
    [esp+k], arg` styles), resolving the x86-32 PIC base so constant strings
    loaded as `lea [ebx - disp]` are recognized. It masks a `printf` whose
    format is a link-time constant, reports whether the format is the call's
    *only* argument, and annotates a `read`/`memcpy` length.
  - **Deep taint** (`explore.py --deep`, `deep.py`): emulates from `main` with
    Triton along one concrete path, taints input buffers, and marks a call
    `CONFIRMED` when attacker data provably reaches its key argument.

Confidence, highest to lowest: **`CONFIRMED` (taint-proven)** > **unbounded sink
by construction (`CRITICAL`)** > **conditional sink with a dangerous local
signature (`WARNING` + note)** > **conditional sink, unrefined**.

---

## Detected: unbounded writes → stack/global buffer overflow

A copy or formatted write with **no size bound** overflows any destination
shorter than the source. The classic stack smash.

| Sink | Why it is unbounded |
| --- | --- |
| `gets` | Reads a line from stdin with no limit at all. |
| `strcpy`, `stpcpy` | Copy until a NUL, no bound. |
| `strcat` | Appends until a NUL, no bound. |
| `sprintf`, `vsprintf` | Format into a buffer with no size cap. |
| `scanf`, `sscanf`, `fscanf` with `%s`/`%[` and no width | Write unbounded input. |

**Signature:** a call to one of these. For the `scanf` family the width is in
the format string, which `explore` does not parse, so the family is flagged
whenever used.
**`explore`:** `CRITICAL`. Deep taint upgrades to `CONFIRMED` when the source
operand is attacker-tainted.

## Detected: format string

A `printf`-family call whose **format argument is attacker-controlled** lets the
attacker supply conversion specifiers: `%p`/`%x` leak the stack, `%s`
dereferences, and `%n` writes memory. The textbook form is the format passed as
the function's *only* argument — `printf(user)` instead of
`printf("%s", user)`.

**Sinks:** `printf`, `fprintf`, `dprintf`, `vprintf`, `vfprintf`, `snprintf`,
`syslog`.
**Signature, strongest first:**
1. Format is **non-constant** *and* **the sole argument** (no variadic register
   set up for the call). This is the classic bug and is reported with the
   `single-arg` note.
2. Format is non-constant but other arguments are present (could still be a bug
   if the format itself is tainted).
3. Format is a link-time constant → **cannot** carry attacker specifiers.
**`explore`:** `WARNING`. A constant format (case 3) is **masked** (not
reported). Deep taint marks the call `CONFIRMED` when the format is tainted.
**Limit:** the local pass does not read the format's *bytes*, so it cannot tell
`"%s"` from an attacker string that merely looks constant through a path it does
not follow.

## Detected: command / program injection

Passing influenced data to a shell or `exec` runs attacker commands.

**Sinks:** `system`, `popen` (shell), `execl`, `execlp`, `execle`, `execv`,
`execvp`, `execve` (program spawn).
**Signature:** a call to one of these.
**`explore`:** `CRITICAL`; `CONFIRMED` when the command/path argument is tainted.

## Detected: attacker-controlled length → overflow

A copy or read whose **length** comes from the attacker overflows a fixed
destination even when the API is otherwise "safe".

**Sinks:** `read`, `recv`, `memcpy`, `memmove`.
**Signature:** the length argument is not a small constant.
**`explore`:** `WARNING`, annotated `n=0x100` for a constant length or
`n=computed` when it comes from a register; `CONFIRMED` when the length is
tainted. A constant, sane length is the benign case.

## Detected with caveats: bounded-but-error-prone

Bounded APIs that still bite through off-by-one or a missing terminator.

| Sink | Pitfall |
| --- | --- |
| `strncpy` | Does not NUL-terminate when the source is as long as the bound. |
| `strncat` | The bound counts chars *excluding* the NUL it appends: off-by-one. |

**`explore`:** `WARNING`. These are flagged on use; whether the surrounding
sizing is wrong is not something the binary makes decidable.

---

## Not reliably detectable statically (and why)

Listed so the catalog is honest about its edges. `explore` does **not** claim
these; a clean report does not rule them out.

| Class | Why static binary detection is unreliable |
| --- | --- |
| **Heap: use-after-free, double-free** | Requires modeling allocation lifetimes and aliasing across the whole program; no single call site is the "bug". |
| **Integer overflow → undersized `malloc`** | The bug is in arithmetic (`malloc(a * b)`), not a named sink; needs value-range analysis and knowledge of intended bounds. |
| **Off-by-one / logic overflow with correct APIs** | A hand-rolled loop or a wrong `sizeof` overflows with no risky call at all — nothing to match. |
| **TOCTOU / race conditions** | Depend on interleaving and the environment, invisible in a single disassembly. |
| **Type confusion, uninitialized reads** | Need type and dataflow information generally absent from a stripped binary. |

## Practical limits of the current engine

- **PLT-resolved calls only:** statically linked or non-x86 binaries resolve few
  or no names, so little is reported. Local provenance covers x86 and x86-64;
  deep taint (`--deep`) is x86-64 only.
- **Local provenance** does not follow values through memory, across functions,
  or around loops — hence deep taint for the cross-function answer. On an
  x86-32 PIE whose PIC base it cannot resolve, a constant format is reported
  rather than masked (a false positive, not a missed bug).
- **Deep taint** follows a *single concrete path* within an instruction budget;
  a call it never reaches simply stays unconfirmed. It raises confidence; it
  never clears a finding.
