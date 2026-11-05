/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 0xarctos
 *
 * Part of Compwnion - companion tools for pwn quests
 * Licensed under the Apache License, Version 2.0; see the LICENSE file.
 *
 * Maps the code as RWX while keeping a non-executable stack.
 */

PHDRS {
    text PT_LOAD FLAGS(7);
    stack PT_GNU_STACK FLAGS(6);
}

SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    .text : { *(.text*) } :text
    /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) }
}
