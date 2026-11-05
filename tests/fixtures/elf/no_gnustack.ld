/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 0xarctos
 *
 * Part of Compwnion - companion tools for pwn quests
 * Licensed under the Apache License, Version 2.0; see the LICENSE file.
 *
 * Listing the segments explicitly leaves out PT_GNU_STACK.
 */

PHDRS {
    text PT_LOAD FLAGS(5);
}

SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    .text : { *(.text*) } :text
    /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) }
}
