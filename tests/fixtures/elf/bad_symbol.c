// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.

// Imports a symbol whose name is not valid UTF-8. It needs a function type
// because LIEF does not list untyped undefined symbols as imports.
extern void bad_symbol(void) __asm__("bad_symbol_\xff") __attribute__((weak));
__asm__(".type bad_symbol_\xff, @function");

int main(void) {
    if (bad_symbol) {
        bad_symbol();
    }
    return 0;
}
