// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.

#include <stdio.h>

// Gives the compiler nothing to protect: no stack buffer, no fortifiable call.
int main(void) {
    puts("Hello from Compwnion");
    return 0;
}
