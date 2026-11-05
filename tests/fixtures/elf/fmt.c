// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.
//
// Only calls printf with a constant format: explore must mask these, since a
// constant format cannot carry attacker-controlled specifiers. Parsed, not run.

#include <stdio.h>

int main(void) {
    printf("ready\n");            // constant format: masked
    printf("value=%d\n", 7);      // constant format: masked
    return 0;
}
