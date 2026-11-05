// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.
//
// The format string comes straight from attacker input, so deep analysis must
// confirm the printf call as a real format-string bug. Parsed, not run.

#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buffer[128];
    read(0, buffer, sizeof(buffer));  // fills buffer with input
    printf(buffer);                   // format string straight from input
    return 0;
}
