// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.
//
// A non-constant format passed WITH a variadic argument: still worth flagging,
// but not the textbook single-argument format string, so explore must not tag
// it "single-arg". Parsed by the tests, never run.

#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buffer[128];
    read(0, buffer, sizeof(buffer));  // fills the format with input
    printf(buffer, 1);                // non-constant format, one variadic arg
    return 0;
}
