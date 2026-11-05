// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.

#include <stdio.h>

// printf with a non-trivial format has a fortified variant, unlike puts.
int main(int argc, char **argv) {
    printf("Hello from %s (%d)\n", argv[0], argc);
    return 0;
}
