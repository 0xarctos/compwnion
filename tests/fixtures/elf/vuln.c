// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0xarctos
//
// Part of Compwnion - companion tools for pwn quests
// Licensed under the Apache License, Version 2.0; see the LICENSE file.
//
// Deliberately misuses risky libc functions so that explore has call sites to
// find. Only parsed by the tests, never run. Built at -O0 so no call is elided.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char global[64];

void handle(char *input) {
    strcpy(global, input);        // critical
    strcat(global, input);        // critical
    sprintf(global, "value=%s", input);  // critical
    printf(input);                // conditional: format string
    system(input);                // critical
    puts(global);
}

int main(void) {
    char local[32];
    read(0, local, 256);          // conditional: oversized read
    scanf("%s", local);           // critical: unbounded scanf
    handle(local);
    return 0;
}
