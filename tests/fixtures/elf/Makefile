# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0xarctos
#
# Part of Compwnion - companion tools for pwn quests
# Licensed under the Apache License, Version 2.0; see the LICENSE file.

CC ?= gcc
CFLAGS = -O2 -s

HARDENED = -fPIE -pie -fstack-protector-all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fcf-protection=full -z relro -z now -z noexecstack
UNHARDENED = -fno-pie -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fcf-protection=none -z norelro -z execstack
STATIC = -nostdlib -ffreestanding -fno-stack-protector -z noexecstack

BINARIES = hello-pie hello-no-pie hello-hardened hello-unhardened hello-partial-relro \
	hello-no-relro hello-old-dtags hello-no-canary hello-no-fortify hello-execstack \
	hello-not-stripped hello-debuginfo hello-rpath hello-runpath hello-no-cet hello-ibt-only \
	hello-shstk-only hello-lib hello-puts-only hello-bad-symbol \
	static-nostdlib static-nostdlib-32 static-pie-nostdlib static-no-gnustack \
	static-no-gnustack-32 static-rwx-load

all: $(BINARIES)

hello-pie: hello.c
	$(CC) $(CFLAGS) -fPIE -pie -o $@ $<

hello-no-pie: hello.c
	$(CC) $(CFLAGS) -fno-pie -no-pie -o $@ $<

hello-hardened: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -o $@ $<

hello-unhardened: hello.c
	$(CC) $(CFLAGS) $(UNHARDENED) -o $@ $<

hello-partial-relro: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -z lazy -o $@ $<

hello-no-relro: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -z norelro -o $@ $<

hello-old-dtags: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -Wl,--disable-new-dtags -o $@ $<

hello-no-canary: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -fno-stack-protector -o $@ $<

hello-no-fortify: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -o $@ $<

hello-execstack: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -z execstack -o $@ $<

hello-not-stripped: hello.c
	$(CC) -O2 $(HARDENED) -o $@ $<

hello-debuginfo: hello.c
	$(CC) -O2 -g $(HARDENED) -o $@ $<

hello-rpath: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -Wl,--disable-new-dtags,-rpath,/opt/compwnion -o $@ $<

hello-runpath: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -Wl,--enable-new-dtags,-rpath,/opt/compwnion -o $@ $<

hello-no-cet: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -fcf-protection=none -o $@ $<

# gcc accumulates -fcf-protection values until it sees "none".
hello-ibt-only: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -fcf-protection=none -fcf-protection=branch -o $@ $<

hello-shstk-only: hello.c
	$(CC) $(CFLAGS) $(HARDENED) -fcf-protection=none -fcf-protection=return -o $@ $<

hello-lib: hello.c
	$(CC) $(CFLAGS) -shared -fPIC -fstack-protector-all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -z relro -z now -z noexecstack -o $@ $<

hello-puts-only: puts.c
	$(CC) $(CFLAGS) -fPIE -pie -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -o $@ $<

hello-bad-symbol: bad_symbol.c
	$(CC) $(CFLAGS) $(HARDENED) -o $@ $<

static-nostdlib: static.c
	$(CC) $(CFLAGS) -static $(STATIC) -o $@ $<

static-nostdlib-32: static.c
	$(CC) $(CFLAGS) -m32 -static $(STATIC) -o $@ $<

static-pie-nostdlib: static.c
	$(CC) $(CFLAGS) -static-pie -fPIE $(STATIC) -o $@ $<

static-no-gnustack: static.c no_gnustack.ld
	$(CC) $(CFLAGS) -static $(STATIC) -T no_gnustack.ld -o $@ $<

static-no-gnustack-32: static.c no_gnustack.ld
	$(CC) $(CFLAGS) -m32 -static $(STATIC) -T no_gnustack.ld -o $@ $<

static-rwx-load: static.c rwx_load.ld
	$(CC) $(CFLAGS) -static $(STATIC) -T rwx_load.ld -o $@ $<

clean:
	rm -f $(BINARIES)

.PHONY: all clean
