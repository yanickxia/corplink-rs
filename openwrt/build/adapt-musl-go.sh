#!/bin/sh
set -eu
# The pinned Go 1.25.5 archive has exactly one Linux/amd64 init_array entry.
mkdir -p /work/musl-compat
cd /work/src/libwg
ar p libwg.a go.o > /work/musl-compat/go.o
readelf -SW /work/musl-compat/go.o | grep -Eq '\.init_array +INIT_ARRAY +[[:xdigit:]]+ +[[:xdigit:]]+ +000008 '
readelf -rW /work/musl-compat/go.o | grep -q 'R_X86_64_64.*_rt0_amd64_linux_lib + 0'
objcopy --remove-section .init_array --globalize-symbol=_rt0_amd64_linux_lib /work/musl-compat/go.o
cc -O2 -fPIC -c /work/musl-go-init.c -o /work/musl-compat/musl-go-init.o
ar rD libwg.a /work/musl-compat/go.o /work/musl-compat/musl-go-init.o
