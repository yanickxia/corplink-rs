#!/bin/sh
set -eu
rustc_program="$1"
shift
previous=""
build_tool=false
corplink_binary=false
for argument in "$@"; do
    if [ "$previous" = "--crate-name" ] && [ "$argument" = "build_script_build" ]; then
        build_tool=true
    fi
    if [ "$previous" = "--crate-name" ] && [ "$argument" = "corplink_rs" ]; then
        corplink_binary=true
    fi
    previous="$argument"
done
if [ "$build_tool" = true ]; then
    exec "$rustc_program" "$@" -C target-feature=-crt-static
fi
if [ "$corplink_binary" = true ]; then
    exec "$rustc_program" "$@" -C relocation-model=static -C link-arg=-no-pie -C link-arg=-Wl,--wrap=__libc_start_main
fi
exec "$rustc_program" "$@"
