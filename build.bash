#!/usr/bin/env bash

log_run() {
    echo "[X] $@"
    $@
}

SELF_PATH=$(dirname "$(realpath "$0")")
DEPS_PATH="$SELF_PATH/_deps"
BUILD_PATH="$SELF_PATH/_build"
SRC_PATH="$SELF_PATH/src"

CFLAGS=(-std=gnu99 -Wall -Wextra -Wshadow -O3 -DNDEBUG)
LDFLAGS=()
LIBS=(-l:libev.a -l:libblake3.a -l:libcrypto.a -ldl)

if [[ -z $CC ]]; then
    CC=cc
fi

mkdir -p "$BUILD_PATH"

# build config
log_run $CC -fPIC -shared -o "$BUILD_PATH/config.so" "$SELF_PATH/config.c"

# build ssc-local
log_run $CC \
    "${CFLAGS[@]}" "${LDFLAGS[@]}" \
    -DSSC_OS_UNIX=1 \
    -I"$DEPS_PATH/include" \
    -I"$SELF_PATH/src" \
    -L"$DEPS_PATH/lib" \
    -o "$BUILD_PATH/ssc-local" \
    "$SRC_PATH/local_build.c" \
    -l:libuv.a -l:libblake3.a -l:libcrypto.a -ldl
