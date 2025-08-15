#!/usr/bin/env bash

# This script will setup dependencies in the project root directory because I
# hate installing them system-wide :)

set -x

# project root directory path
ROOT_PATH=$(dirname "$(realpath "$0")")
DEPS_PATH="$ROOT_PATH/_deps"

CMAKE_BUILD_TYPE=Release

build_openssl() {
    local version='3.5.1'
    local archive="openssl-$version.tar.gz"
    local source_dir="openssl-source"
    cd "$DEPS_PATH"
    if [[ -e "$source_dir" ]]; then
        return 0
    fi
    if [[ ! -e "$archive" ]]; then
        curl -L -# \
            -o "$archive" \
            "https://github.com/openssl/openssl/releases/download/openssl-$version/$archive" \
            || exit 1
    fi
    mkdir -p "$source_dir"
    tar -xzf "$archive" -C "$source_dir" --strip-components=1 || exit 1
    cd "$source_dir"
    ./Configure \
        --prefix="$DEPS_PATH" \
        --release \
        no-deprecated
    make -j$(nproc) && make install
    cd "$ROOT_PATH"
}

build_blake3() {
    local version='1.8.2'
    local source_dir='BLAKE3-source'
    cd "$DEPS_PATH"
    if [[ ! -e "$source_dir" ]]; then
        git clone --depth=1 --branch=$version \
            'https://github.com/BLAKE3-team/BLAKE3' "$source_dir" || exit 1
    else
        return 0
    fi
    cd "$source_dir/c"
    mkdir -p build && cd build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
        -DBLAKE3_EXAMPLES=0 -DBLAKE3_USE_TBB=0 \
        -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE
    make -j$(nproc) && make install
    cd "$ROOT_PATH"
}

build_libuv() {
    local version='v1.51.0'
    local source_dir='libuv-source'
    local archive="libuv-$version.tar.gz"
    cd "$DEPS_PATH"
    if [[ -e "$source_dir" ]]; then
        return 0
    fi
    if [[ ! -e "$archive" ]]; then
        curl -L -# \
            -o "$archive" \
            "https://dist.libuv.org/dist/$version/libuv-$version.tar.gz" \
            || exit 1
    fi
    mkdir -p "$source_dir"
    tar -xzf "$archive" -C "$source_dir" --strip-components=1 || exit 1
    cd "$source_dir"
    mkdir -p build && cd build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
        -DLIBUV_BUILD_TESTS=OFF -DLIBUV_BUILD_BENCH=OFF \
        -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE
    make -j$(nproc) && make install
    cd "$ROOT_PATH"
}

mkdir -p "$DEPS_PATH/lib"
if [[ ! -e "$DEPS_PATH/lib64" ]]; then
    ln -sfr "$DEPS_PATH/lib" "$DEPS_PATH/lib64"
fi

# build_openssl
build_libuv
build_blake3
