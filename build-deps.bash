#!/usr/bin/env bash

# This script will setup dependencies in the project root directory because I
# hate installing them system-wide :)

# project root directory path
export ROOT_PATH=$(dirname "$(realpath "$0")")
export DEPS_PATH="$ROOT_PATH/_deps"
export CMAKE_BUILD_TYPE=Release

mkdir -p "$DEPS_PATH/lib"
if [[ ! -e "$DEPS_PATH/lib64" ]]; then
    ln -sfr "$DEPS_PATH/lib" "$DEPS_PATH/lib64"
fi

for s in $(find "$ROOT_PATH/scripts/" -name "*.bash"); do
    bash "$s"
done
