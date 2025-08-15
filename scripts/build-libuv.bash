version='v1.51.0'
source_dir='libuv-source'
archive="libuv-$version.tar.gz"

cd "$DEPS_PATH"

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

cmake --fresh .. \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DLIBUV_BUILD_TESTS=OFF -DLIBUV_BUILD_BENCH=OFF \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE

make -j$(nproc) && make install
