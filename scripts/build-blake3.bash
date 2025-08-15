version='1.8.2'
source_dir='BLAKE3-source'

cd "$DEPS_PATH"

if [[ ! -e "$source_dir" ]]; then
    git clone --depth=1 --branch=$version \
        'https://github.com/BLAKE3-team/BLAKE3' "$source_dir" || exit 1
fi

cd "$source_dir/c"
mkdir -p build && cd build

cmake --fresh .. \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DBLAKE3_EXAMPLES=0 -DBLAKE3_USE_TBB=0 \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE

make -j$(nproc) && make install
