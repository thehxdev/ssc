# SSC
Personal implementation of Shadowsocks protocol with AEAD-2022 ciphers
as described in [SIP022](https://shadowsocks.org/doc/sip022.html).

> [!WARNING]
> This project is in early stages and lacks lots of features and proper
> error/event handling. In order to use Shadowsocks, checkout
> [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust).


## Unique features
- 100% written by human. No AI shit. (It's a feature these days)

- No malloc/free. All memory is managed by a single Arena and some Pool
allocators. EVERY allocation, IS reusable thanks to pool allocators. This keeps
memory usage low and avoids memory fragmentation and null pointer crashes.

- The config is a single `.c` file that compiles to a `.so` (on Unix) or `.dll`
(on Windows) and loaded on runtime.

- Unity Build!


## Build
SSC depends on these libraries:
- LibUV: As event loop implementation and I/O abstraction
- OpenSSL: Encryption/Decryption
- BLAKE3: Sub-key derivation with random salt

### Dependencies
Use `vcpkg` to install dependencies. Run these commands on project root directory:
```bash
git clone --depth=1 "https://github.com/microsoft/vcpkg.git"
cd ./vcpkg

# Windows
./bootstrap-vcpkg.bat

# Unix
./bootstrap-vcpkg.sh

./vcpkg install openssl libuv blake3
cd ..
```

### SSC
Then use `cmake` to build the project:
```bash
mkdir -p build ; cd build

cmake .. --fresh -DCMAKE_TOOLCHAIN_FILE:FILEPATH="../vcpkg/scripts/buildsystems/vcpkg.cmake"

cmake --build .
```

## Run
Run the Shadowsocks client implementation (`ssc-local`):
```bash
# Unix-like
./build/ssc-local ./build/config.so

# Windows
.\build\ssc-local.exe .\build\config.dll
```

> [!NOTE]
> Once you changed `config.c` file, rebuild project.
