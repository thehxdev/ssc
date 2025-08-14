# SSC
Personal implementation of Shadowsocks protocol with AEAD-2022 ciphers
as described in [SIP022](https://shadowsocks.org/doc/sip022.html).

> [!WARNING]
> This project is in early stages and lacks lots of features and proper
> error/event handling. In order to use Shadowsocks, checkout
> [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust).

## Unique features
- No malloc/free (at least for now). All memory is managed by a single Arena
and some Pool allocators. EVERY allocation, IS reusabel thanks to pool allocators.
This keeps memory usage low and avoids memory fragmentation.

- The config is a single `.c` file that compiles to a `.so` (on unix) or `.dll`
(on windows) and loaded on runtime.

- Unity Build! Build the project with JUST the C compiler and a single command.

## Build
SSC dependes on these projects:
- LibUV: As event loop implementation
- OpenSSL: For encryption/decryption
- BLAKE3: For sub-key derivation with random salt

To build all dependencies, run [`build-deps.bash`](build-deps.bash) script in
project's root directory. This script will install dependencies to `_deps`
subdirectory in the project's root directory (NOT globally).

Edit the [`config.c`](config.c) file. Then build the config and project with
[`build.bash`](build.bash) script.

### Build notes
This project uses [Unity Build](https://en.wikipedia.org/wiki/Unity_build). In
order to build SSC, you just need a C compiler and nothing else! You can build
`ssc-local` executable with this simple command even without the build script:
```bash
cc -std=gnu99 -O2 -DNDEBUG -o 'ssc-local' 'src/local_build.c'
```

## Run
Run the shadowsocks client implementation (`ssc-local`):
```bash
./_build/ssc-local ./_build/config.so
```
If you change the configuration, you must compile `config.c` to `config.so` file again.
