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
SSC depends on these projects:
- LibUV: As event loop implementation
- OpenSSL: For encryption/decryption
- BLAKE3: For sub-key derivation with random salt

### Dependencies
Build dependencies before building `ssc`. All dependencies will be installed on
the project root directory and NOT system-wide.

#### Unix-like
On Unix-like systems use [`build-deps.bash`](build-deps.bash) to install all
dependencies locally on project root directory.

#### x64 Windows
Use `vcpkg` to install dependencies on windows. Run these commands on project
root directory:
```powershell
git clone --depth=1 "https://github.com/microsoft/vcpkg.git"
cd .\vcpkg\
.\bootstrap-vcpkg.bat
.\vcpkg install openssl libuv blake3 --triplet x64-windows
cd ..\
```

### SSC
Edit the [`config.c`](config.c) file. Then build the config and project using
the build script. On Unix-like systems use [`build.bash`](build.bash) and on
x64 Windows use [`build.bat`](build.bat) script.

To rebuild the project just re-run the build script.


## Run
Run the Shadowsocks client implementation (`ssc-local`):
```bash
# Unix-like
./_build/ssc-local ./_build/config.so

# Windows
.\_build\ssc-local.exe .\_build\config.dll
```

> [!NOTE]
> Once you changed `config.c` file, run build script again.
