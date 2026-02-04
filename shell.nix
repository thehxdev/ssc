{ pkgs ? import <nixpkgs> { } }:
let
    inherit (pkgs) mkShell;
    inherit (pkgs.lib) makeLibraryPath;

    dependencyLibraries = with pkgs; [
        libuv
        libblake3
        openssl
    ];
in
    mkShell {
        nativeBuildInputs = with pkgs; [
            gcc
            gnumake
            cmake
            pkg-config
        ];

        buildInputs = dependencyLibraries;

        packages = with pkgs; [
            gdb
            clang-tools
        ];

        shellHook = ''
        export CC=gcc
        export CXX=g++
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${ makeLibraryPath dependencyLibraries }
        '';
    }
