# Quickstart

This page is a guide for getting used to Enigma on different
platforms quickly.

Users are recommended to follow this guide for at least once
so that they will have idea of how Enigma work basically,
making it easier for more customized configuration.

# Quickstart for Windows (with WinFSP)

The WinFSP mode is recommended on Windows since it provides the
best integration with lowest overhead.

1. Download and install [WinFSP](https://github.com/winfsp/winfsp).
You can download the MSI from its
[release page](https://github.com/winfsp/winfsp/releases/latest).
Windows is not shipped with native FUSE like support so this
installation is mandatory.
2. Download Enigma from the
[release page](https://github.com/aegistudio/enigma/releases/latest).
The executables for Windows are named `enigma-windows-<arch>.exe`.
Choose the one that fits in your CPU architecture.
3. Create a text file like `E:\password.txt` and type in some
content. The internal content serves as the key to encrypt. It
might not seen to be secure enough but is okay to start with.
4. Create a directory like `E:\enigma`. It will become the
underlying root directory of the Enigma's encrypted storage.
5. Launch a `cmd` or `powershell` shell and navigate to the
downloaded Enigma executable file. For convenience, you might
rename it to `enigma.exe`.
6. Initialize the Enigma storage through a command like
`.\enigma.exe --aes256-sha256 "E:\password.txt" --path "E:\enigma" init`.
The `--aes256-sha256` means to take the SHA-256 digest of
specified file as AES-256 key. And the `--path` specifies the
root of the Enigma storage.
7. Finally, mount the Windows local drive by
`.\enigma.exe --aes256-sha256 "E:\password.txt" --path "E:\enigma" winfsp`.
By default it will be mounted on `Q:` drive, but you might specify
`--mount "X:"` to mount it on `X:` drive or something else alike.

# Quickstart for Linux (with FUSE)

The FUSE mode is recommended on Linux, and since FUSE is often
shipped with newer version Linux, there's no extra installation
to be done.

1. Download Enigma from the
[release page](https://github.com/aegistudio/enigma/releases/latest).
The executable for Linux are named `enigma-linux-<arch>`. Choose
the one that fits in your CPU architecture. You might rename it
to `./enigma` for convenience.
2. Create a text file like `./password.txt` and types in some
content. The internal content serves as the key to encrypt. It
might not seen to be secure enough but is okay to start with.
3. Create a directory like `./store`. It will become the
underlying root directory of the Enigma's encrypted storage.
4. Initialize the Enigma storage through a command like
`./enigma --aes256-sha256 "./password.txt" --path "./store" init`.
The `--aes256-sha256` means to take the SHA-256 digest of
specified file as AES-256 key. And the `--path` specifies the
root of the Enigma storage.
5. Create a directory like `./mountpoint`. It will become the
mountpoint where Enigma is mounted later.
6. Finally, mount the FUSE mountpoint by
`./enigma --aes256-sha256 "./password.txt" --path "./store" fuse ./mountpoint`.
The `./mountpoint` is accessible as long as the `enigma` program
is running.
