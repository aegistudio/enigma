# Enigma: a simple encrypted filesystem

***(WARN: This project has not been validated or verified for
security. In fact, current implementation is prone to chosen
ciphertext attack. It is strongly not recommended to use this
in production.)***

![build](https://github.com/aegistudio/enigma/actions/workflows/build.yml/badge.svg)
![release](https://img.shields.io/github/release/aegistudio/enigma)
![update](https://img.shields.io/github/release-date/aegistudio/enigma.svg?color=blue&label=update)

Enigma is a simple encrypted filesystem that adds a thin layer of
encryption over native filesystem and keeps your most sensitive
secrets.

[Quickstart for Windows (with WinFSP)](doc/quickstart.md#quickstart-for-windows-with-winfsp)

[Quickstart for Linux (with FUSE)](doc/quickstart.md#quickstart-for-linux-with-fuse)

<p align="center">
<img src="https://github.com/aegistudio/enigma-assets/blob/693f0bd237cc73108e45dacb40eaf142a0255a75/winfsp.gif" width="71%" height="71%"/>
<br/><i>Use Enigma as a Windows local drive through WinFSP</i>
</p>

<p align="center">
<img src="https://github.com/aegistudio/enigma-assets/blob/03198af9acc329642c3a084e05838e4cd4c7ea35/fuse.gif" width="71%" height="71%"/>
<br/><i>Use Enigma as a mount point through FUSE on Linux</i>
</p>

## Roadmap

* Operation Mode
  * [x] Direct mapping mode
  * [ ] POSIX-compatible mode
* Key Specification
  * [x] File (prone to invasion) [^1]
  * [ ] Vault (with [github.com/hashicorp/vault](https://github.com/hashicorp/vault))
  * [ ] HTTP request (remote decryption)
* Integration
  * [x] WinFSP (**Windows** only, with [github.com/aegistudio/go-winfsp](https://github.com/aegistudio/go-winfsp))
  * [x] FUSE (**Linux** and **Mac** only, with [github.com/hanwen/go-fuse](https://github.com/hanwen/go-fuse))
  * [x] HTTP (trivially by Golang's `http` library)
  * [x] FTP (with [github.com/fclairamb/ftpserverlib](https://github.com/fclairamb/ftpserverlib))
  * [ ] NFSv3

## Methods of Encryption

Both the file names and data will be encrypted by an [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
key in [CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR),
which takes trillions of years for the attackers to crack, owing to
the miracles of cryptology.

Encrypting in CTR mode enables the filesystem to random access the
stored content, without bloating the file size. Many CPUs support
hardware accelerating computation of AES-256 block. This is crucial
for implementing a fast, efficient and low overhead file system.

The nonce, which is required by CTR mode to encrypt file names and
data, is generated regarding the path relative to root in filesystem.
Walking down the path to the final component of file name, we compute
the SHA256 hash of its parent's hash concatenating current visited
component. The hash of `/` is the SHA256 digest of the key.

Since all information to calculate the nonce is contained inside the
file or directory's path we are going to visit naturally, we don't
need to spend any extra space to store the nonce.

Under the same directory, encrypting file names with the same nonce
directly is prone to [chosen-plaintext attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack).
To mitigate, we generate a short extra nonce for each file name,
which is computed from the cryptological digest. Then the nonce for
the file name is computed from the digest of the directory it is in,
plus the short extra nonce and the file's length. After being
encrypted, the file name is encoded in Base64 as it is usually in
invalid ASCII or Unicode.

For resisting [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack),
the default extra nonce size is 3 bytes, which yields a birthday
bound of about `Q(H) = 46819.7` files and low possibility bound of
about `n(H;0.25%) = 2813.6` files [^2], and is considered providing
enough security under most circumstances.

The AES-256 key for encrypting the file system, is randomly generated
through a cryptologically secure random process, then encrypted and
authenticated by a root key supports [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption).
This extra indirection enables us to check whether proper key is
specified, and enables online decryption to protect the root key,
without sacrificing the performance.

## License

The project is licensed under [Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0).
Anyone is free to modify and redistribute the code, however they
must swear the oath of keeping users' data and secrets sacred and
depicts what they have modified for users' judgement.

[^1]: Storing your key as regular files on the disk directly can be
a security issue if your physical machine has been invaded. It's not
so risky if the key is transfered over TTY, pipe, socket, etc.
[^2]: Assume native file system supports file name of maximum 128
bytes, there're `(128-1) * 6 / 8 - 1 = 94.25` cases of file names'
length. The number of outputs for file names' nonces is
`H = 94.25 * (2^24) = 1581252608.0`.
