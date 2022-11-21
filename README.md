# Hologram: a simple encrypted filesystem

Hologram is a simple encrypted filesystem implementation that encrypts
a directory tree and expose it as a filesystem interface.

## Overview

Hologram encrypts and ensure confidentiality for both file names and
data. It takes the path information in filesystem into consideration,
forming their nonce for encryption.

For file name, to increase the difficulty of guessing their name in
path, a nonce prefix of random length will also be generated with
respect to the file name. The name is base64 encoded since the cipher
text of name is literally arbitrary data.

Since the file name and data encryption is correlated to their path
in tree, renaming file or directory is not atomic. That means we will
have to decrypt every content in the source path and re-encrypt them
in the destinattion path. So you must pay extra attention when working
with rename-based application, such as log rotation system and data
base systems.

The file name and data will be encrypted in CTR block mode, which
supports random accessing each files.
