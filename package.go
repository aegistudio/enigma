// Package hologram implements the simple encrypted filesystem.
//
// The filesystem is specified a block cipher which is used to
// encrypt the subcipher of the filesystem. The subcipher is
// then used to encrypt the file names and data. The path of
// each file is taken into consideration while generating nonce.
//
// Thanks to the CTR mode, the size of each files is the same
// size as their plain text one, and supports random access.
//
// For nonce generation, a crypto random nonce will be generated
// for encrypting the cipher, while file names will have their
// corresponding nonce generated in a deterministic process. The
// file will be encrypted by their file names, which means each
// file must be re-encrypted when it is renamed.
package hologram

import (
	"io/fs"

	"github.com/pkg/errors"
)

// cleanPathError is intended for cleaning path errors for
// both file system and file implementations.
func cleansePathError(name string, err error) error {
	if err == nil {
		return nil
	}
	var pathError *fs.PathError
	if errors.As(err, &pathError) {
		pathError.Path = name
	}
	return err
}

// pathError constructs and create the path error.
func pathError(op, name string, err error) error {
	return &fs.PathError{
		Op:   op,
		Path: name,
		Err:  err,
	}
}
