package hologram

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// nonceType value correlated to path from root.
//
// For the CTR block mode, since the block size of AES-256 is
// 16, we assign directories to use [0:16] for encrypting file
// name and assign files to use [16:] for encrypting data.
type nonceType [32]byte

// newNonce attempts to create a new nonce by hashing input.
func newNonce(input []byte) nonceType {
	return nonceType(sha256.Sum256(input))
}

// evaluateNonce attempts to evaluate the next layer of nonce.
func (n nonceType) evaluateNonce(name []byte) nonceType {
	var message []byte
	message = append(message, n[:]...)
	message = append(message, []byte("nonce")...)
	message = append(message, name...)
	return newNonce(message)
}

// evaluateNoncePrefix attempts to evaluate the nonce prefix
// for the specified name.
func (n nonceType) evaluateNoncePrefix(name []byte) []byte {
	var nonceInput []byte
	nonceInput = append(nonceInput, n[:]...)
	nonceInput = append(nonceInput, []byte("noncePrefix")...)
	nonceInput = append(nonceInput, name...)
	nonceOutput := sha256.Sum256(nonceInput)
	var noncePrefix []byte
	for i := 0; i < maxNoncePrefix; i++ {
		// Append one or more keys into the path component.
		current := nonceOutput[i]
		noncePrefix = append(noncePrefix, current)
		if int(uint8(current)) < 0x080 {
			break
		}
	}
	return noncePrefix
}

// xorNameCipher encrypts or decrypts the specified content.
func (n nonceType) xorNameCipher(
	block cipher.Block, noncePrefix, name []byte,
) []byte {
	var ivInput []byte
	ivInput = append(ivInput, n[:]...)
	ivInput = append(ivInput, []byte("cipher")...)
	ivInput = append(ivInput, noncePrefix...)
	var lenBuf [binary.MaxVarintLen64]byte
	varLen := binary.PutUvarint(lenBuf[:], uint64(len(name)))
	ivInput = append(ivInput, lenBuf[:varLen]...)
	ivArray := sha256.Sum256(ivInput)
	iv := ivArray[0:16]
	result := make([]byte, len(name))
	cipher.NewCTR(block, iv[:]).XORKeyStream(result, name)
	return result
}

// encryptName attempts to evaluate the file name with the
// specified cache value.
func (n nonceType) encryptName(
	block cipher.Block, name []byte,
) string {
	var result []byte
	noncePrefix := n.evaluateNoncePrefix(name)
	cipherText := n.xorNameCipher(block, noncePrefix, name)
	result = append(result, noncePrefix...)
	result = append(result, cipherText...)
	return "@" + base64.RawURLEncoding.EncodeToString(result)
}

// decryptName attempts to decrypt the real name of a file
// and checks whether it is a valid file name.
func (n nonceType) decryptName(
	block cipher.Block, name []byte,
) string {
	if len(name) < 1 || name[0] != '@' {
		return ""
	}
	name = name[1:]
	name, err := base64.RawURLEncoding.DecodeString(string(name))
	if err != nil {
		return ""
	}

	// Extract the nonce prefix from the list.
	var noncePrefix []byte
	for i := 0; i < maxNoncePrefix; i++ {
		current := name[0]
		noncePrefix = append(noncePrefix, current)
		name = name[1:]
		if int(uint8(current)) < 0x080 {
			break
		}
	}

	// Evaluate and validate whether the cipher is valid.
	plainText := n.xorNameCipher(block, noncePrefix, name)
	trueNoncePrefix := n.evaluateNoncePrefix(plainText)
	if !bytes.Equal(noncePrefix, trueNoncePrefix) {
		return ""
	}
	return string(plainText)
}
