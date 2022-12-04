package enigma

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandCTR(t *testing.T) {
	assert := assert.New(t)
	var err error
	dataSize := int(1 << 20)
	sampleTimes := int(1 << 10)
	bufSize := int(1 << 16)
	r := cryptoRand.Reader

	// Construct the referential data for testing.
	plain := make([]byte, dataSize)
	_, err = r.Read(plain)
	assert.NoError(err)
	key := make([]byte, 32) // AES-256
	_, err = r.Read(key)
	assert.NoError(err)
	iv := make([]byte, aes.BlockSize)
	_, err = r.Read(iv)
	assert.NoError(err)
	block, err := aes.NewCipher(key)
	assert.NoError(err)
	ctrStream := cipher.NewCTR(block, iv)
	cipher := make([]byte, dataSize)
	ctrStream.XORKeyStream(cipher, plain)

	// Create our random stream for testing.
	randCTRStream := newRandCTR(block, iv)

	// Randomly choose some data range and perform testing.
	var seedBuf [8]byte
	_, err = r.Read(seedBuf[:])
	assert.NoError(err)
	src := rand.NewSource(int64(binary.LittleEndian.Uint64(seedBuf[:])))
	rand := rand.New(src)
	buf := make([]byte, bufSize)
	for i := 0; i < sampleTimes; i++ {
		start := rand.Intn(dataSize)
		size := rand.Intn(len(buf))
		end := start + size
		if end > dataSize {
			end = dataSize
			size = dataSize - start
		}
		dst := buf[:size]
		randCTRStream.Seek(uint64(start))
		randCTRStream.XORKeyStream(dst, plain[start:end])
		assert.Equal(dst, cipher[start:end])
	}
}
