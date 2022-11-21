package hologram

import (
	"crypto/cipher"
)

// randCTR is a CTR block mode implementation that supports
// random access. It delegates to the true golang's CTR
// while adding a few features to it.
//
// Delegating to golang's implementation is a consideration
// for performance, as golang's standard library has done
// some optimization upon it.
//
// XXX: this implementation relies strongly on the internal
// implementation of crypto/cipher's CTR, which interprets
// the block as a very-large integer and increments the
// cipher block's counter. We will either continue on using
// the cipher or recreates a key stream block by tweaking.
type randCTR struct {
	b      cipher.Block
	iv     []byte
	offset uint64
	inner  cipher.Stream
}

func newRandCTR(block cipher.Block, iv []byte) *randCTR {
	return &randCTR{
		b:      block,
		iv:     iv,
		offset: 0,
		inner:  cipher.NewCTR(block, iv),
	}
}

func (ctr *randCTR) recreate() *randCTR {
	return newRandCTR(ctr.b, ctr.iv)
}

func (ctr *randCTR) XORKeyStream(dst, src []byte) {
	ctr.inner.XORKeyStream(dst, src)
	ctr.offset += uint64(len(src))
}

func (ctr *randCTR) Tell() uint64 {
	return ctr.offset
}

func (ctr *randCTR) Seek(offset uint64) {
	if offset == ctr.offset {
		return
	}
	blockSize := ctr.b.BlockSize()
	blockSkip := offset % uint64(blockSize)
	blockCtr := offset / uint64(blockSize)
	newIV := make([]byte, blockSize)
	carrier := uint64(0)
	remaining := blockCtr
	for i := blockSize; i > 0; i-- {
		current := remaining & uint64(0x0ff)
		remaining >>= 8
		next := uint64(uint8(ctr.iv[i-1])) + current + carrier
		if next > uint64(0x0ff) {
			carrier = 1
		} else {
			carrier = 0
		}
		newIV[i-1] = byte(next)
	}
	newCtr := cipher.NewCTR(ctr.b, newIV)
	temp := make([]byte, int(blockSkip))
	newCtr.XORKeyStream(temp, temp)
	ctr.offset = offset
	ctr.inner = newCtr
}
