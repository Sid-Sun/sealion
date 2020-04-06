package seaturtle

import (
	"crypto/cipher"
	"strconv"
)

type seaTurtleCipher struct {
	subkeys [56]uint32
}

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "seaturtle: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {

	switch len(key) {
	case 16, 24, 32:
		break
	default:
		return nil, KeySizeError(len(key))
	}

	c := new(seaTurtleCipher)
	c.subkeys = generateSubKeys(key)

	return c, nil
}

func (s seaTurtleCipher) BlockSize() int {
	return BlockSize
}

func (s seaTurtleCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("seaturtle: input not full block")
	}
	cryptBlock(s.subkeys[:], dst, src, false)
}

func (s seaTurtleCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("seaturtle: input not full block")
	}
	cryptBlock(s.subkeys[:], dst, src, true)
}
