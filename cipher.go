package sealion

import (
	"crypto/cipher"
	"strconv"
)

type seaLionCipher struct {
	subkeys [40]uint32
}

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "sealion: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {

	switch len(key) {
	case 16, 24, 32:
		break
	default:
		return nil, KeySizeError(len(key))
	}

	c := new(seaLionCipher)
	c.subkeys = generateSubKeys(key)

	return c, nil
}

func (s seaLionCipher) BlockSize() int {
	return BlockSize
}

func (s seaLionCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sealion: input not full block")
	}
	cryptBlock(s.subkeys, dst, src, false)
}

func (s seaLionCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sealion: input not full block")
	}
	cryptBlock(s.subkeys, dst, src, true)
}
