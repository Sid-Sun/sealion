package seaturtle

import (
	"strconv"
)

type Cipher struct {
	subkeys [56]uint32
}

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "seaturtle: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (*Cipher, error) {

	switch len(key) {
	case 16, 24, 32:
		break
	default:
		return nil, KeySizeError(len(key))
	}

	c := new(Cipher)
	c.generateSubKeys(key)

	return c, nil
}

func (s *Cipher) BlockSize() int {
	return BlockSize
}

func (s *Cipher) Encrypt(src []byte) []byte {
	if len(src) < BlockSize {
		panic("seaturtle: input not full block")
	}

	return cryptBlock(s.subkeys[:], src, false)
}

func (s *Cipher) Decrypt(src []byte) []byte {
	if len(src) < BlockSize {
		panic("seaturtle: input not full block")
	}

	return cryptBlock(s.subkeys[:], src, true)
}
