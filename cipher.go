package seaturtle

import (
	"crypto/cipher"
	"strconv"
)

type seaturtleCipher struct {
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

	c := new(seaturtleCipher)
	c.generateSubKeys(key)

	return c, nil
}

func (s seaturtleCipher) BlockSize() int {
	return BlockSize
}

func (s seaturtleCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("seaturtle: input not full block")
	}

	if len(dst) < BlockSize {
		panic("seaturtle: output not full block")
	}

	encryptBlock(s.subkeys[:], dst, src)
}

func (s seaturtleCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("seaturtle: input not full block")
	}

	if len(dst) < BlockSize {
		panic("seaturtle: output not full block")
	}

	decryptBlock(s.subkeys[:], dst, src)
}
