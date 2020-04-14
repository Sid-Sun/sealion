package sealion

func pht8(a, b *byte) (byte, byte) {
	temp := (*a + *b) % byte(255)
	return temp, (temp + *b) % byte(255)
}

func pht16(a, b *uint16) (uint16, uint16) {
	temp := (*a + *b) % uint16(65535)
	return temp, (temp + *b) % uint16(65535)
}

func concatenate8ToGet16(a, b uint8) uint16 {
	return (uint16(a) << 8) | uint16(b)
}

func concatenate16ToGet32(a, b *uint16) uint32 {
	return (uint32(*a) << 16) | uint32(*b)
}

func concatenate32(a, b *uint32) uint64 {
	return (uint64(*a) << 32) | uint64(*b)
}

func rotate16RightBy4(x *uint16) {
	*x = (*x)>>4 | (*x)<<(12)
}

func shift16ToGet8(x *uint16, ind uint8) uint8 { //
	// Indexing must start at 1
	return uint8((*x << ((ind - 1) * 8)) >> (8))
}

func shift32ToGet16(x *uint32, ind uint8) uint16 {
	// Indexing must start at 1
	return uint16((*x << ((ind - 1) * 16)) >> 16)
}
