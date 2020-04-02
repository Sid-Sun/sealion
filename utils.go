package seaturtle

func pht8(a byte, b byte) (byte, byte) {
	a = (a + b) % byte(255)
	b = (a + b) % byte(255)
	return a, b
}

func pht16(a uint16, b uint16) (uint16, uint16) {
	a = (a + b) % uint16(65535)
	b = (a + b) % uint16(65535)
	return a, b
}

func concatenate8ToGet16(a uint8, b uint8) uint16 {
	return (uint16(a) << 8) | uint16(b)
}

func concatenate16ToGet32(a, b uint16) uint32 {
	return (uint32(a) << 16) | uint32(b)
}

func concatenate32(a uint32, b uint32) uint64 {
	return (uint64(a) << 32) | uint64(b)
}

func rotate16byN(x uint16, N uint8, ShiftRight bool) uint16 {
	if ShiftRight {
		return x>>N | x<<(16-N)
	} else {
		return x<<N | x>>(16-N)
	}
}

func shift16ToGet8(x uint16, ind uint8) uint8 {
	// Indexing must start at 1
	return uint8((x << ((ind - 1) * 8)) >> (8))
}

func shift32ToGet4(x uint32, ind uint8) uint8 {
	// Indexing must start at 1
	return uint8((x << ((ind - 1) * 4)) >> (7 * 4))
}

func shift32ToGet16(x uint32, ind uint8) uint16 {
	// Indexing must start at 1
	return uint16((x << ((ind-1)*16)) >> 16)
}
