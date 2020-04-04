package seaturtle

import (
	"encoding/binary"
)

func cryptBlock(subkeys []uint32, dst, src []byte, decrypt bool) {
	var t uint64
	left := binary.BigEndian.Uint64(src[0:8])
	right := binary.BigEndian.Uint64(src[8:16])

	if !decrypt {
		// Input Whitening
		left = left ^ concatenate32(subkeys[0], subkeys[1])
		right = right ^ concatenate32(subkeys[2], subkeys[3])

		for i := 0; i < 16; i++ {
			t = left
			left_ := feistelFunction(left, subkeys[4+(i*3)]) ^ concatenate32(subkeys[5+(i*3)], subkeys[6+(i*3)])
			left = left_ ^ right
			right = t
		}

		// Undo Last Swap
		t = left
		left = right
		right = t

		// Output Whitening
		left = left ^ concatenate32(subkeys[52], subkeys[53])
		right = right ^ concatenate32(subkeys[54], subkeys[55])
	} else {
		// Input Whitening
		left = left ^ concatenate32(subkeys[52], subkeys[53])
		right = right ^ concatenate32(subkeys[54], subkeys[55])

		// Perform 16 feistel rounds
		for i := 0; i < 16; i++ {
			t = left
			left_ := feistelFunction(left, subkeys[49+(i*-3)]) ^ concatenate32(subkeys[50+(i*-3)], subkeys[51+(i*-3)])
			left = left_ ^ right
			right = t
		}

		// Undo Last Swap
		t = left
		left = right
		right = t

		// Output Whitening
		left = left ^ concatenate32(subkeys[0], subkeys[1])
		right = right ^ concatenate32(subkeys[2], subkeys[3])
	}

	binary.BigEndian.PutUint64(dst[0:8], left)
	binary.BigEndian.PutUint64(dst[8:16], right)
}

func feistelFunction(input uint64, p uint32) uint64 {
	G1 := gFunction(input, p)

	// Initial PHT without schedule
	for x := 0; x < 4; x += 2 {
		G1[x], G1[x+1] = pht8(G1[x], G1[x+1])
		G1[x+4], G1[x+5] = pht8(G1[x+4], G1[x+5])
	}

	// PHT With Schedule
	numberOfScheduledPHTLayers := 2
	var intermediate [8]uint8
	for j := 0; j < numberOfScheduledPHTLayers; j++ {
		for x := 0; x < 4; x += 2 {
			intermediate[x], intermediate[x+1] = pht8(G1[x*2], G1[(x+1)*2])
			intermediate[x+4], intermediate[x+5] = pht8(G1[1+(x*2)], G1[1+((x+1)*2)])
		}
		G1 = intermediate
	}

	return binary.BigEndian.Uint64(G1[:])
}

func gFunction(input uint64, p uint32) [8]uint8 {
	var s0, s1, s2, s3, s4, s5, s6, s7 uint16
	// Split 64 bit input to four 16 bit blocks
	// s0, s2, s4, s6 have the original input and s1, s3, s5, s7 have derived input
	s0 = uint16(input >> (3 * 16))
	s2 = uint16(input >> (2 * 16))
	s4 = uint16(input >> (1 * 16))
	s6 = uint16(input)
	// Rotate the split blocks as per data p
	s0 = rotate16byN(s0, shift32ToGet4(p, 1), false)
	s2 = rotate16byN(s2, shift32ToGet4(p, 2), false)
	s4 = rotate16byN(s4, shift32ToGet4(p, 3), false)
	s6 = rotate16byN(s6, shift32ToGet4(p, 4), false)
	// Do Expansion and then DDR with data p on four 16 bit blocks
	// Expansion is performed by taking 1 byte each from corresponding s0, s2, s4, s6 and concatenating
	// In case of s7, the second byte for concatenation is the first byte of s0
	s1 = rotate16byN(concatenate8ToGet16(shift16ToGet8(s0, 2), shift16ToGet8(s2, 1)), shift32ToGet4(p, 5), true)
	s3 = rotate16byN(concatenate8ToGet16(shift16ToGet8(s2, 2), shift16ToGet8(s4, 1)), shift32ToGet4(p, 6), true)
	s5 = rotate16byN(concatenate8ToGet16(shift16ToGet8(s4, 2), shift16ToGet8(s6, 1)), shift32ToGet4(p, 7), true)
	s7 = rotate16byN(concatenate8ToGet16(shift16ToGet8(s6, 2), shift16ToGet8(s0, 1)), shift32ToGet4(p, 8), true)
	return [8]uint8{
		// There are 8 16:8 APN S Boxes
		// For the corresponding array implementation, we need to split 16 bits into 8 bits
		sBoxes[0][shift16ToGet8(s0, 1)][shift16ToGet8(s0, 2)],
		sBoxes[1][shift16ToGet8(s1, 1)][shift16ToGet8(s1, 2)],
		sBoxes[2][shift16ToGet8(s2, 1)][shift16ToGet8(s2, 2)],
		sBoxes[3][shift16ToGet8(s3, 1)][shift16ToGet8(s3, 2)],
		sBoxes[4][shift16ToGet8(s4, 1)][shift16ToGet8(s4, 2)],
		sBoxes[5][shift16ToGet8(s5, 1)][shift16ToGet8(s5, 2)],
		sBoxes[6][shift16ToGet8(s6, 1)][shift16ToGet8(s6, 2)],
		sBoxes[7][shift16ToGet8(s7, 1)][shift16ToGet8(s7, 2)],
	}
}

func (s seaTurtleCipher) generateSubKeys(key []byte) {
	uint32KeyWordsCount := len(key) / 4 // Number of 32 bit words needed for initial key (4,6 or 8)
	nextPiWord := 0

	// Put the initial key in SubKeys after XOR with a word of PI
	for i := 0; i < uint32KeyWordsCount; i++ {
		s.subkeys[i] = binary.BigEndian.Uint32(key[i*4:(i*4)+4]) ^ pi[nextPiWord]
		nextPiWord++
	}

	var numberOfRounds, gFuncCount, uint16KeyWordsCount int

	uint16KeyWordsCount = uint32KeyWordsCount * 2
	gFuncCount = 1 // How many G Functions to be run in a Round

	switch uint32KeyWordsCount {
	case 4:
		// 128 Bit Key Schedule Rounds
		numberOfRounds = 13
	case 6:
		// 192 Bit Key Schedule Rounds
		numberOfRounds = 9
	case 8:
		// 256 Bit Key Schedule Rounds
		numberOfRounds = 6
	}

	if uint32KeyWordsCount > 4 {
		gFuncCount = 2
	}

	for i := 0; i < numberOfRounds; i++ {

		G := make([][8]uint8, gFuncCount)
		G[0] = gFunction(concatenate32(s.subkeys[i*uint32KeyWordsCount], s.subkeys[(i*uint32KeyWordsCount)+1]), pi[nextPiWord])
		nextPiWord++
		if gFuncCount == 2 {
			G[1] = gFunction(concatenate32(s.subkeys[4+(i*uint32KeyWordsCount)], s.subkeys[5+(i*uint32KeyWordsCount)]), pi[nextPiWord])
			nextPiWord++
		}

		pArray := make([]uint16, uint16KeyWordsCount)

		// Initialize P Array
		m, n := 0, 0
		for j := 0; j < uint16KeyWordsCount; j++ {
			switch j {
			case 0, 1, 2, 3, 8, 9, 10, 11:
				pArray[j] = concatenate8ToGet16(G[m][n], G[m][n+1])
				n += 2
				if n > 6 {
					m += 1
					n = 0
				}
			case 4, 6, 12, 14:
				pArray[j] = shift32ToGet16(s.subkeys[(i*uint32KeyWordsCount)+(j/2)], 1)
				pArray[j+1] = shift32ToGet16(s.subkeys[(i*uint32KeyWordsCount)+(j/2)], 2)
				j++ // Skip next iteration since we processed for it already
			}
		}

		// Initial PHT without schedule
		for x := 0; x < uint16KeyWordsCount; x += 2 {
			pArray[x], pArray[x+1] = pht16(pArray[x], pArray[x+1])
		}

		// PHT With Schedule
		numberOfScheduledPHTLayers := uint32KeyWordsCount / 2

		//var intermediate [16]uint16
		intermediate := make([]uint16, uint16KeyWordsCount)

		for j := 0; j < numberOfScheduledPHTLayers; j++ {
			for x := 0; x < uint32KeyWordsCount; x += 2 {
				intermediate[x], intermediate[x+1] = pht16(pArray[x*2], pArray[(x+1)*2])
				intermediate[x+uint32KeyWordsCount], intermediate[x+1+uint32KeyWordsCount] = pht16(pArray[1+(x*2)], pArray[1+((x+1)*2)])
			}
			copy(pArray, intermediate)
		}

		nextKeyWord := uint32KeyWordsCount + (i * uint32KeyWordsCount)
		for j := 0; j < uint16KeyWordsCount; j += 2 {
			if nextKeyWord > 55 { // 192 Bit KeySchedule generates more subkeys than necessary, ensure they are not added
				break
			}
			s.subkeys[nextKeyWord] = concatenate16ToGet32(pArray[j], pArray[j+1])
			nextKeyWord++
		}
	}
}
