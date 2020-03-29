package seaturtle

import (
	"encoding/binary"
)

// Encrypt one block from src into dst, using the subkeys.
func encryptBlock(subkeys []uint32, dst, src []byte) {
	cryptBlock(subkeys, dst, src, false)
}

// Decrypt one block from src into dst, using the subkeys.
func decryptBlock(subkeys []uint32, dst, src []byte) {
	cryptBlock(subkeys, dst, src, true)
}

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
			left_ := feistelFunction(left, subkeys[49 +(i*-3)]) ^ concatenate32(subkeys[50 +(i*-3)], subkeys[51 +(i*-3)])
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

func (s seaturtleCipher) generateSubKeys(key []byte) {
	numberOfWordsForInitialKey := len(key) / 4 // Number of 32 bit words needed for initial key (4,6 or 8)
	nextPiWord := 0
	// Put the initial key in SubKeys after XOR with a word of PI
	for i := 0; i < numberOfWordsForInitialKey; i++ {
		s.subkeys[i] = binary.BigEndian.Uint32(key[i*4:(i*4)+4]) ^ pi[nextPiWord]
		nextPiWord++
	}
	switch numberOfWordsForInitialKey {
	// TODO: Convert Different KeySchedules to a single, generic one
	case 4:
		// 128 Bit Key Schedule Rounds
		numberOfRounds := 13
		for i := 0; i < numberOfRounds; i++ {
			G1 := gFunction(concatenate32(s.subkeys[i*4], s.subkeys[(i*4)+1]), pi[nextPiWord])
			nextPiWord++
			var pArray [8]uint16
			// Initialize P Array
			pArray[0] = concatenate8ToGet16(G1[0], G1[1])
			pArray[1] = concatenate8ToGet16(G1[2], G1[3])
			pArray[2] = concatenate8ToGet16(G1[4], G1[5])
			pArray[3] = concatenate8ToGet16(G1[6], G1[7])
			pArray[4] = shift32ToGet16(s.subkeys[(i*4)+2], 1)
			pArray[5] = shift32ToGet16(s.subkeys[(i*4)+2], 2)
			pArray[6] = shift32ToGet16(s.subkeys[(i*4)+3], 1)
			pArray[7] = shift32ToGet16(s.subkeys[(i*4)+3], 2)
			// Initial PHT without schedule
			for x := 0; x < 8; x += 2 {
				pArray[x], pArray[x+1] = pht16(pArray[x], pArray[x+1])
			}
			// PHT With Schedule
			numberOfScheduledPHTLayers := numberOfWordsForInitialKey / 2
			var intermediate [8]uint16
			for j := 0; j < numberOfScheduledPHTLayers; j++ {
				for x := 0; x < 4; x += 2 {
					intermediate[x], intermediate[x+1] = pht16(pArray[x*2], pArray[(x+1)*2])
					intermediate[x+4], intermediate[x+5] = pht16(pArray[1+(x*2)], pArray[1+((x+1)*2)])
				}
				pArray = intermediate
			}
			nextKeyWord := 4 + (i * 4)
			for i := 0; i < 8; i += 2 {
				s.subkeys[nextKeyWord] = concatenate16ToGet32(pArray[i], pArray[i+1])
				nextKeyWord++
			}
		}
	case 6:
		// 192 Bit Key Schedule Rounds
		numberOfRounds := 9
		for i := 0; i < numberOfRounds; i++ {
			G1 := gFunction(concatenate32(s.subkeys[i*6], s.subkeys[(i*6)+1]), pi[nextPiWord])
			nextPiWord++
			G2 := gFunction(concatenate32(s.subkeys[4+(i*6)], s.subkeys[5+(i*6)]), pi[nextPiWord])
			nextPiWord++
			var pArray [12]uint16
			// Initialize P Array
			pArray[0] = concatenate8ToGet16(G1[0], G1[1])
			pArray[1] = concatenate8ToGet16(G1[2], G1[3])
			pArray[2] = concatenate8ToGet16(G1[4], G1[5])
			pArray[3] = concatenate8ToGet16(G1[6], G1[7])
			pArray[4] = shift32ToGet16(s.subkeys[(i*6)+2], 1)
			pArray[5] = shift32ToGet16(s.subkeys[(i*6)+2], 2)
			pArray[6] = shift32ToGet16(s.subkeys[(i*6)+3], 1)
			pArray[7] = shift32ToGet16(s.subkeys[(i*6)+3], 2)
			pArray[8] = concatenate8ToGet16(G2[0], G2[1])
			pArray[9] = concatenate8ToGet16(G2[2], G2[3])
			pArray[10] = concatenate8ToGet16(G2[4], G2[5])
			pArray[11] = concatenate8ToGet16(G2[6], G2[7])
			// Initial PHT without schedule
			for x := 0; x < 12; x += 2 {
				pArray[x], pArray[x+1] = pht16(pArray[x], pArray[x+1])
			}
			// PHT With Schedule
			numberOfScheduledPHTLayers := numberOfWordsForInitialKey / 2
			var intermediate [12]uint16
			for j := 0; j < numberOfScheduledPHTLayers; j++ {
				for x := 0; x < 6; x += 2 {
					intermediate[x], intermediate[x+1] = pht16(pArray[x*2], pArray[(x+1)*2])
					intermediate[x+6], intermediate[x+7] = pht16(pArray[1+(x*2)], pArray[1+((x+1)*2)])
				}
				pArray = intermediate
			}
			nextKeyWord := 6 + (i * 6)
			for i := 0; i < 12; i += 2 {
				if !(nextKeyWord > 56) { // 192 Bit KeySchedule generates more subkeys than necessary, ensure they are not added
					s.subkeys[nextKeyWord] = concatenate16ToGet32(pArray[i], pArray[i+1])
					nextKeyWord++
				} else {
					break
				}
			}
		}
	case 8:
		// 256 Bit Key Schedule Rounds
		numberOfRounds := 6
		for i := 0; i < numberOfRounds; i++ {
			G1 := gFunction(concatenate32(s.subkeys[i*8], s.subkeys[(i*8)+1]), pi[nextPiWord])
			nextPiWord++
			G2 := gFunction(concatenate32(s.subkeys[4+(i*8)], s.subkeys[5+(i*8)]), pi[nextPiWord])
			nextPiWord++
			var pArray [16]uint16
			// Initialize P Array
			pArray[0] = concatenate8ToGet16(G1[0], G1[1])
			pArray[1] = concatenate8ToGet16(G1[2], G1[3])
			pArray[2] = concatenate8ToGet16(G1[4], G1[5])
			pArray[3] = concatenate8ToGet16(G1[6], G1[7])
			pArray[4] = shift32ToGet16(s.subkeys[(i*8)+2], 1)
			pArray[5] = shift32ToGet16(s.subkeys[(i*8)+2], 2)
			pArray[6] = shift32ToGet16(s.subkeys[(i*8)+3], 1)
			pArray[7] = shift32ToGet16(s.subkeys[(i*8)+3], 2)
			pArray[8] = concatenate8ToGet16(G2[0], G2[1])
			pArray[9] = concatenate8ToGet16(G2[2], G2[3])
			pArray[10] = concatenate8ToGet16(G2[4], G2[5])
			pArray[11] = concatenate8ToGet16(G2[6], G2[7])
			pArray[12] = shift32ToGet16(s.subkeys[(i*8)+6], 1)
			pArray[13] = shift32ToGet16(s.subkeys[(i*8)+6], 2)
			pArray[14] = shift32ToGet16(s.subkeys[(i*8)+7], 1)
			pArray[15] = shift32ToGet16(s.subkeys[(i*8)+7], 2)
			// Initial PHT without schedule
			for x := 0; x < 16; x += 2 {
				pArray[x], pArray[x+1] = pht16(pArray[x], pArray[x+1])
			}
			// PHT With Schedule
			numberOfScheduledPHTLayers := numberOfWordsForInitialKey / 2
			var intermediate [16]uint16
			for j := 0; j < numberOfScheduledPHTLayers; j++ {
				for x := 0; x < 8; x += 2 {
					intermediate[x], intermediate[x+1] = pht16(pArray[x*2], pArray[(x+1)*2])
					intermediate[x+8], intermediate[x+9] = pht16(pArray[1+(x*2)], pArray[1+((x+1)*2)])
				}
				pArray = intermediate
			}
			nextKeyWord := 8 + (i * 8)
			for i := 0; i < 16; i += 2 {
				s.subkeys[nextKeyWord] = concatenate16ToGet32(pArray[i], pArray[i+1])
				nextKeyWord++
			}
		}
	}
}
