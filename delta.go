//implementation based on the rsync algorithm (https://rsync.samba.org/tech_report/node2.html)
// Circular buffer interface based on https://github.com/balena-os/circbuf
// code implementation based on https://github.com/balena-os/librsync-go

package rollingHash

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
)

const (
	// Md4SigMagic A signature file with MD4 signatures.
	Md4SigMagic MagicNumber = 0x72730136

	// Blake2SigMagic A signature file using the BLAKE2 hash.
	Blake2SigMagic MagicNumber = 0x72730137
)

type Bytes struct {
	Offset  int    // End of diff position in block
	Start   int    // Start of diff position in block
	Missing bool   // true if Block not found
	Lit     []byte // Literal bytes to replace in delta
}

func newBlock(index int, literalMatches []byte, blockSize int) Bytes {
	return Bytes{
		Start:  index * blockSize,               // Block change start
		Offset: (index * blockSize) + blockSize, // Block change endwhereas it could be copied-on-write to a new data structure
		Lit:    literalMatches,                  // Store literal matches
	}
}

type Delta map[int]Bytes

func (d Delta) Add(index int, b Bytes) {
	d[index] = b
}

func CalcDelta(sig *SignatureType, i io.Reader, output io.Writer, blockSize int) (map[int]Bytes, error) {
	input := bufio.NewReader(i)

	weakSum := NewRollSum()
	delta := make(Delta)
	var tmp []byte

	for {
		in, err := input.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		weakSum.Rollin(in)
		if weakSum.count < uint64(sig.blockLen) {
			continue
		}

		if weakSum.count > uint64(sig.blockLen) {
			weakSum.Rollout()
			tmp = append(tmp, weakSum.old)
		}

		index, err := Seek(sig, weakSum.Digest(), weakSum.window)
		if err != nil {
			return nil, err
		}
		if ^index != 0 {
			nb := newBlock(index, tmp, blockSize)
			delta.Add(index, nb)
			weakSum.Reset()
			tmp = []byte{}
		}
	}

	delta = IntegrityCheck(sig, delta, blockSize)
	weakSum.Reset()
	tmp = []byte{}

	return delta, binary.Write(output, binary.BigEndian, OpEnd)
}

func Seek(sig *SignatureType, wk uint32, b []byte) (int, error) {
	if _, ok := sig.weak2block[wk]; ok {
		strong, _ := CalcStrongSum(b, sig.sigType, sig.strongLen)
		for _, s := range sig.strongSigs {
			if bytes.Equal(s, strong) {
				return sig.weak2block[wk], nil
			}
		}
	}
	return -1, nil
}

func IntegrityCheck(sig *SignatureType, matches Delta, blockSize int) Delta {
	for i := range sig.strongSigs {
		if _, ok := matches[i]; !ok {
			matches[i] = Bytes{
				Offset:  (i * blockSize) + blockSize,
				Start:   i * blockSize,
				Missing: true,
			}
		}
	}
	return matches
}
