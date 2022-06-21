package rollingHash

import (
	"bufio"
	"bytes"
	"github.com/stretchr/testify/require"
	"testing"
)

func CalculateDelta(a []byte, b []byte, t *testing.T) map[int]Bytes {
	blockSize := 1 << 4 // 16 bytes

	bytesA := bytes.NewReader(a)
	bytesB := bytes.NewReader(b)

	bufioA := bufio.NewReader(bytesA)
	bufioB := bufio.NewReader(bytesB)

	// For each block slice from file
	sig := signature(t, bufioA, blockSize)

	var buf bytes.Buffer
	delta, err := CalcDelta(sig, bufioB, &buf, blockSize)
	require.NoError(t, err)
	return delta
}

func CheckMatch(delta map[int]Bytes, expected map[int][]byte, t *testing.T) {
	for i := range expected {
		// Index not matched in delta
		if _, ok := delta[i]; !ok {
			t.Errorf("Expected match corresponding index for delta %d", i)
		}

		literal := delta[i].Lit
		expect := expected[i]

		if string(literal) != string(expect) {
			t.Errorf("want \"%s\", got \"%s\" ", expect, literal)
		}
	}
}

func TestDelta(t *testing.T) {
	t.Run("chunk change", func(t *testing.T) {
		a := []byte("i am here guys how are you doing this is a small test for chunk split and rolling hash")
		b := []byte("i here guys how are you doing this is a mall test chunk split and rolling hash")
		expect := map[int][]byte{
			1: []byte("i here guys h"),               // Match first block change
			4: []byte(" this is a mall test chunk "), // Match block 4 changed

		}

		delta := CalculateDelta(a, b, t)
		CheckMatch(delta, expect, t)
	})

	t.Run("chunk add", func(t *testing.T) {
		a := []byte("i am here guys how are you doing this is a small test for chunk split and rolling hash")
		b := []byte("i am here guys how are you doingadded this is a small test for chunk split and rolling hash")
		expect := map[int][]byte{
			2: []byte("added"), // Match blocks 2 changed

		}
		delta := CalculateDelta(a, b, t)
		CheckMatch(delta, expect, t)
	})

	t.Run("chunk removal", func(t *testing.T) {
		a := []byte("i am here guys how are you doing this is a small test for chunk split and rolling hash")
		b := []byte("ow are you doing this is a small split and rolling hash")
		delta := CalculateDelta(a, b, t)

		// Check for block 1 and block 3 removal
		if delta[0].Missing == false && delta[3].Missing == false {
			t.Errorf("Expected delta first and third block missing")
		}

		// Match block missing position should be eq to expected based on block bytes size
		matchPositionForBlock1 := delta[0].Start == 0 && delta[0].Offset == 16
		matchPositionForBlock3 := delta[3].Start == 48 && delta[3].Offset == 64

		if !matchPositionForBlock1 {
			t.Errorf("Expected delta range for missing block 1 = 0-16")
		}

		if !matchPositionForBlock3 {
			t.Errorf("Expected delta range for missing block 3 = 48-64")
		}
	})

	t.Run("chunk shifted", func(t *testing.T) {
		o := []byte("i am here guys how are you doing this is a small test for chunk split and rolling hash")
		c := []byte("i am here guys   how are you doing    test for chunk split and rolling hash")
		expect := map[int][]byte{
			1: []byte("i am here guys   h"), // Match first block change
			3: []byte("   "),                // Match third block change
		}

		delta := CalculateDelta(o, c, t)
		CheckMatch(delta, expect, t)
	})
}

func TestSeekMatchBlock(t *testing.T) {
	a := []byte("hello world this is a test for my seek block")
	bytesA := bytes.NewReader(a)
	bufioA := bufio.NewReader(bytesA)

	s := signature(t, bufioA, 1<<3)
	weakSum := uint32(174195318)

	index, err := Seek(s, weakSum, []byte("rld this"))
	require.NoError(t, err)

	if index != 2 {
		t.Errorf("Expected index 1 for weakSum=174195318")
	}
}
