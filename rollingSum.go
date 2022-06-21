//https://rsync.samba.org/tech_report/node3.html

package rollingHash

const M = 65521

type RollSum struct {
	window []byte // A fixed size array of temporary evaluated bytes
	old    uint8  // Last element rolled out
	count  uint64 // Last position
	s1, s2 uint16 // adler32 formula
}

func NewRollSum() RollSum {
	return RollSum{
		window: make([]byte, 0),
		count:  0,
		s1:     0,
		s2:     0,
	}
}

func (r *RollSum) Rollin(in byte) {
	r.s1 = (r.s1 + uint16(in)) % M
	r.s2 = (r.s2 + r.s1) % M
	r.count += 1
	r.window = append(r.window, in)
}

func (r *RollSum) Digest() uint32 {
	return (uint32(r.s2) << 16) | (uint32(r.s1) & 0xffff)
}

func (r *RollSum) Rollout() {
	if len(r.window) == 0 {
		r.count = 0
		return
	}

	r.old = r.window[0]
	r.s1 = (r.s1 - uint16(r.old)) % M
	r.s2 = (r.s2 - (uint16(len(r.window)) * uint16(r.old))) % M
	r.count -= 1
	r.window = r.window[1:]
}

func WeakChecksum(data []byte) uint32 {
	var sum RollSum
	sum.Update(data)
	return sum.Digest()
}

func (r *RollSum) Update(p []byte) {
	for index, char := range p {
		r.s1 += uint16(char)
		r.s2 += uint16(len(p)-index) * uint16(char)
		r.count++
	}

	r.s1 %= M
	r.s2 %= M
}

func (r *RollSum) Reset() {
	r.window = make([]byte, 0)
	r.count = 0
	r.s1 = 0
	r.s2 = 0
	r.old = 0
}
