//https://rsync.samba.org/tech_report/node3.html

package rollingHash

const RollsumCharOffset = 31

type RollSum struct {
	count  uint64
	s1, s2 uint16
}

func NewRollSum() RollSum {
	return RollSum{}
}

func (r *RollSum) Rollin(in byte) {
	r.s1 += uint16(in) + uint16(RollsumCharOffset)
	r.s2 += r.s1
	r.count += 1
}

func (r *RollSum) Digest() uint32 {
	return (uint32(r.s2) << 16) | (uint32(r.s1) & 0xffff)
}

func (r *RollSum) Rollout(out byte) {
	r.s1 -= uint16(out) + uint16(RollsumCharOffset)
	r.s2 -= uint16(r.count) * (uint16(out) + uint16(RollsumCharOffset))
	r.count -= 1
}

func (r *RollSum) Reset() {
	r.count = 0
	r.s1 = 0
	r.s2 = 0
}

func WeakChecksum(data []byte) uint32 {
	var sum RollSum
	sum.Update(data)
	return sum.Digest()
}

func (r *RollSum) Update(p []byte) {
	l := len(p)

	for n := 0; n < l; {
		if n+15 < l {
			for i := 0; i < 16; i++ {
				r.s1 += uint16(p[n+i])
				r.s2 += r.s1
			}
			n += 16
		} else {
			r.s1 += uint16(p[n])
			r.s2 += r.s1
			n += 1
		}
	}

	r.s1 += uint16(l * RollsumCharOffset)
	r.s2 += uint16(((l * (l + 1)) / 2) * RollsumCharOffset)
	r.count += uint64(l)
}
