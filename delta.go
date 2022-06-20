//implementation based on the rsync algorithm (https://rsync.samba.org/tech_report/node2.html)
// Circular buffer interface based on https://github.com/balena-os/circbuf
// code implementation based on https://github.com/balena-os/librsync-go

package rollingHash

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/balena-os/circbuf"
	"io"
)

const (
	DeltaMagic MagicNumber = 0x72730236

	// Md4SigMagic A signature file with MD4 signatures.
	Md4SigMagic MagicNumber = 0x72730136

	// Blake2SigMagic A signature file using the BLAKE2 hash.
	Blake2SigMagic MagicNumber = 0x72730137
)

type matchKind uint8

const (
	MatchKindLiteral matchKind = iota
	MatchKindCopy
)

type Op uint8

const (
	OpEnd Op = iota
	OP_LITERAL_1
	OP_LITERAL_2
	OP_LITERAL_3
	OP_LITERAL_4
	OP_LITERAL_5
	OP_LITERAL_6
	OP_LITERAL_7
	OP_LITERAL_8
	OP_LITERAL_9
	OP_LITERAL_10
	OP_LITERAL_11
	OP_LITERAL_12
	OP_LITERAL_13
	OP_LITERAL_14
	OP_LITERAL_15
	OP_LITERAL_16
	OP_LITERAL_17
	OP_LITERAL_18
	OP_LITERAL_19
	OP_LITERAL_20
	OP_LITERAL_21
	OP_LITERAL_22
	OP_LITERAL_23
	OP_LITERAL_24
	OP_LITERAL_25
	OP_LITERAL_26
	OP_LITERAL_27
	OP_LITERAL_28
	OP_LITERAL_29
	OP_LITERAL_30
	OP_LITERAL_31
	OP_LITERAL_32
	OP_LITERAL_33
	OP_LITERAL_34
	OP_LITERAL_35
	OP_LITERAL_36
	OP_LITERAL_37
	OP_LITERAL_38
	OP_LITERAL_39
	OP_LITERAL_40
	OP_LITERAL_41
	OP_LITERAL_42
	OP_LITERAL_43
	OP_LITERAL_44
	OP_LITERAL_45
	OP_LITERAL_46
	OP_LITERAL_47
	OP_LITERAL_48
	OP_LITERAL_49
	OP_LITERAL_50
	OP_LITERAL_51
	OP_LITERAL_52
	OP_LITERAL_53
	OP_LITERAL_54
	OP_LITERAL_55
	OP_LITERAL_56
	OP_LITERAL_57
	OP_LITERAL_58
	OP_LITERAL_59
	OP_LITERAL_60
	OP_LITERAL_61
	OP_LITERAL_62
	OP_LITERAL_63
	OP_LITERAL_64
	OP_LITERAL_N1
	OP_LITERAL_N2
	OP_LITERAL_N4
	OP_LITERAL_N8
	OP_COPY_N1_N1
	OP_COPY_N1_N2
	OP_COPY_N1_N4
	OP_COPY_N1_N8
	OP_COPY_N2_N1
	OP_COPY_N2_N2
	OP_COPY_N2_N4
	OP_COPY_N2_N8
	OP_COPY_N4_N1
	OP_COPY_N4_N2
	OP_COPY_N4_N4
	OP_COPY_N4_N8
	OP_COPY_N8_N1
	OP_COPY_N8_N2
	OP_COPY_N8_N4
	OP_COPY_N8_N8
	OP_RESERVED_85
	OP_RESERVED_86
	OP_RESERVED_87
	OP_RESERVED_88
	OP_RESERVED_89
	OP_RESERVED_90
	OP_RESERVED_91
	OP_RESERVED_92
	OP_RESERVED_93
	OP_RESERVED_94
	OP_RESERVED_95
	OP_RESERVED_96
	OP_RESERVED_97
	OP_RESERVED_98
	OP_RESERVED_99
	OP_RESERVED_100
	OP_RESERVED_101
	OP_RESERVED_102
	OP_RESERVED_103
	OP_RESERVED_104
	OP_RESERVED_105
	OP_RESERVED_106
	OP_RESERVED_107
	OP_RESERVED_108
	OP_RESERVED_109
	OP_RESERVED_110
	OP_RESERVED_111
	OP_RESERVED_112
	OP_RESERVED_113
	OP_RESERVED_114
	OP_RESERVED_115
	OP_RESERVED_116
	OP_RESERVED_117
	OP_RESERVED_118
	OP_RESERVED_119
	OP_RESERVED_120
	OP_RESERVED_121
	OP_RESERVED_122
	OP_RESERVED_123
	OP_RESERVED_124
	OP_RESERVED_125
	OP_RESERVED_126
	OP_RESERVED_127
	OP_RESERVED_128
	OP_RESERVED_129
	OP_RESERVED_130
	OP_RESERVED_131
	OP_RESERVED_132
	OP_RESERVED_133
	OP_RESERVED_134
	OP_RESERVED_135
	OP_RESERVED_136
	OP_RESERVED_137
	OP_RESERVED_138
	OP_RESERVED_139
	OP_RESERVED_140
	OP_RESERVED_141
	OP_RESERVED_142
	OP_RESERVED_143
	OP_RESERVED_144
	OP_RESERVED_145
	OP_RESERVED_146
	OP_RESERVED_147
	OP_RESERVED_148
	OP_RESERVED_149
	OP_RESERVED_150
	OP_RESERVED_151
	OP_RESERVED_152
	OP_RESERVED_153
	OP_RESERVED_154
	OP_RESERVED_155
	OP_RESERVED_156
	OP_RESERVED_157
	OP_RESERVED_158
	OP_RESERVED_159
	OP_RESERVED_160
	OP_RESERVED_161
	OP_RESERVED_162
	OP_RESERVED_163
	OP_RESERVED_164
	OP_RESERVED_165
	OP_RESERVED_166
	OP_RESERVED_167
	OP_RESERVED_168
	OP_RESERVED_169
	OP_RESERVED_170
	OP_RESERVED_171
	OP_RESERVED_172
	OP_RESERVED_173
	OP_RESERVED_174
	OP_RESERVED_175
	OP_RESERVED_176
	OP_RESERVED_177
	OP_RESERVED_178
	OP_RESERVED_179
	OP_RESERVED_180
	OP_RESERVED_181
	OP_RESERVED_182
	OP_RESERVED_183
	OP_RESERVED_184
	OP_RESERVED_185
	OP_RESERVED_186
	OP_RESERVED_187
	OP_RESERVED_188
	OP_RESERVED_189
	OP_RESERVED_190
	OP_RESERVED_191
	OP_RESERVED_192
	OP_RESERVED_193
	OP_RESERVED_194
	OP_RESERVED_195
	OP_RESERVED_196
	OP_RESERVED_197
	OP_RESERVED_198
	OP_RESERVED_199
	OP_RESERVED_200
	OP_RESERVED_201
	OP_RESERVED_202
	OP_RESERVED_203
	OP_RESERVED_204
	OP_RESERVED_205
	OP_RESERVED_206
	OP_RESERVED_207
	OP_RESERVED_208
	OP_RESERVED_209
	OP_RESERVED_210
	OP_RESERVED_211
	OP_RESERVED_212
	OP_RESERVED_213
	OP_RESERVED_214
	OP_RESERVED_215
	OP_RESERVED_216
	OP_RESERVED_217
	OP_RESERVED_218
	OP_RESERVED_219
	OP_RESERVED_220
	OP_RESERVED_221
	OP_RESERVED_222
	OP_RESERVED_223
	OP_RESERVED_224
	OP_RESERVED_225
	OP_RESERVED_226
	OP_RESERVED_227
	OP_RESERVED_228
	OP_RESERVED_229
	OP_RESERVED_230
	OP_RESERVED_231
	OP_RESERVED_232
	OP_RESERVED_233
	OP_RESERVED_234
	OP_RESERVED_235
	OP_RESERVED_236
	OP_RESERVED_237
	OP_RESERVED_238
	OP_RESERVED_239
	OP_RESERVED_240
	OP_RESERVED_241
	OP_RESERVED_242
	OP_RESERVED_243
	OP_RESERVED_244
	OP_RESERVED_245
	OP_RESERVED_246
	OP_RESERVED_247
	OP_RESERVED_248
	OP_RESERVED_249
	OP_RESERVED_250
	OP_RESERVED_251
	OP_RESERVED_252
	OP_RESERVED_253
	OP_RESERVED_254
	OP_RESERVED_255
)

type match struct {
	kind   matchKind
	pos    uint64
	len    uint64
	output io.Writer
	lit    []byte
}

func (m *match) add(kind matchKind, pos, len uint64) error {
	if len != 0 && m.kind != kind {
		err := m.flush()
		if err != nil {
			return err
		}
	}

	m.kind = kind

	switch kind {
	case MatchKindLiteral:
		m.lit = append(m.lit, byte(pos))
		m.len += 1
	case MatchKindCopy:
		m.lit = []byte{}
		if m.pos+m.len != pos {
			err := m.flush()
			if err != nil {
				return err
			}
			m.pos = pos
			m.len = len
		} else {
			m.len += len
		}
	}
	return nil
}

func (m *match) write(d uint64, size uint8) error {
	switch size {
	case 1:
		return binary.Write(m.output, binary.BigEndian, uint8(d))
	case 2:
		return binary.Write(m.output, binary.BigEndian, uint16(d))
	case 4:
		return binary.Write(m.output, binary.BigEndian, uint32(d))
	case 8:
		return binary.Write(m.output, binary.BigEndian, uint64(d))
	}
	var b []byte
	m.output.Write(b)
	return fmt.Errorf("invalid size: %v", size)
}

func intSize(d uint64) uint8 {
	switch {
	case d == uint64(uint8(d)):
		return 1
	case d == uint64(uint16(d)):
		return 2
	case d == uint64(uint32(d)):
		return 4
	default:
		return 8
	}
}

func (m *match) flush() error {
	if m.len == 0 {
		return nil
	}
	posSize := intSize(m.pos)
	lenSize := intSize(m.len)

	var cmd Op

	switch m.kind {
	case MatchKindCopy:
		switch posSize {
		case 1:
			cmd = OP_COPY_N1_N1
		case 2:
			cmd = OP_COPY_N2_N1
		case 4:
			cmd = OP_COPY_N4_N1
		case 8:
			cmd = OP_COPY_N8_N1
		}

		switch lenSize {
		case 2:
			cmd += 1
		case 4:
			cmd += 2
		case 8:
			cmd += 3
		}

		err := binary.Write(m.output, binary.BigEndian, cmd)
		if err != nil {
			return err
		}
		err = m.write(m.pos, posSize)
		if err != nil {
			return err
		}
		err = m.write(m.len, lenSize)
		if err != nil {
			return err
		}
	case MatchKindLiteral:
		cmd = OP_LITERAL_N1
		switch lenSize {
		case 1:
			cmd = OP_LITERAL_N1
		case 2:
			cmd = OP_LITERAL_N2
		case 4:
			cmd = OP_LITERAL_N4
		case 8:
			cmd = OP_LITERAL_N8
		}

		err := binary.Write(m.output, binary.BigEndian, cmd)
		if err != nil {
			return err
		}
		err = m.write(m.len, lenSize)
		if err != nil {
			return err
		}
		m.output.Write(m.lit)
		m.lit = []byte{}
	}
	m.pos = 0
	m.len = 0
	return nil
}

func Delta(sig *SignatureType, i io.Reader, output io.Writer) error {
	input := bufio.NewReader(i)

	err := binary.Write(output, binary.BigEndian, DeltaMagic)
	if err != nil {
		return err
	}

	prevByte := byte(0)
	m := match{output: output}

	weakSum := NewRollSum()
	block, _ := circbuf.NewBuffer(int64(sig.blockLen))

	for {
		in, err := input.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if block.TotalWritten() > 0 {
			prevByte, err = block.Get(0)
			if err != nil {
				return err
			}
		}
		block.WriteByte(in)
		weakSum.Rollin(in)

		if weakSum.count < uint64(sig.blockLen) {
			continue
		}

		if weakSum.count > uint64(sig.blockLen) {
			err := m.add(MatchKindLiteral, uint64(prevByte), 1)
			if err != nil {
				return err
			}
			weakSum.Rollout(prevByte)
		}

		if blockIdx, ok := sig.weak2block[weakSum.Digest()]; ok {
			strong2, _ := CalcStrongSum(block.Bytes(), sig.sigType, sig.strongLen)
			if bytes.Equal(sig.strongSigs[blockIdx], strong2) {
				weakSum.Reset()
				block.Reset()
				err := m.add(MatchKindCopy, uint64(blockIdx)*uint64(sig.blockLen), uint64(sig.blockLen))
				if err != nil {
					return err
				}
			}
		}
	}

	for _, b := range block.Bytes() {
		err := m.add(MatchKindLiteral, uint64(b), 1)
		if err != nil {
			return err
		}
	}

	if err := m.flush(); err != nil {
		return err
	}

	return binary.Write(output, binary.BigEndian, OpEnd)
}
