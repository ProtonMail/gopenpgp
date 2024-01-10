package internal

import (
	"errors"
	"io"
	"unicode/utf8"
)

var ErrIncorrectUtf8 = errors.New("openpgp: data encoding is not valid utf-8")

const (
	maxRuneSize = 4

	locb = 0b10000000
	hicb = 0b10111111

	xx = 0xF1
	as = 0xF0
	s1 = 0x02
	s2 = 0x13
	s3 = 0x03
	s4 = 0x23
	s5 = 0x34
	s6 = 0x04
	s7 = 0x44
)

var first = [256]uint8{
	//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x00-0x0F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x10-0x1F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x20-0x2F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x30-0x3F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x40-0x4F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x50-0x5F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x60-0x6F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x70-0x7F
	//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x80-0x8F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x90-0x9F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xA0-0xAF
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xB0-0xBF
	xx, xx, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, // 0xC0-0xCF
	s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, // 0xD0-0xDF
	s2, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s4, s3, s3, // 0xE0-0xEF
	s5, s6, s6, s6, s7, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xF0-0xFF
}

type acceptRange struct {
	lo uint8
	hi uint8
}

var acceptRanges = [16]acceptRange{
	0: {locb, hicb},
	1: {0xA0, hicb},
	2: {locb, 0x9F},
	3: {0x90, hicb},
	4: {locb, 0x8F},
}

func canOverlap(in []byte) []byte {
	if len(in) < maxRuneSize {
		return in
	}
	return nil
}

// valid is a slightly modified utf8.Valid() function copied from the standard library.
// If the byte slice is not valid utf8, it additionally returns the remaining data if the
// remaining data is smaller than the largest potential rune.
func valid(p []byte) (bool, []byte) {
	p = p[:len(p):len(p)]
	for len(p) >= 8 {
		first32 := uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24
		second32 := uint32(p[4]) | uint32(p[5])<<8 | uint32(p[6])<<16 | uint32(p[7])<<24
		if (first32|second32)&0x80808080 != 0 {
			break
		}
		p = p[8:]
	}
	n := len(p)
	for i := 0; i < n; {
		pi := p[i]
		if pi < utf8.RuneSelf {
			i++
			continue
		}
		x := first[pi]
		if x == xx {
			return false, canOverlap(p[i:])
		}
		size := int(x & 7)
		if i+size > n {
			return false, canOverlap(p[i:])
		}
		accept := acceptRanges[x>>4]
		if c := p[i+1]; c < accept.lo || accept.hi < c {
			return false, canOverlap(p[i:])
		} else if size == 2 {
		} else if c := p[i+2]; c < locb || hicb < c {
			return false, canOverlap(p[i:])
		} else if size == 3 {
		} else if c := p[i+3]; c < locb || hicb < c {
			return false, canOverlap(p[i:])
		}
		i += size
	}
	return true, nil
}

type utf8Checker struct {
	buffer       [maxRuneSize]byte
	overflowSize int
}

func (c *utf8Checker) check(p []byte) error {
	pInspect := p
	if c.overflowSize > 0 {
		// There is data in the overflow buffer from the last check call
		copied := copy(c.buffer[c.overflowSize:], p)
		c.overflowSize += copied
		r, runeSize := utf8.DecodeRune(c.buffer[:c.overflowSize])
		if r == utf8.RuneError && runeSize == 1 {
			if c.overflowSize < maxRuneSize {
				// Could still be valid utf-8 on next check
				return nil
			}
			return ErrIncorrectUtf8
		}
		pInspect = pInspect[copied-(c.overflowSize-runeSize):]
		c.overflowSize = 0
	}
	if len(pInspect) < 1 {
		return nil
	}
	isValid, rest := valid(pInspect)
	if !isValid && len(rest) > 0 {
		// Could still be valid utf-8 on next check
		copy(c.buffer[:], rest)
		c.overflowSize = len(rest)
	} else if !isValid {
		return ErrIncorrectUtf8
	}
	return nil
}

func (c *utf8Checker) close() error {
	if c.overflowSize > 0 {
		return ErrIncorrectUtf8
	}
	return nil
}

type Utf8CheckWriteCloser struct {
	utf8Checker
	internal io.WriteCloser
}

func NewUtf8CheckWriteCloser(wrap io.WriteCloser) *Utf8CheckWriteCloser {
	return &Utf8CheckWriteCloser{
		internal: wrap,
	}
}

func (cw *Utf8CheckWriteCloser) Write(p []byte) (n int, err error) {
	err = cw.check(p)
	if err != nil {
		return
	}
	n, err = cw.internal.Write(p)
	return
}

func (cw *Utf8CheckWriteCloser) Close() (err error) {
	err = cw.close()
	if err != nil {
		return
	}
	err = cw.internal.Close()
	return
}
