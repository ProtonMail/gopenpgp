package internal

import (
	"errors"
	"io"
	"unicode/utf8"
)

var ErrIncorrectUtf8 = errors.New("openpgp: data encoding is not valid utf-8")

const maxSize = 4

type utf8Checker struct {
	overflow [maxSize]byte
	to       int
}

func (c *utf8Checker) check(p []byte) error {
	var pos int
	if c.to > 0 {
		copied := copy(c.overflow[c.to:], p)
		c.to += copied
		r, runeSize := utf8.DecodeRune(c.overflow[:c.to])
		if r == utf8.RuneError {
			if c.to >= maxSize {
				return ErrIncorrectUtf8
			} else {
				// Could still be valid utf-8 on next check
				return nil
			}
		}
		pos = copied - (c.to - runeSize)
		c.to = 0
	}
	for pos < len(p) {
		if p[pos] < utf8.RuneSelf {
			pos++
			continue
		}
		r, sizeRune := utf8.DecodeRune(p[pos:])
		if r == utf8.RuneError && sizeRune == 1 {
			remaining := len(p) - pos
			if remaining < maxSize {
				// Could still be valid utf-8 on next check
				copy(c.overflow[:], p[pos:])
				c.to = remaining
				break
			} else {
				return ErrIncorrectUtf8
			}
		}
		pos += sizeRune
	}
	return nil
}

func (c *utf8Checker) close() error {
	if c.to > 0 {
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
