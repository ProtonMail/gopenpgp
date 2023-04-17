package crypto

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"
)

var escape = []byte{0xEF, 0xBF, 0xBD}

func sanitizeString(input string) string {
	return strings.ToValidUTF8(input, "\ufffd")
}

func NewSanitizeReader(r io.Reader) io.Reader {
	return &sanitizeReader{r, new(bytes.Buffer), false, false}
}

type sanitizeReader struct {
	r            io.Reader
	buffer       *bytes.Buffer
	pin, invalid bool
}

func (sr *sanitizeReader) resetState() {
	sr.pin = false
	sr.invalid = false
}

func (sr *sanitizeReader) Read(buf []byte) (int, error) {
	// read from internal buffer first
	internalRead, _ := sr.buffer.Read(buf)
	if internalRead == len(buf) {
		return internalRead, nil
	}
	// if there is more space in buf, read from the reader
	n, err := sr.r.Read(buf[internalRead:])
	if err != nil && err != io.EOF {
		// error occured that is not EOF
		return n, err
	}
	// filter non-unicode and \r\n in what has been read from the reader,
	for i := internalRead; i < internalRead+n; {
		c := buf[i]
		if sr.pin {
			// last char read is \r
			if c == '\n' {
				sr.buffer.WriteByte('\n')
				i++
			} else {
				sr.buffer.WriteByte('\r')
			}
			sr.resetState()
			continue
		}
		if c == '\r' {
			// check for \n on next char
			i++
			sr.pin = true
			sr.invalid = false
			continue
		}

		if c < utf8.RuneSelf {
			// valid utf-8 char
			i++
			sr.resetState()
			sr.buffer.WriteByte(c)
			continue
		}

		_, wid := utf8.DecodeRune(buf[i:])
		if wid == 1 {
			// invalid utf-8 char
			i++
			if !sr.invalid {
				sr.invalid = true
				sr.pin = false
				sr.buffer.Write(escape)
			}
			continue
		}
		// valid utf-8 rune
		sr.resetState()
		sr.buffer.Write(buf[i : i+wid])
		i += wid
	}
	if err == io.EOF && sr.pin {
		sr.resetState()
		sr.buffer.WriteByte('\r')
	}
	finalRead, _ := sr.buffer.Read(buf[internalRead:])
	if err == io.EOF && sr.buffer.Len() == 0 {
		return internalRead + finalRead, err
	}
	return internalRead + finalRead, nil
}
