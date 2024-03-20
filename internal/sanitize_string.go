package internal

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

func SanitizeString(input string) string {
	return strings.ToValidUTF8(input, string(unicode.ReplacementChar))
}

func NewSanitizeReader(r io.Reader) io.Reader {
	sanitizer := &sanitizeReader{r, new(bytes.Buffer), false}
	return newSanitizeUtf8Reader(sanitizer)
}

type sanitizeUtf8Reader struct {
	r               *bufio.Reader
	reminder        []byte
	internalBuffer  [4]byte
	lastRuneInvalid bool
}

func newSanitizeUtf8Reader(reader io.Reader) *sanitizeUtf8Reader {
	return &sanitizeUtf8Reader{
		r: bufio.NewReader(reader),
	}
}

func (sr *sanitizeUtf8Reader) Read(buf []byte) (int, error) {
	read := 0
	// Check if there is a reminder from the previous read
	if sr.reminder != nil {
		toCopy := len(sr.reminder)
		if toCopy > len(buf) {
			toCopy = len(buf)
		}
		copy(buf[read:], sr.reminder[:toCopy])
		read += toCopy
		if toCopy < len(sr.reminder) {
			sr.reminder = sr.reminder[toCopy:]
		} else {
			sr.reminder = nil
		}
	}
	// Decode utf-8 runes from the internal reader and copy
	for read < len(buf) {
		runeItem, size, err := sr.r.ReadRune()
		if err != nil {
			return read, err
		}
		if runeItem == unicode.ReplacementChar {
			// If last rune written is a replacement skip
			if sr.lastRuneInvalid {
				continue
			}
			size = 3
			sr.lastRuneInvalid = true
		} else {
			sr.lastRuneInvalid = false
		}
		if read+size <= len(buf) {
			utf8.EncodeRune(buf[read:], runeItem)
			read += size
		} else {
			// Not enough space to write the entire rune
			size = utf8.EncodeRune(sr.internalBuffer[:], runeItem)
			copied := copy(buf[read:], sr.internalBuffer[:len(buf)-read])
			sr.reminder = sr.internalBuffer[copied:size]
			read += copied
			break
		}
	}
	return read, nil
}

type sanitizeReader struct {
	r      io.Reader
	buffer *bytes.Buffer
	pin    bool
}

func (sr *sanitizeReader) resetState() {
	sr.pin = false
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
		// error occurred that is not EOF
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
			continue
		}
		sr.resetState()
		sr.buffer.Write(buf[i : i+1])
		i++
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
