// Package internal contains internal methods and constants.
package internal

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/constants"
)

var nl []byte = []byte("\n")
var rnl []byte = []byte("\r\n")

func Canonicalize(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
}

func CanonicalizeBytes(text []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(text, rnl, nl), nl, rnl)
}

func TrimEachLine(text string) string {
	lines := strings.Split(text, "\n")

	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\r")
	}

	return strings.Join(lines, "\n")
}

func TrimEachLineBytes(text []byte) []byte {
	lines := bytes.Split(text, nl)

	for i := range lines {
		lines[i] = bytes.TrimRight(lines[i], " \t\r")
	}

	return bytes.Join(lines, nl)
}

// ArmorHeaders is a map of default armor headers.
var ArmorHeaders = map[string]string{}

func init() {
	if constants.ArmorHeaderEnabled {
		ArmorHeaders = map[string]string{
			"Version": constants.ArmorHeaderVersion,
			"Comment": constants.ArmorHeaderComment,
		}
	}
}

// ResetReader is a reader that can be reset by buffering data internally.
type ResetReader struct {
	Reader     io.Reader
	buffer     *bytes.Buffer
	bufferData bool
}

// NewResetReader creates a new ResetReader with the default state.
func NewResetReader(reader io.Reader) *ResetReader {
	return &ResetReader{
		Reader:     reader,
		buffer:     bytes.NewBuffer(nil),
		bufferData: true,
	}
}

func (rr *ResetReader) Read(b []byte) (n int, err error) {
	n, err = rr.Reader.Read(b)
	if rr.bufferData {
		rr.buffer.Write(b[:n])
	}
	return
}

// DisableBuffering disables the internal buffering.
// After the disable, a Reset is not allowed anymore.
func (rr *ResetReader) DisableBuffering() {
	rr.bufferData = false
}

// Reset creates a reader that reads again from the beginning and
// resets the internal state.
func (rr *ResetReader) Reset() (io.Reader, error) {
	if !rr.bufferData {
		return nil, errors.New("reset not possible if buffering is disabled")
	}
	rr.Reader = io.MultiReader(rr.buffer, rr.Reader)
	rr.buffer = bytes.NewBuffer(nil)
	return rr.Reader, nil
}
