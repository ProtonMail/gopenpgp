package crypto

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func expectedOutput(in string) string {
	return sanitizeString(strings.ReplaceAll(in, "\r\n", "\n"))
}

func testStringSanitizeReader(t *testing.T, test string) {
	reader := NewSanitizeReader(bytes.NewReader([]byte(test)))
	byteBuffer := new(bytes.Buffer)
	smallBuff := make([]byte, 3)
	var err error
	for err != io.EOF {
		var n int
		n, err = reader.Read(smallBuff)
		byteBuffer.Write(smallBuff[:n])
	}
	assert.Equal(t, byteBuffer.String(), expectedOutput(test))
}

func TestStringSanitizeReader(t *testing.T) {
	test := "a\xc5zsd\xc5\r\ndf\rdf\xc5df\rsdf\r\n\r\n\r\n\r\n\r\n\r\n\r\n"
	testStringSanitizeReader(t, test)
	testStringSanitizeReader(t, "\r\n\r\n\r\n\r\n\r\n\r\n\r\n")
	testStringSanitizeReader(t, "\n")
	testStringSanitizeReader(t, "\r")
	testStringSanitizeReader(t, "")
	testStringSanitizeReader(t, "\xc5\xc5\xc5\xc5\xc5\xc5\xc5\xc5\xc5")
}
