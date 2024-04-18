package internal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testTrimWriteCloser(t *testing.T, test string) {
	testBytes := []byte(test)
	for _, batchSize := range []int{1, 2, 3, 7, 11} {
		var buff bytes.Buffer
		w := &noOpWriteCloser{
			writer: &buff,
		}
		trimWriter := NewTrimWriteCloser(w)
		for ind := 0; ind < len(testBytes); ind += batchSize {
			end := ind + batchSize
			if end > len(testBytes) {
				end = len(testBytes)
			}
			if _, err := trimWriter.Write(testBytes[ind:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := trimWriter.Close(); err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, TrimEachLine(test), buff.String())
	}
}

func TestTrimWriteCloser(t *testing.T) {
	testTrimWriteCloser(t, "\n    \t     \r")
	testTrimWriteCloser(t, "this is a test \n   \t \n\n")
	testTrimWriteCloser(t, "sdf\n   \t sddf\n \r\rsd   \t fsdf\n")
	testTrimWriteCloser(t, "BEGIN:VCARD\r\nVERSION:4.0\r\nFN;PREF=1:   \r\nEND:VCARD")
	testTrimWriteCloser(t, strings.Repeat("\r \nthis is a test \n   \t \n\n)", 10000))
}
