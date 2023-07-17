package internal

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var invalidUtf8 = []string{"f0288cbc", "fc80808080af"}

var validUtf8 = []string{"Hell⌘o☏", "World", "||||"}

type noOpCloser struct {
	buff *bytes.Buffer
}

func (c *noOpCloser) Write(p []byte) (n int, err error) {
	return c.buff.Write(p)
}

func (cw *noOpCloser) Close() (err error) {
	return
}

func TestUtf8CheckWriteCloser(t *testing.T) {
	for _, invalid := range invalidUtf8 {
		buff := bytes.NewBuffer(nil)
		writeCloser := NewUtf8CheckWriteCloser(&noOpCloser{buff})
		data, _ := hex.DecodeString(invalid)
		var err error
		for id := range data {
			if _, err = writeCloser.Write(data[id : id+1]); err != nil {
				break
			}
		}
		errClose := writeCloser.Close()
		if err == nil && errClose == nil {
			t.Error("Should be invalid utf8")
		}
	}

	for _, valid := range validUtf8 {
		buff := bytes.NewBuffer(nil)
		writeCloser := NewUtf8CheckWriteCloser(&noOpCloser{buff})
		var err error
		data := []byte(valid)
		for id := range data {
			if _, err = writeCloser.Write(data[id : id+1]); err != nil {
				t.Error("Should be valid utf8")
			}
		}
		if err := writeCloser.Close(); err != nil {
			t.Error("Should be valid utf8")
		}
	}
}
