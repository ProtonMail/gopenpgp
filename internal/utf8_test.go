package internal

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

var invalidUtf8 = []string{"f0288cbc", "fc80808080af"}

var validUtf8 = []string{"Hell⌘o☏", "World", "||||", "你好，世界！"}

type noOpCloser struct {
	buff *bytes.Buffer
}

func (c *noOpCloser) Write(p []byte) (n int, err error) {
	return c.buff.Write(p)
}

func (c *noOpCloser) Close() (err error) {
	return
}

func loadLargeData(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/utf8Valid.txt")
	if err != nil {
		t.Fatal(err)
	}
	validUtf8 = append(validUtf8, string(data))
}

func TestUtf8CheckWriteCloser(t *testing.T) {
	loadLargeData(t)
	t.Run("invalid utf-8", func(t *testing.T) {
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
	})

	t.Run("valid utf-8", func(t *testing.T) {
		for _, copySize := range []int64{1, 3, 7, 11} {
			for _, valid := range validUtf8 {
				buff := bytes.NewBuffer(nil)
				writeCloser := NewUtf8CheckWriteCloser(&noOpCloser{buff})
				dataReader := strings.NewReader(valid)
				for {
					_, err := io.CopyN(writeCloser, dataReader, copySize)
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := writeCloser.Close(); err != nil {
					t.Error("Should be valid utf8")
				}
			}
		}
	})
}
