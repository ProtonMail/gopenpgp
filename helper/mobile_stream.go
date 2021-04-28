// +build mobile

package helper

import (
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"io"
)

type MobileReadResult struct {
	N     int
	IsEOF bool
	Data  []byte
}

func NewMobileReadResult(n int, eof bool, data []byte) *MobileReadResult {
	return &MobileReadResult{n, eof, data}
}

type MobileReader interface {
	Read(int) (*MobileReadResult, error)
}

type Mobile2GoWriter struct {
	writer crypto.Writer
}

func NewMobile2GoWriter(writer crypto.Writer) *Mobile2GoWriter {
	return &Mobile2GoWriter{writer}
}

func (d *Mobile2GoWriter) Write(b []byte) (int, error) {
	bufferCopy := make([]byte, len(b))
	copy(bufferCopy, b)
	return d.writer.Write(bufferCopy)
}

type Mobile2GoReader struct {
	reader MobileReader
}

func NewMobile2GoReader(reader MobileReader) *Mobile2GoReader {
	return &Mobile2GoReader{reader}
}

func (d *Mobile2GoReader) Read(b []byte) (int, error) {
	result, err := d.reader.Read(len(b))
	if err != nil {
		fmt.Printf("error while reading %v\n", err)
		return 0, err
	}
	n := result.N
	fmt.Printf("Read %d\n", n)
	if n > 0 {
		copy(b, result.Data[:n])
		fmt.Printf("Bytes %x\n", b[:n])
	}
	if result.IsEOF {
		fmt.Println("EOF")
		err = io.EOF
	}
	return n, err
}

type Go2MobileReader struct {
	reader crypto.Reader
}

func NewGo2MobileReader(reader crypto.Reader) *Go2MobileReader {
	return &Go2MobileReader{reader}
}

func (d *Go2MobileReader) Read(max int) (*MobileReadResult, error) {
	b := make([]byte, max)
	n, err := d.reader.Read(b)
	result := &MobileReadResult{}
	if err != nil {
		if errors.Is(err, io.EOF) {
			fmt.Println("EOF")
			result.IsEOF = true
		} else {
			return nil, err
		}
	}
	result.N = n
	fmt.Printf("Read %d\n", n)
	if n > 0 {
		result.Data = b[:n]
		fmt.Printf("Bytes %x\n", b[:n])
	}
	return result, nil
}
