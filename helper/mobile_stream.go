package helper

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type MobileReadResult struct {
	N     int
	IsEOF bool
	Data  []byte
}

func NewMobileReadResult(n int, eof bool, data []byte) *MobileReadResult {
	return &MobileReadResult{n, eof, clone(data)}
}

func clone(src []byte) (dst []byte) {
	dst = make([]byte, len(src))
	copy(dst, src)
	return
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
	reader  MobileReader
	debug   []byte
	counter int
}

func NewMobile2GoReader(reader MobileReader) *Mobile2GoReader {
	return &Mobile2GoReader{reader, nil, 0}
}

func (d *Mobile2GoReader) Read(b []byte) (int, error) {
	result, err := d.reader.Read(len(b))
	if err != nil {
		fmt.Printf("error while reading %v\n", err)
		return 0, err
	}
	n := result.N
	d.counter++
	if n > 0 {
		copy(b, result.Data[:n])
		fmt.Printf("Read %d\n", n)
		d.debug = append(d.debug, b[:n]...)
		fmt.Printf("%d hash %x bytes %x\n", d.counter, sha256.Sum256(d.debug), b[:n])
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
			result.IsEOF = true
		} else {
			return nil, err
		}
	}
	result.N = n
	if n > 0 {
		result.Data = b[:n]
	}
	return result, nil
}
