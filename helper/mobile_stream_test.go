package helper

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

func cloneTestData() (a, b []byte) {
	a = []byte("Hello World!")
	b = clone(a)
	return a, b
}
func Test_clone(t *testing.T) {
	if a, b := cloneTestData(); !bytes.Equal(a, b) {
		t.Fatalf("expected %x, got %x", a, b)
	}
}

func TestMobile2GoWriter(t *testing.T) {
	testData := []byte("Hello World!")
	outBuf := &bytes.Buffer{}
	reader := bytes.NewReader(testData)
	writer := NewMobile2GoWriter(outBuf)
	bufSize := 2
	writeBuf := make([]byte, bufSize)
	reachedEnd := false
	for !reachedEnd {
		n, err := reader.Read(writeBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				reachedEnd = true
			} else {
				t.Fatal("Expected no error while reading, got:", err)
			}
		}
		writtenTotal := 0
		for writtenTotal < n {
			written, err := writer.Write(writeBuf[writtenTotal:n])
			if err != nil {
				t.Fatal("Expected no error while writing, got:", err)
			}
			writtenTotal += written
		}
	}
	if writtenData := outBuf.Bytes(); !bytes.Equal(testData, writtenData) {
		t.Fatalf("expected %x, got %x", testData, writtenData)
	}
}

func TestMobile2GoWriterWithSHA256(t *testing.T) {
	testData := []byte("Hello World!")
	testHash := sha256.Sum256(testData)
	outBuf := &bytes.Buffer{}
	reader := bytes.NewReader(testData)
	writer := NewMobile2GoWriterWithSHA256(outBuf)
	bufSize := 2
	writeBuf := make([]byte, bufSize)
	reachedEnd := false
	for !reachedEnd {
		n, err := reader.Read(writeBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				reachedEnd = true
			} else {
				t.Fatal("Expected no error while reading, got:", err)
			}
		}
		writtenTotal := 0
		for writtenTotal < n {
			written, err := writer.Write(writeBuf[writtenTotal:n])
			if err != nil {
				t.Fatal("Expected no error while writing, got:", err)
			}
			writtenTotal += written
		}
	}
	if writtenData := outBuf.Bytes(); !bytes.Equal(testData, writtenData) {
		t.Fatalf("expected data to be %x, got %x", testData, writtenData)
	}

	if writtenHash := writer.GetSHA256(); !bytes.Equal(testHash[:], writtenHash) {
		t.Fatalf("expected has to be %x, got %x", testHash, writtenHash)
	}
}

func TestGo2MobileReader(t *testing.T) {
	testData := []byte("Hello World!")
	reader := NewGo2MobileReader(bytes.NewReader(testData))
	var readData []byte
	bufSize := 2
	reachedEnd := false
	for !reachedEnd {
		res, err := reader.Read(bufSize)
		if err != nil {
			t.Fatal("Expected no error while reading, got:", err)
		}
		n := res.N
		reachedEnd = res.IsEOF
		if n > 0 {
			readData = append(readData, res.Data[:n]...)
		}
	}
	if !bytes.Equal(testData, readData) {
		t.Fatalf("expected data to be %x, got %x", testData, readData)
	}
}

type testMobileReader struct {
	reader      io.Reader
	returnError bool
}

func (r *testMobileReader) Read(max int) (*MobileReadResult, error) {
	if r.returnError {
		return nil, errors.New("gopenpgp: test - forced error while reading")
	}
	buf := make([]byte, max)
	n, err := r.reader.Read(buf)
	eof := false
	if err != nil {
		if errors.Is(err, io.EOF) {
			eof = true
		} else {
			return nil, errors.New("gopenpgp: test - error while reading")
		}
	}
	return NewMobileReadResult(n, eof, buf[:n]), nil
}

func TestMobile2GoReader(t *testing.T) {
	testData := []byte("Hello World!")
	reader := NewMobile2GoReader(&testMobileReader{bytes.NewReader(testData), false})
	var readData []byte
	bufSize := 2
	readBuf := make([]byte, bufSize)
	reachedEnd := false
	for !reachedEnd {
		n, err := reader.Read(readBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				reachedEnd = true
			} else {
				t.Fatal("Expected no error while reading, got:", err)
			}
		}
		if n > 0 {
			readData = append(readData, readBuf[:n]...)
		}
	}
	if !bytes.Equal(testData, readData) {
		t.Fatalf("expected data to be %x, got %x", testData, readData)
	}
	readerErr := NewMobile2GoReader(&testMobileReader{bytes.NewReader(testData), true})
	if _, err := readerErr.Read(readBuf); err == nil {
		t.Fatal("expected an error while reading, got nil")
	}
}
