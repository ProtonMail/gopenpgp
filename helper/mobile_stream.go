package helper

import (
	"crypto/sha256"
	"hash"
	"io"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pkg/errors"
)

// Mobile2GoWriter is used to wrap a writer in the mobile app runtime,
// to be usable in the golang runtime (via gomobile).
type Mobile2GoWriter struct {
	writer crypto.Writer
}

// NewMobile2GoWriter wraps a writer to be usable in the golang runtime (via gomobile).
func NewMobile2GoWriter(writer crypto.Writer) *Mobile2GoWriter {
	return &Mobile2GoWriter{writer}
}

// Write writes the data in the provided buffer in the wrapped writer.
// It clones the provided data to prevent errors with garbage collectors.
func (w *Mobile2GoWriter) Write(b []byte) (n int, err error) {
	bufferCopy := clone(b)
	return w.writer.Write(bufferCopy)
}

// Mobile2GoWriterWithSHA256 is used to wrap a writer in the mobile app runtime,
// to be usable in the golang runtime (via gomobile).
// It also computes the SHA256 hash of the data being written on the fly.
type Mobile2GoWriterWithSHA256 struct {
	writer crypto.Writer
	sha256 hash.Hash
}

// NewMobile2GoWriterWithSHA256 wraps a writer to be usable in the golang runtime (via gomobile).
// The wrapper also computes the SHA256 hash of the data being written on the fly.
func NewMobile2GoWriterWithSHA256(writer crypto.Writer) *Mobile2GoWriterWithSHA256 {
	return &Mobile2GoWriterWithSHA256{writer, sha256.New()}
}

// Write writes the data in the provided buffer in the wrapped writer.
// It clones the provided data to prevent errors with garbage collectors.
// It also computes the SHA256 hash of the data being written on the fly.
func (w *Mobile2GoWriterWithSHA256) Write(b []byte) (n int, err error) {
	bufferCopy := clone(b)
	n, err = w.writer.Write(bufferCopy)
	if err == nil {
		hashedTotal := 0
		for hashedTotal < n {
			hashed, err := w.sha256.Write(bufferCopy[hashedTotal:n])
			if err != nil {
				return 0, errors.Wrap(err, "gopenpgp: couldn't hash encrypted data")
			}
			hashedTotal += hashed
		}
	}
	return n, err
}

// GetSHA256 returns the SHA256 hash of the data that's been written so far.
func (w *Mobile2GoWriterWithSHA256) GetSHA256() []byte {
	return w.sha256.Sum(nil)
}

// MobileReader is the interface that readers in the mobile runtime must use and implement.
// This is a workaround to some of the gomobile limitations.
type MobileReader interface {
	Read(max int) (result *MobileReadResult, err error)
}

// MobileReadResult is what needs to be returned by MobileReader.Read.
// The read data is passed as a return value rather than passed as an argument to the reader.
// This avoids problems introduced by gomobile that prevent the use of native golang readers.
type MobileReadResult struct {
	N     int    // N, The number of bytes read
	IsEOF bool   // IsEOF, If true, then the reader has reached the end of the data to read.
	Data  []byte // Data, the data that has been read
}

// NewMobileReadResult initialize a MobileReadResult with the correct values.
// It clones the data to avoid the garbage collector freeing the data too early.
func NewMobileReadResult(n int, eof bool, data []byte) *MobileReadResult {
	return &MobileReadResult{N: n, IsEOF: eof, Data: clone(data)}
}

func clone(src []byte) (dst []byte) {
	dst = make([]byte, len(src))
	copy(dst, src)
	return
}

// Mobile2GoReader is used to wrap a MobileReader in the mobile app runtime,
// to be usable in the golang runtime (via gomobile) as a native Reader.
type Mobile2GoReader struct {
	reader MobileReader
}

// NewMobile2GoReader wraps a MobileReader to be usable in the golang runtime (via gomobile).
func NewMobile2GoReader(reader MobileReader) *Mobile2GoReader {
	return &Mobile2GoReader{reader}
}

// Read reads data from the wrapped MobileReader and copies the read data in the provided buffer.
// It also handles the conversion of EOF to an error.
func (r *Mobile2GoReader) Read(b []byte) (n int, err error) {
	result, err := r.reader.Read(len(b))
	if err != nil {
		return 0, errors.Wrap(err, "gopenpgp: couldn't read from mobile reader")
	}
	n = result.N
	if n > 0 {
		copy(b, result.Data[:n])
	}
	if result.IsEOF {
		err = io.EOF
	}
	return n, err
}

// Go2MobileReader is used to wrap a native golang Reader in the golang runtime,
// to be usable in the mobile app runtime (via gomobile) as a MobileReader.
type Go2MobileReader struct {
	isEOF  bool
	reader crypto.Reader
}

// NewGo2MobileReader wraps a native golang Reader to be usable in the mobile app runtime (via gomobile).
// It doesn't follow the standard golang Reader behavior, and returns n = -1 on EOF.
func NewGo2MobileReader(reader crypto.Reader) *Go2MobileReader {
	return &Go2MobileReader{isEOF: false, reader: reader}
}

// Read reads bytes into the provided buffer and returns the number of bytes read
// It doesn't follow the standard golang Reader behavior, and returns n = -1 on EOF.
func (r *Go2MobileReader) Read(b []byte) (n int, err error) {
	if r.isEOF {
		return -1, nil
	}
	n, err = r.reader.Read(b)
	if errors.Is(err, io.EOF) {
		if n == 0 {
			return -1, nil
		} else {
			r.isEOF = true
			return n, nil
		}
	}
	return
}
