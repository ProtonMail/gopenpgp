package internal

import (
	"bytes"
	"io"
)

func trim(p []byte) []byte {
	return bytes.TrimRight(p, " \t\r")
}

func NewTrimWriteCloser(internal io.WriteCloser) *TrimWriteCloser {
	return NewTrimWriteCloserWithBufferSize(internal, 256)
}

func NewTrimWriteCloserWithBufferSize(internal io.WriteCloser, size int) *TrimWriteCloser {
	return &TrimWriteCloser{
		internal:   internal,
		whitespace: bytes.NewBuffer(make([]byte, 0, size)),
		err:        nil,
	}
}

type TrimWriteCloser struct {
	internal   io.WriteCloser
	whitespace *bytes.Buffer
	err        error
}

func (w *TrimWriteCloser) Write(p []byte) (n int, err error) {
	n = len(p)
	if w.err != nil {
		return 0, err
	}
	for index := bytes.IndexByte(p, '\n'); index != -1; index = bytes.IndexByte(p, '\n') {
		trimmedSuffixLine := trim(p[:index])
		bufferWhitespace := w.whitespace.Bytes()
		if len(bufferWhitespace) > 0 {
			if len(trimmedSuffixLine) != 0 {
				if _, err = w.internal.Write(bufferWhitespace); err != nil {
					w.err = err
					return 0, err
				}
			}
			w.whitespace.Reset()
		}
		if len(trimmedSuffixLine) < len(p[:index]) {
			if _, err = w.internal.Write(trimmedSuffixLine); err != nil {
				w.err = err
				return index, err
			}
			if _, err = w.internal.Write([]byte("\n")); err != nil {
				w.err = err
				return index + 1, err
			}
		} else {
			if _, err = w.internal.Write(p[:index+1]); err != nil {
				w.err = err
				return index + 1, err
			}
		}
		p = p[index+1:]
	}

	if len(p) > 0 {
		nonWhitespace := trim(p)
		if len(nonWhitespace) > 0 && w.whitespace.Len() > 0 {
			if _, err = w.internal.Write(w.whitespace.Bytes()); err != nil {
				w.err = err
				return n - len(p), err
			}
			w.whitespace.Reset()
		}
		if _, err = w.internal.Write(nonWhitespace); err != nil {
			w.err = err
			return n - len(p), err
		}

		if _, err = w.whitespace.Write(p[len(nonWhitespace):]); err != nil {
			w.err = err
			return n - len(p), err
		}
	}
	return n, nil
}

func (w *TrimWriteCloser) Close() error {
	return w.internal.Close()
}
