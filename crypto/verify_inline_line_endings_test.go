package crypto

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// sanitizeReaderBufferSize is the default bufio.Reader size used by
// internal.NewSanitizeReader. The streamed case places a canonical CRLF on
// this boundary so the '\r' and '\n' arrive in different sanitizer reads.
const sanitizeReaderBufferSize = 4096

func TestVerifyInlineRevertsTextLineEndings(t *testing.T) {
	signer := newInlineSigner(t, true)
	verifier := newInlineVerifier(t, false)

	split := bytes.Repeat([]byte("a"), sanitizeReaderBufferSize-1)
	split = append(split, '\n', 't', 'a', 'i', 'l', '\n')

	cases := []struct {
		name       string
		plaintext  []byte
		chunkSize  int
		checkSplit bool
	}{
		{name: "newlines", plaintext: []byte("a\nb\n"), chunkSize: 1},
		{name: "no trailing newline", plaintext: []byte("a\nb"), chunkSize: 1},
		{name: "lone cr", plaintext: []byte("a\rb"), chunkSize: 1},
		{name: "already crlf", plaintext: []byte("a\r\nb\r\n"), chunkSize: 1},
		{name: "empty", plaintext: []byte{}, chunkSize: 1},
		{
			name:       "crlf split across read boundary",
			plaintext:  split,
			chunkSize:  sanitizeReaderBufferSize - 1,
			checkSplit: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed := signInline(t, signer, tc.plaintext)
			want := revertCanonicalLineEndings(t, tc.plaintext)
			if tc.checkSplit {
				assertCanonicalCRLFSplit(t, signed)
			}
			assertInlinePlaintext(t, verifier, signed, want, tc.chunkSize)
		})
	}
}

func TestVerifyInlineBinaryLineEndingsUnchanged(t *testing.T) {
	signer := newInlineSigner(t, false)
	verifier := newInlineVerifier(t, false)

	split := bytes.Repeat([]byte("a"), sanitizeReaderBufferSize-1)
	split = append(split, '\r', '\n', 't', 'a', 'i', 'l')

	cases := []struct {
		name      string
		plaintext []byte
		chunkSize int
	}{
		{name: "crlf", plaintext: []byte("a\r\nb\r\n"), chunkSize: 1},
		{name: "no trailing newline", plaintext: []byte("a\nb"), chunkSize: 1},
		{name: "lone cr", plaintext: []byte("a\rb"), chunkSize: 1},
		{name: "empty", plaintext: []byte{}, chunkSize: 1},
		{
			name:      "crlf split across read boundary",
			plaintext: split,
			chunkSize: sanitizeReaderBufferSize,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed := signInline(t, signer, tc.plaintext)
			assertInlinePlaintext(t, verifier, signed, tc.plaintext, tc.chunkSize)
		})
	}
}

func TestVerifyInlineDisableAutomaticTextSanitize(t *testing.T) {
	plaintext := []byte("a\nb\n")
	signer := newInlineSigner(t, true)
	verifier := newInlineVerifier(t, true)
	signed := signInline(t, signer, plaintext)
	want := canonicalText(t, plaintext)
	assertInlinePlaintext(t, verifier, signed, want, 1)
}

func newInlineSigner(t *testing.T, utf8 bool) PGPSign {
	t.Helper()
	builder := testPGP.Sign().SigningKeys(keyRingTestPrivate)
	if utf8 {
		builder = builder.Utf8()
	}
	signer, err := builder.New()
	if err != nil {
		t.Fatal("Expected no error creating signer, got:", err)
	}
	return signer
}

func newInlineVerifier(t *testing.T, disableSanitize bool) PGPVerify {
	t.Helper()
	builder := testPGP.Verify().VerificationKeys(keyRingTestPublic)
	if disableSanitize {
		builder = builder.DisableAutomaticTextSanitize()
	}
	verifier, err := builder.New()
	if err != nil {
		t.Fatal("Expected no error creating verifier, got:", err)
	}
	return verifier
}

func signInline(t *testing.T, signer PGPSign, plaintext []byte) []byte {
	t.Helper()
	signed, err := signer.Sign(plaintext, Bytes)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	return signed
}

func assertInlinePlaintext(t *testing.T, verifier PGPVerify, signed, want []byte, chunkSize int) {
	t.Helper()
	verified, err := verifier.VerifyInline(signed, Bytes)
	if err != nil {
		t.Fatal("Expected no error while verifying inline, got:", err)
	}
	if err = verified.SignatureError(); err != nil {
		t.Fatal("Expected no signature error while verifying inline, got:", err)
	}
	assertPlaintext(t, "VerifyInline", verified.Bytes(), want)

	reader, err := verifier.VerifyingReader(nil, bytes.NewReader(signed), Bytes)
	if err != nil {
		t.Fatal("Expected no error while opening verifying reader, got:", err)
	}
	streamed := readInChunks(t, reader, chunkSize)
	verifyResult, err := reader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying streamed signature, got:", err)
	}
	if err = verifyResult.SignatureError(); err != nil {
		t.Fatal("Expected no signature error while verifying streamed signature, got:", err)
	}
	assertPlaintext(t, "VerifyingReader", streamed, want)
}

func assertPlaintext(t *testing.T, path string, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	if len(got) < 80 && len(want) < 80 {
		t.Errorf("%s plaintext = %q, want %q", path, got, want)
		return
	}
	limit := len(got)
	if len(want) < limit {
		limit = len(want)
	}
	for i := range limit {
		if got[i] != want[i] {
			t.Errorf("%s plaintext mismatch at %d: got %#x want %#x (lens %d and %d)", path, i, got[i], want[i], len(got), len(want))
			return
		}
	}
	t.Errorf("%s plaintext length = %d, want %d", path, len(got), len(want))
}

func assertCanonicalCRLFSplit(t *testing.T, signed []byte) {
	t.Helper()
	body := inlineLiteralBody(t, signed)
	splitAt := sanitizeReaderBufferSize
	if len(body) <= splitAt || body[splitAt-1] != '\r' || body[splitAt] != '\n' {
		t.Fatalf("canonical text does not place CRLF across the %d-byte read boundary (len=%d)", splitAt, len(body))
	}
}

func inlineLiteralBody(t *testing.T, signed []byte) []byte {
	t.Helper()
	packets := packet.NewReader(bytes.NewReader(signed))
	for {
		p, err := packets.Next()
		if err != nil {
			t.Fatal("Expected a literal data packet in the signed message, got:", err)
		}
		literal, ok := p.(*packet.LiteralData)
		if !ok {
			continue
		}
		body, err := io.ReadAll(literal.Body)
		if err != nil {
			t.Fatal("Expected no error reading literal data, got:", err)
		}
		return body
	}
}

func revertCanonicalLineEndings(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	return bytes.ReplaceAll(canonicalText(t, plaintext), []byte("\r\n"), []byte("\n"))
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func canonicalText(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := openpgp.NewCanonicalTextWriteCloser(nopWriteCloser{&buf})
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal("Expected no error canonicalising text, got:", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal("Expected no error closing canonical text writer, got:", err)
	}
	return buf.Bytes()
}

func readInChunks(t *testing.T, reader io.Reader, chunkSize int) []byte {
	t.Helper()
	var out bytes.Buffer
	buf := make([]byte, chunkSize)
	emptyReads := 0
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			emptyReads = 0
			out.Write(buf[:n])
		}
		if errors.Is(err, io.EOF) {
			return out.Bytes()
		}
		if err != nil {
			t.Fatal("Expected no error while reading verified data, got:", err)
		}
		if n == 0 {
			emptyReads++
			if emptyReads > 100 {
				t.Fatal("Expected the verifying reader to make progress")
			}
		}
	}
}
