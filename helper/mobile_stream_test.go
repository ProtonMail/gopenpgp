package helper

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
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

func TestGo2AndroidReader(t *testing.T) {
	testData := []byte("Hello World!")
	reader := NewGo2AndroidReader(bytes.NewReader(testData))
	var readData []byte
	bufSize := 2
	buffer := make([]byte, bufSize)
	reachedEnd := false
	for !reachedEnd {
		n, err := reader.Read(buffer)
		if err != nil {
			t.Fatal("Expected no error while reading, got:", err)
		}
		reachedEnd = n < 0
		if n > 0 {
			readData = append(readData, buffer[:n]...)
		}
	}
	if !bytes.Equal(testData, readData) {
		t.Fatalf("expected data to be %x, got %x", testData, readData)
	}
}

func TestGo2IOSReader(t *testing.T) {
	testData := []byte("Hello World!")
	reader := NewGo2IOSReader(bytes.NewReader(testData))
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

func setUpTestKeyRing() (*crypto.KeyRing, *crypto.KeyRing, error) {
	testKey, err := crypto.GenerateKey("test", "test@protonmail.com", "x25519", 0, 0)
	if err != nil {
		return nil, nil, err
	}
	testPublicKey, err := testKey.ToPublic()
	if err != nil {
		return nil, nil, err
	}
	testPrivateKeyRing, err := crypto.NewKeyRing(testKey)
	if err != nil {
		return nil, nil, err
	}
	testPublicKeyRing, err := crypto.NewKeyRing(testPublicKey)
	if err != nil {
		return nil, nil, err
	}
	return testPublicKeyRing, testPrivateKeyRing, nil
}

func TestExplicitVerifyAllGoesWell(t *testing.T) {
	data := []byte("hello")
	pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	ciphertext, err := pubKR.Encrypt(crypto.NewPlainMessage(data), privKR)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	reader, err := privKR.DecryptStream(
		bytes.NewReader(ciphertext.Data),
		pubKR,
		crypto.GetUnixTime(),
	)
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := VerifySignatureExplicit(reader)
	if sigErr != nil {
		t.Fatalf("Got a signature error while verifying embedded sig: %v", sigErr)
	}
	if err != nil {
		t.Fatalf("Got an error while verifying embedded sig: %v", err)
	}
}

func TestExplicitVerifyTooEarly(t *testing.T) {
	data := []byte("hello")
	pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	ciphertext, err := pubKR.Encrypt(crypto.NewPlainMessage(data), privKR)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	reader, err := privKR.DecryptStream(
		bytes.NewReader(ciphertext.Data),
		pubKR,
		crypto.GetUnixTime(),
	)
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	buff := make([]byte, 1)
	_, err = reader.Read(buff)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := VerifySignatureExplicit(reader)
	if sigErr != nil {
		t.Fatalf("Got a signature error while verifying embedded sig: %v", sigErr)
	}
	if err == nil {
		t.Fatalf("Got no error while verifying a reader before reading it entirely")
	}
}

func TestExplicitVerifyNoSig(t *testing.T) {
	data := []byte("hello")
	pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	ciphertext, err := pubKR.Encrypt(crypto.NewPlainMessage(data), nil)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	reader, err := privKR.DecryptStream(
		bytes.NewReader(ciphertext.Data),
		pubKR,
		crypto.GetUnixTime(),
	)
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := VerifySignatureExplicit(reader)
	if sigErr == nil {
		t.Fatal("Got no signature error while verifying unsigned data")
	}
	if sigErr.Status != constants.SIGNATURE_NOT_SIGNED {
		t.Fatal("Signature error status was not SIGNATURE_NOT_SIGNED")
	}
	if err != nil {
		t.Fatalf("Got an error while verifying embedded sig: %v", err)
	}
}

func TestExplicitVerifyWrongVerifier(t *testing.T) {
	data := []byte("hello")
	pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	_, privKR2, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR2.ClearPrivateParams()
	ciphertext, err := pubKR.Encrypt(crypto.NewPlainMessage(data), privKR2)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	reader, err := privKR.DecryptStream(
		bytes.NewReader(ciphertext.Data),
		pubKR,
		crypto.GetUnixTime(),
	)
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := VerifySignatureExplicit(reader)
	if sigErr == nil {
		t.Fatal("Got no signature error while verifying with wrong key")
	}
	if sigErr.Status != constants.SIGNATURE_NO_VERIFIER {
		t.Fatal("Signature error status was not SIGNATURE_NO_VERIFIER")
	}
	if err != nil {
		t.Fatalf("Got an error while verifying embedded sig: %v", err)
	}
}
