package mobile

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
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

func setUpTestKeyRing() (*crypto.PGPHandle, *crypto.KeyRing, *crypto.KeyRing, error) {
	pgpHandle := crypto.PGPWithProfile(profile.GnuPG())
	testKey, err := pgpHandle.KeyGeneration().
		AddUserId("test", "test@protonmail.com").
		New().
		GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	testPublicKey, err := testKey.ToPublic()
	if err != nil {
		return nil, nil, nil, err
	}
	testPrivateKeyRing, err := crypto.NewKeyRing(testKey)
	if err != nil {
		return nil, nil, nil, err
	}
	testPublicKeyRing, err := crypto.NewKeyRing(testPublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return pgpHandle, testPublicKeyRing, testPrivateKeyRing, nil
}

func TestExplicitVerifyAllGoesWell(t *testing.T) {
	data := []byte("hello")
	pgpHandle, pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	encHandle, _ := pgpHandle.Encryption().Recipients(pubKR).SigningKeys(privKR).New()
	ciphertext, err := encHandle.Encrypt(data)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	decHandle, _ := pgpHandle.Decryption().DecryptionKeys(privKR).VerifyKeys(pubKR).New()
	reader, err := decHandle.DecryptingReader(bytes.NewReader(ciphertext.GetBinary()))
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := reader.VerifySignature()
	if sigErr.HasSignatureError() {
		t.Fatalf("Got a signature error while verifying embedded sig: %v", sigErr.SignatureError())
	}
	if err != nil {
		t.Fatalf("Got an error while verifying embedded sig: %v", err)
	}
}

func TestExplicitVerifyTooEarly(t *testing.T) {
	data := []byte("hello")
	pgp, pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	encHandle, _ := pgp.Encryption().Recipients(pubKR).SigningKeys(privKR).New()
	ciphertext, err := encHandle.Encrypt(data)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	decHandle, _ := pgp.Decryption().DecryptionKeys(privKR).VerifyKeys(pubKR).New()
	reader, err := decHandle.DecryptingReader(bytes.NewReader(ciphertext.GetBinary()))
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	buff := make([]byte, 1)
	_, err = reader.Read(buff)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := reader.VerifySignature()
	if err == nil {
		t.Fatalf("Got no error while verifying a reader before reading it entirely")
	}
	if sigErr.HasSignatureError() {
		t.Fatalf("Got a signature error while verifying embedded sig: %v", sigErr.SignatureError())
	}
}

func TestExplicitVerifyNoSig(t *testing.T) {
	data := []byte("hello")
	pgp, pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	encHandle, _ := pgp.Encryption().Recipients(pubKR).New()
	ciphertext, err := encHandle.Encrypt(data)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	decHandle, _ := pgp.Decryption().DecryptionKeys(privKR).VerifyKeys(pubKR).New()
	reader, err := decHandle.DecryptingReader(bytes.NewReader(ciphertext.GetBinary()))
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := reader.VerifySignature()
	if err != nil {
		t.Fatalf("Got an error while verifying embedded sig: %v", err)
	}
	if !sigErr.HasSignatureError() {
		t.Fatal("Got no signature error while verifying unsigned data")
	}
	if sigErr.SignatureErrorExplicit().Status != constants.SIGNATURE_NOT_SIGNED {
		t.Fatal("Signature error status was not SIGNATURE_NOT_SIGNED")
	}
}

func TestExplicitVerifyWrongVerifier(t *testing.T) {
	data := []byte("hello")
	pgp, pubKR, privKR, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR.ClearPrivateParams()
	_, _, privKR2, err := setUpTestKeyRing()
	if err != nil {
		t.Fatalf("Got an error while loading test key: %v", err)
	}
	defer privKR2.ClearPrivateParams()
	encHandle, _ := pgp.Encryption().Recipients(pubKR).SigningKeys(privKR2).New()
	ciphertext, err := encHandle.Encrypt(data)
	if err != nil {
		t.Fatalf("Got an error while encrypting test data: %v", err)
	}
	decHandle, _ := pgp.Decryption().DecryptionKeys(privKR).VerifyKeys(pubKR).New()
	reader, err := decHandle.DecryptingReader(bytes.NewReader(ciphertext.GetBinary()))
	if err != nil {
		t.Fatalf("Got an error while decrypting stream data: %v", err)
	}
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("Got an error while reading decrypted data: %v", err)
	}
	sigErr, err := reader.VerifySignature()
	if err != nil {
		t.Fatalf("Got an error while verifying embedded sig: %v", err)
	}
	if !sigErr.HasSignatureError() {
		t.Fatal("Got no signature error while verifying with wrong key")
	}
	if sigErr.SignatureErrorExplicit().Status != constants.SIGNATURE_NO_VERIFIER {
		t.Fatal("Signature error status was not SIGNATURE_NO_VERIFIER")
	}
}
