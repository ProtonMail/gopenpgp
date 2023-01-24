package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

func TestSessionKey_EncryptDecryptStream(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	messageWriter, err := testSessionKey.EncryptStream(
		&dataPacketBuf,
		testMeta,
		keyRingTestPrivate,
	)
	if err != nil {
		t.Fatal("Expected no error while encrypting stream with session key, got:", err)
	}
	bufferSize := 2
	buffer := make([]byte, bufferSize)
	reachedEnd := false
	for !reachedEnd {
		n, err := messageReader.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				reachedEnd = true
			} else {
				t.Fatal("Expected no error while reading data, got:", err)
			}
		}
		writtenTotal := 0
		for writtenTotal < n {
			written, err := messageWriter.Write(buffer[writtenTotal:n])
			if err != nil {
				t.Fatal("Expected no error while writing data, got:", err)
			}
			writtenTotal += written
		}
	}
	err = messageWriter.Close()
	if err != nil {
		t.Fatal("Expected no error while closing plaintext writer, got:", err)
	}
	dataPacket := dataPacketBuf.Bytes()
	decryptedReader, err := testSessionKey.DecryptStream(
		bytes.NewReader(dataPacket),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling DecryptStream, got:", err)
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	err = decryptedReader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the signature, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	decryptedMeta := decryptedReader.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
}

func TestSessionKey_EncryptStreamCompatible(t *testing.T) {
	enc := func(w io.Writer, meta *PlainMessageMetadata, kr *KeyRing) (io.WriteCloser, error) {
		return testSessionKey.EncryptStream(w, meta, kr)
	}
	testSessionKey_EncryptStreamCompatible(enc, t)
}

func TestSessionKey_EncryptStreamWithCompressionCompatible(t *testing.T) {
	enc := func(w io.Writer, meta *PlainMessageMetadata, kr *KeyRing) (io.WriteCloser, error) {
		return testSessionKey.EncryptStreamWithCompression(w, meta, kr)
	}
	testSessionKey_EncryptStreamCompatible(enc, t)
}

type sessionKeyEncryptionFunction = func(io.Writer, *PlainMessageMetadata, *KeyRing) (io.WriteCloser, error)

func testSessionKey_EncryptStreamCompatible(enc sessionKeyEncryptionFunction, t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	messageWriter, err := enc(
		&dataPacketBuf,
		testMeta,
		keyRingTestPrivate,
	)
	if err != nil {
		t.Fatal("Expected no error while encrypting stream with session key, got:", err)
	}
	bufferSize := 2
	buffer := make([]byte, bufferSize)
	reachedEnd := false
	for !reachedEnd {
		n, err := messageReader.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				reachedEnd = true
			} else {
				t.Fatal("Expected no error while reading data, got:", err)
			}
		}
		writtenTotal := 0
		for writtenTotal < n {
			written, err := messageWriter.Write(buffer[writtenTotal:n])
			if err != nil {
				t.Fatal("Expected no error while writing data, got:", err)
			}
			writtenTotal += written
		}
	}
	err = messageWriter.Close()
	if err != nil {
		t.Fatal("Expected no error while closing plaintext writer, got:", err)
	}
	dataPacket := dataPacketBuf.Bytes()
	decryptedMsg, err := testSessionKey.DecryptAndVerify(
		dataPacket,
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling DecryptAndVerify, got:", err)
	}
	decryptedBytes := decryptedMsg.Data
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	if testMeta.IsBinary != decryptedMsg.IsBinary() {
		t.Fatalf("Expected isBinary to be %t got %t", testMeta.IsBinary, decryptedMsg.IsBinary())
	}
	if testMeta.Filename != decryptedMsg.GetFilename() {
		t.Fatalf("Expected filename to be %s got %s", testMeta.Filename, decryptedMsg.GetFilename())
	}
	if testMeta.ModTime != int64(decryptedMsg.GetTime()) {
		t.Fatalf("Expected modification time to be %d got %d", testMeta.ModTime, int64(decryptedMsg.GetTime()))
	}
}

func TestSessionKey_DecryptStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	dataPacket, err := testSessionKey.EncryptAndSign(
		&PlainMessage{
			Data:     messageBytes,
			TextType: !testMeta.IsBinary,
			Time:     uint32(testMeta.ModTime),
			Filename: testMeta.Filename,
		},
		keyRingTestPrivate,
	)
	if err != nil {
		t.Fatal("Expected no error while encrypting plaintext, got:", err)
	}
	decryptedReader, err := testSessionKey.DecryptStream(
		bytes.NewReader(dataPacket),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling DecryptStream, got:", err)
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	err = decryptedReader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the signature, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	decryptedMeta := decryptedReader.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
}
