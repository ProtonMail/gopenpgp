package crypto

import (
	"bytes"
	"io"
	"testing"

	"github.com/pkg/errors"
)

func TestSessionKey_EncryptDecryptStream(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	isBinary := true
	modTime := GetUnixTime()
	messageWriter, err := testSessionKey.EncryptStream(
		&dataPacketBuf,
		isBinary,
		testFilename,
		modTime,
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
	decryptedBytes, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	err = decryptedReader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the signature, got:", err)
	}
	if isBinary != decryptedReader.IsBinary() {
		t.Fatalf("Expected isBinary to be %t got %t", isBinary, decryptedReader.IsBinary())
	}
	if testFilename != decryptedReader.GetFilename() {
		t.Fatalf("Expected filename to be %s got %s", testFilename, decryptedReader.GetFilename())
	}
	if modTime != decryptedReader.GetModificationTime() {
		t.Fatalf("Expected modification time to be %d got %d", modTime, decryptedReader.GetModificationTime())
	}
}

func TestSessionKey_EncryptStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	isBinary := true
	modTime := GetUnixTime()
	messageWriter, err := testSessionKey.EncryptStream(
		&dataPacketBuf,
		isBinary,
		testFilename,
		modTime,
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
	if isBinary != decryptedMsg.IsBinary() {
		t.Fatalf("Expected isBinary to be %t got %t", isBinary, decryptedMsg.IsBinary())
	}
	if testFilename != decryptedMsg.GetFilename() {
		t.Fatalf("Expected filename to be %s got %s", testFilename, decryptedMsg.GetFilename())
	}
	if modTime != int64(decryptedMsg.GetTime()) {
		t.Fatalf("Expected modification time to be %d got %d", modTime, int64(decryptedMsg.GetTime()))
	}
}

func TestSessionKey_DecryptStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	modTime := GetUnixTime()
	dataPacket, err := testSessionKey.EncryptAndSign(
		NewPlainMessageFromFile(messageBytes, testFilename, uint32(modTime)),
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
	decryptedBytes, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	err = decryptedReader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the signature, got:", err)
	}
	if !decryptedReader.IsBinary() {
		t.Fatalf("Expected isBinary to be %t got %t", true, decryptedReader.IsBinary())
	}
	if testFilename != decryptedReader.GetFilename() {
		t.Fatalf("Expected filename to be %s got %s", testFilename, decryptedReader.GetFilename())
	}
	if modTime != decryptedReader.GetModificationTime() {
		t.Fatalf("Expected modification time to be %d got %d", modTime, decryptedReader.GetModificationTime())
	}
}
