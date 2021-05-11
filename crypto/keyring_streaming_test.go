package crypto

import (
	"bytes"
	"io"
	"testing"

	"github.com/pkg/errors"
)

const testFilename = "filename.txt"

func TestKeyRing_EncryptStream(t *testing.T) {
	keyRingPrivate, err := keyRingTestPrivate.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	keyRingPublic, err := keyRingTestPublic.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	isBinary := true
	filename := "filename.txt"
	modTime := GetUnixTime()
	messageWriter, err := keyRingPublic.EncryptStream(
		&ciphertextBuf,
		isBinary,
		filename,
		modTime,
		keyRingPrivate,
	)
	if err != nil {
		t.Fatal("Expected no error while encrypting stream with key ring, got:", err)
	}
	reachedEnd := false
	bufferSize := 2
	buffer := make([]byte, bufferSize)
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
	decryptedReader, err := keyRingPrivate.DecryptStream(
		&ciphertextBuf,
		keyRingPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
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
	if filename != decryptedReader.GetFilename() {
		t.Fatalf("Expected filename to be %s got %s", filename, decryptedReader.GetFilename())
	}
	if modTime != decryptedReader.GetModificationTime() {
		t.Fatalf("Expected modification time to be %d got %d", modTime, decryptedReader.GetModificationTime())
	}
}

func TestKeyRing_EncryptSplitStream(t *testing.T) {
	keyRingPrivate, err := keyRingTestPrivate.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	keyRingPublic, err := keyRingTestPublic.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	isBinary := true
	filename := "filename.txt"
	modTime := GetUnixTime()
	encryptionResult, err := keyRingPublic.EncryptSplitStream(
		&dataPacketBuf,
		isBinary,
		filename,
		modTime,
		keyRingPrivate,
	)
	if err != nil {
		t.Fatal("Expected no error while calling encrypting split stream with key ring, got:", err)
	}
	messageWriter := encryptionResult
	reachedEnd := false
	bufferSize := 2
	buffer := make([]byte, bufferSize)
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
	keyPacket, err := encryptionResult.GetKeyPacket()
	if err != nil {
		t.Fatal("Expected no error while accessing key packet, got:", err)
	}
	dataPacket := dataPacketBuf.Bytes()
	decryptedReader, err := keyRingPrivate.DecryptSplitStream(
		keyPacket,
		bytes.NewReader(dataPacket),
		keyRingPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while decrypting split stream with key ring, got:", err)
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
	if filename != decryptedReader.GetFilename() {
		t.Fatalf("Expected filename to be %s got %s", filename, decryptedReader.GetFilename())
	}
	if modTime != decryptedReader.GetModificationTime() {
		t.Fatalf("Expected modification time to be %d got %d", modTime, decryptedReader.GetModificationTime())
	}
}

func TestKeyRing_SignDetachedStream(t *testing.T) {
	keyRingPrivate, err := keyRingTestPrivate.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	keyRingPublic, err := keyRingTestPublic.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	signature, err := keyRingPrivate.SignDetachedStream(messageReader)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingPublic.VerifyDetachedStream(messageReader, signature, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_SignDetachedEncryptedStream(t *testing.T) {
	keyRingPrivate, err := keyRingTestPrivate.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	keyRingPublic, err := keyRingTestPublic.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	encSignature, err := keyRingPrivate.SignDetachedEncryptedStream(messageReader, keyRingPublic)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingPublic.VerifyDetachedEncryptedStream(messageReader, encSignature, keyRingPrivate, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}
