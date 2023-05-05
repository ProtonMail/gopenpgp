package crypto

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"reflect"
	"testing"
)

const testContext = "test-context"

var testMeta = &PlainMessageMetadata{
	IsBinary: true,
	Filename: "filename.txt",
	ModTime:  GetUnixTime(),
}

func TestKeyRing_EncryptDecryptStream(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	messageWriter, err := keyRingTestPublic.EncryptStream(
		&ciphertextBuf,
		testMeta,
		keyRingTestPrivate,
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
	ciphertextBytes := ciphertextBuf.Bytes()
	decryptedReader, err := keyRingTestPrivate.DecryptStream(
		bytes.NewReader(ciphertextBytes),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature before reading the data, got nil")
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
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
	decryptedMeta := decryptedReader.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
	decryptedReaderNoVerify, err := keyRingTestPrivate.DecryptStream(
		bytes.NewReader(ciphertextBytes),
		nil,
		0,
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	decryptedBytes, err = ioutil.ReadAll(decryptedReaderNoVerify)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	decryptedMeta = decryptedReaderNoVerify.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
	err = decryptedReaderNoVerify.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature with no keyring, got nil")
	}
}

func TestKeyRing_EncryptDecryptStreamWithContext(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	messageWriter, err := keyRingTestPublic.EncryptStreamWithContext(
		&ciphertextBuf,
		testMeta,
		keyRingTestPrivate,
		NewSigningContext(testContext, true),
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
	ciphertextBytes := ciphertextBuf.Bytes()
	decryptedReader, err := keyRingTestPrivate.DecryptStreamWithContext(
		bytes.NewReader(ciphertextBytes),
		keyRingTestPublic,
		GetUnixTime(),
		NewVerificationContext(testContext, true, 0),
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature before reading the data, got nil")
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
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
	decryptedMeta := decryptedReader.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
	decryptedReaderNoVerify, err := keyRingTestPrivate.DecryptStream(
		bytes.NewReader(ciphertextBytes),
		nil,
		0,
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	decryptedBytes, err = ioutil.ReadAll(decryptedReaderNoVerify)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	decryptedMeta = decryptedReaderNoVerify.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
	err = decryptedReaderNoVerify.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature with no keyring, got nil")
	}
}

func TestKeyRing_EncryptDecryptStreamWithContextAndCompression(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	messageWriter, err := keyRingTestPublic.EncryptStreamWithContextAndCompression(
		&ciphertextBuf,
		testMeta,
		keyRingTestPrivate,
		NewSigningContext(testContext, true),
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
	ciphertextBytes := ciphertextBuf.Bytes()
	decryptedReader, err := keyRingTestPrivate.DecryptStreamWithContext(
		bytes.NewReader(ciphertextBytes),
		keyRingTestPublic,
		GetUnixTime(),
		NewVerificationContext(testContext, true, 0),
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature before reading the data, got nil")
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
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
	decryptedMeta := decryptedReader.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
	decryptedReaderNoVerify, err := keyRingTestPrivate.DecryptStream(
		bytes.NewReader(ciphertextBytes),
		nil,
		0,
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	decryptedBytes, err = ioutil.ReadAll(decryptedReaderNoVerify)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	decryptedMeta = decryptedReaderNoVerify.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
	err = decryptedReaderNoVerify.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature with no keyring, got nil")
	}
}

func TestKeyRing_EncryptStreamCompatible(t *testing.T) {
	enc := func(w io.Writer, meta *PlainMessageMetadata, kr *KeyRing) (io.WriteCloser, error) {
		return keyRingTestPublic.EncryptStream(
			w,
			meta,
			kr,
		)
	}
	testKeyRing_EncryptStreamCompatible(enc, t)
}

func TestKeyRing_EncryptStreamWithCompressionCompatible(t *testing.T) {
	enc := func(w io.Writer, meta *PlainMessageMetadata, kr *KeyRing) (io.WriteCloser, error) {
		return keyRingTestPublic.EncryptStreamWithCompression(
			w,
			meta,
			kr,
		)
	}
	testKeyRing_EncryptStreamCompatible(enc, t)
}

type keyringEncryptionFunction = func(io.Writer, *PlainMessageMetadata, *KeyRing) (io.WriteCloser, error)

func testKeyRing_EncryptStreamCompatible(encrypt keyringEncryptionFunction, t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	messageWriter, err := encrypt(
		&ciphertextBuf,
		testMeta,
		keyRingTestPrivate,
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
	encryptedData := ciphertextBuf.Bytes()
	decryptedMsg, err := keyRingTestPrivate.Decrypt(
		NewPGPMessage(encryptedData),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling normal decrypt with key ring, got:", err)
	}
	decryptedBytes := decryptedMsg.GetBinary()
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the normally decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
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

func TestKeyRing_DecryptStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	pgpMessage, err := keyRingTestPublic.Encrypt(
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
	decryptedReader, err := keyRingTestPrivate.DecryptStream(
		bytes.NewReader(pgpMessage.GetBinary()),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
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

func TestKeyRing_EncryptDecryptSplitStream(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	encryptionResult, err := keyRingTestPublic.EncryptSplitStream(
		&dataPacketBuf,
		testMeta,
		keyRingTestPrivate,
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
	decryptedReader, err := keyRingTestPrivate.DecryptSplitStream(
		keyPacket,
		bytes.NewReader(dataPacket),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while decrypting split stream with key ring, got:", err)
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

func TestKeyRing_EncryptDecryptSplitStreamWithCont(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)

	var dataPacketBuf bytes.Buffer
	encryptionResult, err := keyRingTestPublic.EncryptSplitStreamWithContext(
		&dataPacketBuf,
		testMeta,
		keyRingTestPrivate,
		NewSigningContext(testContext, true),
	)
	if err != nil {
		t.Fatal("Expected no error while calling encrypting split stream with key ring, got:", err)
	}
	messageWriter := encryptionResult
	_, err = io.Copy(messageWriter, messageReader)
	if err != nil {
		t.Fatal("Expected no error while copying plaintext writer, got:", err)
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
	decryptedReader, err := keyRingTestPrivate.DecryptSplitStreamWithContext(
		keyPacket,
		bytes.NewReader(dataPacket),
		keyRingTestPublic,
		GetUnixTime(),
		NewVerificationContext(testContext, true, 0),
	)
	if err != nil {
		t.Fatal("Expected no error while decrypting split stream with key ring, got:", err)
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
}

func TestKeyRing_EncryptSplitStreamCompatible(t *testing.T) {
	enc := func(w io.Writer, meta *PlainMessageMetadata, kr *KeyRing) (*EncryptSplitResult, error) {
		return keyRingTestPublic.EncryptSplitStream(
			w,
			meta,
			kr,
		)
	}
	testKeyRing_EncryptSplitStreamCompatible(enc, t)
}

func TestKeyRing_EncryptSplitStreamWithCompressionCompatible(t *testing.T) {
	enc := func(w io.Writer, meta *PlainMessageMetadata, kr *KeyRing) (*EncryptSplitResult, error) {
		return keyRingTestPublic.EncryptSplitStreamWithCompression(
			w,
			meta,
			kr,
		)
	}
	testKeyRing_EncryptSplitStreamCompatible(enc, t)
}

type keyringEncryptionSplitFunction = func(io.Writer, *PlainMessageMetadata, *KeyRing) (*EncryptSplitResult, error)

func testKeyRing_EncryptSplitStreamCompatible(encrypt keyringEncryptionSplitFunction, t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	var dataPacketBuf bytes.Buffer
	encryptionResult, err := encrypt(
		&dataPacketBuf,
		testMeta,
		keyRingTestPrivate,
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
	decryptedMsg, err := keyRingTestPrivate.Decrypt(
		NewPGPSplitMessage(keyPacket, dataPacket).GetPGPMessage(),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while decrypting split stream with key ring, got:", err)
	}
	decryptedBytes := decryptedMsg.GetBinary()
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

func TestKeyRing_DecryptSplitStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	pgpMessage, err := keyRingTestPublic.Encrypt(
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
	armored, err := pgpMessage.GetArmored()
	if err != nil {
		t.Fatal("Expected no error while armoring ciphertext, got:", err)
	}
	splitMsg, err := NewPGPSplitMessageFromArmored(armored)
	if err != nil {
		t.Fatal("Expected no error while splitting the ciphertext, got:", err)
	}
	keyPacket := splitMsg.KeyPacket
	if err != nil {
		t.Fatal("Expected no error while accessing key packet, got:", err)
	}
	dataPacket := splitMsg.DataPacket
	decryptedReader, err := keyRingTestPrivate.DecryptSplitStream(
		keyPacket,
		bytes.NewReader(dataPacket),
		keyRingTestPublic,
		GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Expected no error while decrypting split stream with key ring, got:", err)
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
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
	decryptedMeta := decryptedReader.GetMetadata()
	if !reflect.DeepEqual(testMeta, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", testMeta, decryptedMeta)
	}
}

func TestKeyRing_SignVerifyDetachedStream(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	signature, err := keyRingTestPrivate.SignDetachedStream(messageReader)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingTestPublic.VerifyDetachedStream(messageReader, signature, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_SignVerifyDetachedStreamWithContext(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	signature, err := keyRingTestPrivate.SignDetachedStreamWithContext(messageReader, NewSigningContext(testContext, true))
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingTestPublic.VerifyDetachedStreamWithContext(messageReader, signature, GetUnixTime(), NewVerificationContext(testContext, true, 0))
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_SignDetachedStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	signature, err := keyRingTestPrivate.SignDetachedStream(messageReader)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	err = keyRingTestPublic.VerifyDetached(NewPlainMessage(messageBytes), signature, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_VerifyDetachedStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	signature, err := keyRingTestPrivate.SignDetached(NewPlainMessage(messageBytes))
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingTestPublic.VerifyDetachedStream(messageReader, signature, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_SignVerifyDetachedEncryptedStream(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	encSignature, err := keyRingTestPrivate.SignDetachedEncryptedStream(messageReader, keyRingTestPublic)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingTestPublic.VerifyDetachedEncryptedStream(messageReader, encSignature, keyRingTestPrivate, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_SignDetachedEncryptedStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	encSignature, err := keyRingTestPrivate.SignDetachedEncryptedStream(messageReader, keyRingTestPublic)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	err = keyRingTestPublic.VerifyDetachedEncrypted(NewPlainMessage(messageBytes), encSignature, keyRingTestPrivate, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}

func TestKeyRing_VerifyDetachedEncryptedStreamCompatible(t *testing.T) {
	messageBytes := []byte("Hello World!")
	messageReader := bytes.NewReader(messageBytes)
	encSignature, err := keyRingTestPrivate.SignDetachedEncrypted(NewPlainMessage(messageBytes), keyRingTestPublic)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = messageReader.Seek(0, 0)
	if err != nil {
		t.Fatal("Expected no error while rewinding the message reader, got:", err)
	}
	err = keyRingTestPublic.VerifyDetachedEncryptedStream(messageReader, encSignature, keyRingTestPrivate, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
}
