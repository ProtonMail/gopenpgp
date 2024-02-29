package crypto

import (
	"bytes"
	"io"
	"testing"

	"github.com/pkg/errors"
)

func TestManualAttachmentProcessor(t *testing.T) {
	defer setFixedTime(testTime)
	setFixedTime(1615394034)

	passphrase := []byte("wUMuF/lkDPYWH/0ZqqY8kJKw7YJg6kS")
	pk, err := NewKeyFromArmored(readTestFile("att_key", false))
	if err != nil {
		t.Error("Expected no error while unarmoring private key, got:" + err.Error())
	}

	uk, err := pk.Unlock(passphrase)
	if err != nil {
		t.Error("Expected no error while unlocking private key, got:" + err.Error())
	}

	defer uk.ClearPrivateParams()

	ukr, err := NewKeyRing(uk)
	if err != nil {
		t.Error("Expected no error while building private keyring, got:" + err.Error())
	}

	inputPlaintext := readTestFile("att_cleartext", false)
	plaintextBytes := []byte(inputPlaintext)
	plaintextReader := bytes.NewReader(plaintextBytes)
	bufferLen := 2 * len(plaintextBytes)
	dataPacket := make([]byte, bufferLen)
	ap, err := ukr.NewManualAttachmentProcessor(
		len(plaintextBytes),
		"test.txt",
		dataPacket,
	)
	if err != nil {
		t.Error("Expected no error while building the attachment processor, got:" + err.Error())
	}
	chunkSize := 1 << 10
	inputBytes := make([]byte, chunkSize)
	var readAllPlaintext = false
	for !readAllPlaintext {
		nBytesRead, err := plaintextReader.Read(inputBytes)
		if errors.Is(err, io.EOF) {
			readAllPlaintext = true
		} else if err != nil {
			t.Error("Expected no error while reading plain data, got:" + err.Error())
		}
		err = ap.Process(inputBytes[:nBytesRead])
		if err != nil {
			t.Error("Expected no error while writing plain data, got:" + err.Error())
		}
	}
	err = ap.Finish()
	if err != nil {
		t.Error("Expected no error while calling finish, got:" + err.Error())
	}
	dataLength := ap.GetDataLength()
	keyPacket := ap.GetKeyPacket()
	if keyPacket == nil {
		t.Error("The key packet was nil")
	}
	if len(keyPacket) == 0 {
		t.Error("The key packet was empty")
	}
	t.Logf("buffer size : %d total written : %d", bufferLen, dataLength)
	if dataLength > bufferLen {
		t.Errorf("Wrote more than was allocated, buffer size : %d total written : %d", bufferLen, dataLength)
	}

	pgpMsg := NewPGPSplitMessage(keyPacket, dataPacket[:dataLength]).GetPGPMessage()
	plainMsg, err := ukr.Decrypt(pgpMsg, nil, 0)
	if err != nil {
		t.Error("Expected no error while decrypting, got:" + err.Error())
	}
	outputPlaintext := string(plainMsg.Data)
	if outputPlaintext != inputPlaintext {
		t.Errorf("Expectedplaintext to be %s got %s", inputPlaintext, outputPlaintext)
	}
}

func TestManualAttachmentProcessorNotEnoughBuffer(t *testing.T) {
	defer setFixedTime(testTime)
	setFixedTime(1615394034)
	passphrase := []byte("wUMuF/lkDPYWH/0ZqqY8kJKw7YJg6kS")
	pk, err := NewKeyFromArmored(readTestFile("att_key", false))
	if err != nil {
		t.Error("Expected no error while unarmoring private key, got:" + err.Error())
	}

	uk, err := pk.Unlock(passphrase)
	if err != nil {
		t.Error("Expected no error while unlocking private key, got:" + err.Error())
	}

	defer uk.ClearPrivateParams()

	ukr, err := NewKeyRing(uk)
	if err != nil {
		t.Error("Expected no error while building private keyring, got:" + err.Error())
	}

	inputPlaintext := readTestFile("att_cleartext", false)
	plaintextBytes := []byte(inputPlaintext)
	plaintextReader := bytes.NewReader(plaintextBytes)
	bufferLen := len(plaintextBytes) / 2
	dataPacket := make([]byte, bufferLen)
	ap, err := ukr.NewManualAttachmentProcessor(
		len(plaintextBytes),
		"test.txt",
		dataPacket,
	)
	if err != nil {
		t.Error("Expected no error while building the attachment processor, got:" + err.Error())
	}
	chunkSize := 1 << 10
	inputBytes := make([]byte, chunkSize)
	var readAllPlaintext = false
	for !readAllPlaintext {
		nBytesRead, err := plaintextReader.Read(inputBytes)
		if errors.Is(err, io.EOF) {
			readAllPlaintext = true
		} else if err != nil {
			t.Error("Expected no error while reading plain data, got:" + err.Error())
		}
		err = ap.Process(inputBytes[:nBytesRead])
		if err != nil {
			t.Error("Expected no error while writing plain data, got:" + err.Error())
		}
	}
	err = ap.Finish()
	if err == nil {
		t.Error("Expected an error while calling finish, got nil")
	}
}

func TestManualAttachmentProcessorEmptyBuffer(t *testing.T) {
	defer setFixedTime(testTime)
	setFixedTime(1615394034)

	passphrase := []byte("wUMuF/lkDPYWH/0ZqqY8kJKw7YJg6kS")
	pk, err := NewKeyFromArmored(readTestFile("att_key", false))
	if err != nil {
		t.Error("Expected no error while unarmoring private key, got:" + err.Error())
	}

	uk, err := pk.Unlock(passphrase)
	if err != nil {
		t.Error("Expected no error while unlocking private key, got:" + err.Error())
	}

	defer uk.ClearPrivateParams()

	ukr, err := NewKeyRing(uk)
	if err != nil {
		t.Error("Expected no error while building private keyring, got:" + err.Error())
	}

	inputPlaintext := readTestFile("att_cleartext", false)
	plaintextBytes := []byte(inputPlaintext)
	bufferLen := 0
	dataPacket := make([]byte, bufferLen)
	_, err = ukr.NewManualAttachmentProcessor(
		len(plaintextBytes),
		"test.txt",
		dataPacket,
	)
	if err == nil {
		t.Error("Expected an error while building the attachment processor with an empty buffer got nil")
	}
}
