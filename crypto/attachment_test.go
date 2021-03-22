package crypto

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// const testAttachmentEncrypted =
// `0ksB0fHC6Duezx/0TqpK/82HSl8+qCY0c2BCuyrSFoj6Dubd93T3//32jVYa624NYvfvxX+UxFKYKJxG09gFsU1IVc87cWvUgmUmgjU=`

var testAttachmentKey, _ = base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")

func TestAttachmentGetKey(t *testing.T) {
	testKeyPacketsDecoded, err := base64.StdEncoding.DecodeString(readTestFile("attachment_keypacket", false))
	if err != nil {
		t.Fatal("Expected no error while decoding base64 KeyPacket, got:", err)
	}

	sessionKey, err := keyRingTestPrivate.DecryptSessionKey(testKeyPacketsDecoded)
	if err != nil {
		t.Fatal("Expected no error while decrypting KeyPacket, got:", err)
	}

	assert.Exactly(t, testAttachmentKey, sessionKey.Key)
}

func TestAttachmentSetKey(t *testing.T) {
	keyPackets, err := keyRingTestPublic.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment key, got:", err)
	}

	sessionKey, err := keyRingTestPrivate.DecryptSessionKey(keyPackets)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	assert.Exactly(t, testSessionKey, sessionKey)
}

func TestAttachmentEncryptDecrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewPlainMessageFromFile([]byte(testAttachmentCleartext), "test.txt", 1602518992)

	encSplit, err := keyRingTestPrivate.EncryptAttachment(message, "")
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	redecData, err := keyRingTestPrivate.DecryptAttachment(encSplit)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, message, redecData)
}

func TestAttachmentEncrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewPlainMessageFromFile([]byte(testAttachmentCleartext), "test.txt", 1602518992)

	encSplit, err := keyRingTestPrivate.EncryptAttachment(message, "")
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	pgpMessage := NewPGPMessage(encSplit.GetBinary())

	redecData, err := keyRingTestPrivate.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, message, redecData)
}

func TestAttachmentDecrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewPlainMessageFromFile([]byte(testAttachmentCleartext), "test.txt", 1602518992)

	encrypted, err := keyRingTestPrivate.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	armored, err := encrypted.GetArmored()
	if err != nil {
		t.Fatal("Expected no error while armoring, got:", err)
	}

	pgpSplitMessage, err := NewPGPSplitMessageFromArmored(armored)
	if err != nil {
		t.Fatal("Expected no error while unarmoring, got:", err)
	}

	redecData, err := keyRingTestPrivate.DecryptAttachment(pgpSplitMessage)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, message, redecData)
}

func TestAttachmentDecryptStatic(t *testing.T) {
	passphrase := []byte("wUMuF/lkDPYWH/0ZqqY8kJKw7YJg6kS")
	keyPacket, err := base64.StdEncoding.DecodeString(readTestFile("att_keypacket", false))
	if err != nil {
		t.Error("Expected no error while decoding key packet, got:" + err.Error())
	}

	dataPacket, err := base64.StdEncoding.DecodeString(readTestFile("att_body", false))
	if err != nil {
		t.Error("Expected no error while decoding data packet, got:" + err.Error())
	}

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

	pgpSplitMessage := NewPGPSplitMessage(keyPacket, dataPacket)
	if err != nil {
		t.Fatal("Expected no error while unarmoring, got:", err)
	}

	dec, err := ukr.DecryptAttachment(pgpSplitMessage)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, []byte("PNG"), dec.GetBinary()[1:4])
}

func TestAttachmentProcessor2(t *testing.T) {
	pgp.latestServerTime = 1615394034
	defer func() { pgp.latestServerTime = testTime }()
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
	ap, err := ukr.NewLowMemoryAttachmentProcessor2(
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
		if err == io.EOF {
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

func TestAttachmentProcessorNotEnoughBuffer(t *testing.T) {
	pgp.latestServerTime = 1615394034
	defer func() { pgp.latestServerTime = testTime }()
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
	ap, err := ukr.NewLowMemoryAttachmentProcessor2(
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
		if err == io.EOF {
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

func TestAttachmentProcessorEmptyBuffer(t *testing.T) {
	pgp.latestServerTime = 1615394034
	defer func() { pgp.latestServerTime = testTime }()
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
	_, err = ukr.NewLowMemoryAttachmentProcessor2(
		len(plaintextBytes),
		"test.txt",
		dataPacket,
	)
	if err == nil {
		t.Error("Expected an error while building the attachment processor with an empty buffer got nil")
	}
}
