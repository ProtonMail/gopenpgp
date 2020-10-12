package crypto

import (
	"encoding/base64"
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
