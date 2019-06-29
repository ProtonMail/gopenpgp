package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

// const testAttachmentEncrypted =
// `0ksB0fHC6Duezx/0TqpK/82HSl8+qCY0c2BCuyrSFoj6Dubd93T3//32jVYa624NYvfvxX+UxFKYKJxG09gFsU1IVc87cWvUgmUmgjU=`

func TestAttachmentGetKey(t *testing.T) {
	testKeyPacketsDecoded, err := base64.StdEncoding.DecodeString(readTestFile("attachment_keypacket", false))
	if err != nil {
		t.Fatal("Expected no error while decoding base64 KeyPacket, got:", err)
	}

	symmetricKey, err := testPrivateKeyRing.DecryptSessionKey(testKeyPacketsDecoded)
	if err != nil {
		t.Fatal("Expected no error while decrypting KeyPacket, got:", err)
	}

	assert.Exactly(t, testSymmetricKey, symmetricKey)
}

func TestAttachmentSetKey(t *testing.T) {
	keyPackets, err := testPublicKeyRing.EncryptSessionKey(testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment key, got:", err)
	}

	symmetricKey, err := testPrivateKeyRing.DecryptSessionKey(keyPackets)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	assert.Exactly(t, testSymmetricKey, symmetricKey)
}

func TestAttachmentEncryptDecrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewPlainMessage([]byte(testAttachmentCleartext))

	encSplit, err := testPrivateKeyRing.EncryptAttachment(message, "s.txt")
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	redecData, err := testPrivateKeyRing.DecryptAttachment(encSplit)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, message, redecData)
}

func TestAttachmentEncrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewPlainMessage([]byte(testAttachmentCleartext))

	encSplit, err := testPrivateKeyRing.EncryptAttachment(message, "s.txt")
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	pgpMessage := NewPGPMessage(append(encSplit.GetKeyPacket(), encSplit.GetDataPacket()...))

	redecData, err := testPrivateKeyRing.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, message, redecData)
}

func TestAttachmentDecrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewPlainMessage([]byte(testAttachmentCleartext))

	encrypted, err := testPrivateKeyRing.Encrypt(message, nil)
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

	redecData, err := testPrivateKeyRing.DecryptAttachment(pgpSplitMessage)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, message, redecData)
}
