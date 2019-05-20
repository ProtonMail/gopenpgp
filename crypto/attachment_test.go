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

	simmetricKey, err := testPrivateKeyRing.DecryptSessionKey(testKeyPacketsDecoded)
	if err != nil {
		t.Fatal("Expected no error while decrypting KeyPacket, got:", err)
	}

	assert.Exactly(t, testSymmetricKey, simmetricKey)
}

func TestAttachmentSetKey(t *testing.T) {
	keyPackets, err := testPublicKeyRing.EncryptSessionKey(testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment key, got:", err)
	}

	simmetricKey, err := testPrivateKeyRing.DecryptSessionKey(keyPackets)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	assert.Exactly(t, testSymmetricKey, simmetricKey)
}

func TestAttachnentEncryptDecrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."
	var message = NewBinaryMessage([]byte(testAttachmentCleartext))

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
