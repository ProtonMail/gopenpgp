package crypto

import (
	"encoding/base64"
	"strings"
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

	split, err := SeparateKeyAndData(
		testPrivateKeyRing,
		strings.NewReader(string(testKeyPacketsDecoded)),
		len(testKeyPacketsDecoded),
		-1)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	assert.Exactly(t, testSymmetricKey.Key, split.KeyPacket)
}

func TestAttachmentSetKey(t *testing.T) {
	packets, err := testPublicKeyRing.EncryptKey(testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment key, got:", err)
	}

	keyPackets, err := base64.StdEncoding.DecodeString(packets)
	if err != nil {
		t.Fatal("Expected no error while decoding base64 KeyPacket, got:", err)
	}

	split, err := SeparateKeyAndData(testPrivateKeyRing, strings.NewReader(string(keyPackets)), len(keyPackets), -1)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	assert.Exactly(t, testSymmetricKey.Key, split.KeyPacket)
}

func TestAttachnentEncryptDecrypt(t *testing.T) {
	var testAttachmentCleartext = "cc,\ndille."

	encSplit, err := pgp.EncryptAttachment([]byte(testAttachmentCleartext), "s.txt", testPrivateKeyRing)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	redecData, err := pgp.DecryptAttachment(encSplit.KeyPacket, encSplit.DataPacket, testPrivateKeyRing, "")
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	assert.Exactly(t, testAttachmentCleartext, string(redecData))
}
