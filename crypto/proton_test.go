package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardeeDecryption(t *testing.T) {
	pgp.latestServerTime = 1679044110
	defer func() {
		pgp.latestServerTime = testTime
	}()

	forwardeeKey, err := NewKeyFromArmored(readTestFile("key_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	forwardeeKeyRing, err := NewKeyRing(forwardeeKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while reading ciphertext, got:", err)
	}

	plainMessage, err := forwardeeKeyRing.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "Message for Bob", plainMessage.GetString())
}

func TestSymmetricKeys(t *testing.T) {
	pgp.latestServerTime = 1679044110
	defer func() {
		pgp.latestServerTime = testTime
	}()

	symmetricKey, err := NewKeyFromArmored(readTestFile("key_symmetric", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	symmetricKeyRing, err := NewKeyRing(symmetricKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = NewPlainMessage(binData)

	ciphertext, err := symmetricKeyRing.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := symmetricKeyRing.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetBinary(), decrypted.GetBinary())
}
