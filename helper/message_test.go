package helper_test

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/stretchr/testify/assert"
)

func TestEncryptPGPMessageToAdditionalKey(t *testing.T) {
	keyA, err := crypto.GenerateKey("A", "a@a.a", "x25519", 0)
	if err != nil {
		t.Fatal("Expected no error when generating key, got:", err)
	}

	keyB, err := crypto.GenerateKey("B", "b@b.b", "x25519", 0)
	if err != nil {
		t.Fatal("Expected no error when generating key, got:", err)
	}

	keyRingA, err := crypto.NewKeyRing(keyA)
	if err != nil {
		t.Fatal("Expected no error when creating keyring, got:", err)
	}
	keyRingB, err := crypto.NewKeyRing(keyB)
	if err != nil {
		t.Fatal("Expected no error when creating keyring, got:", err)
	}

	message := crypto.NewPlainMessageFromString("plain text")
	// Encrypt towards A
	ciphertext, err := keyRingA.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	ciphertextSplit, err := ciphertext.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting message, got:", err)
	}
	// Also encrypt the message towards B
	if err := helper.EncryptPGPMessageToAdditionalKey(ciphertextSplit, keyRingA, keyRingB); err != nil {
		t.Fatal("Expected no error when modifying the message, got:", err)
	}

	// Test decrypt with B
	decrypted, err := keyRingB.Decrypt(
		ciphertextSplit.GetPGPMessage(),
		nil,
		0,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}
