package crypto

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestMessageEncryptionWithPassword(t *testing.T) {
	var message = "The secret code is... 1, 2, 3, 4, 5"

	// Encrypt data with password
	armor, err := testSymmetricKey.EncryptMessage(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = testWrongSymmetricKey.DecryptMessage(armor)
	assert.NotNil(t, err)
	// Decrypt data with the good password
	text, err := testSymmetricKey.DecryptMessage(armor)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, text)
}

func TestMessageEncryption(t *testing.T) {
	var message = "plain text"

	testPublicKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))
	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	err = testPrivateKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error unlocking privateKey, got:", err)
	}

	armor, err := testPublicKeyRing.EncryptMessage(message, testPrivateKeyRing, false)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	plainText, _, err := testPrivateKeyRing.DecryptMessage(armor, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, plainText)
}
