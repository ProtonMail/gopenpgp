package crypto

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestMessageEncryptionWithPassword(t *testing.T) {
	var pmCrypto = PmCrypto{}

	const password = "my secret password"

	// Encrypt data with password
	armor, err := pmCrypto.EncryptMessageWithPassword("my message", password)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	text, err := pmCrypto.DecryptMessageWithPassword(armor, "wrong password")
	assert.NotNil(t, err)
	// Decrypt data with the good password
	text, err = pmCrypto.DecryptMessageWithPassword(armor, password)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, "my message", text)
}

func TestMessageEncryption(t *testing.T) {
	var pmCrypto = PmCrypto{}
	var (
		message = "plain text"
	)

	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey")))
	testPrivateKeyRing.Unlock([]byte(testMailboxPassword))
	testPublicKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey")))

	armor, err := pmCrypto.EncryptMessage(message, testPublicKeyRing, testPrivateKeyRing, testMailboxPassword, false)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	plainText, err := pmCrypto.DecryptMessage(armor, testPrivateKeyRing, testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, plainText)
}
