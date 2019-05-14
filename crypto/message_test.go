package crypto

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestMessageEncryptionWithPassword(t *testing.T) {
	var pgp = GopenPGP{}

	const password = "my secret password"

	// Encrypt data with password
	armor, err := pgp.EncryptMessageWithPassword("my message", password)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = pgp.DecryptMessageWithPassword(armor, "wrong password")
	assert.NotNil(t, err)
	// Decrypt data with the good password
	text, err := pgp.DecryptMessageWithPassword(armor, password)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, "my message", text)
}

func TestMessageEncryption(t *testing.T) {
	var pgp = GopenPGP{}
	var (
		message = "plain text"
	)

	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	_ = testPrivateKeyRing.Unlock([]byte(testMailboxPassword))
	testPublicKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))

	armor, err := pgp.EncryptMessage(message, testPublicKeyRing, testPrivateKeyRing, testMailboxPassword, false)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	plainText, err := pgp.DecryptMessage(armor, testPrivateKeyRing, testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, plainText)
}
