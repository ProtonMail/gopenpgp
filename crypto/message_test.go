package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ProtonMail/gopenpgp/constants"
)

func TestMessageEncryptionWithPassword(t *testing.T) {
	var message = NewCleartextMessage("The secret code is... 1, 2, 3, 4, 5")

	// Encrypt data with password
	encrypted, err := testSymmetricKey.EncryptMessage(message, true)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = testWrongSymmetricKey.DecryptMessage(encrypted)
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decrypted, err := testSymmetricKey.DecryptMessage(encrypted)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted)
}

func TestMessageEncryption(t *testing.T) {
	var message = NewCleartextMessage("plain text")

	testPublicKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))
	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	err = testPrivateKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error unlocking privateKey, got:", err)
	}

	ciphertext, err := testPublicKeyRing.EncryptMessage(message, testPrivateKeyRing, false)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := testPrivateKeyRing.DecryptMessage(ciphertext, testPublicKeyRing, pgp.GetTimeUnix())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
	assert.Exactly(t, constants.SIGNATURE_OK, decrypted.GetVerification())
}
