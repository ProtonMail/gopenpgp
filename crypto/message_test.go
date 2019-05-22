package crypto

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ProtonMail/gopenpgp/constants"
)

func TestTextMessageEncryptionWithPassword(t *testing.T) {
	var message = NewPlainMessageFromString("The secret code is... 1, 2, 3, 4, 5")

	// Encrypt data with password
	encrypted, err := testSymmetricKey.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = testWrongSymmetricKey.Decrypt(encrypted)
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decrypted, err := testSymmetricKey.Decrypt(encrypted)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
	assert.Exactly(t, constants.SIGNATURE_NOT_SIGNED, decrypted.GetVerification())
	assert.Exactly(t, false, decrypted.IsVerified())
}

func TestBinaryMessageEncryptionWithPassword(t *testing.T) {
	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = NewPlainMessage(binData)

	// Encrypt data with password
	encrypted, err := testSymmetricKey.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = testWrongSymmetricKey.Decrypt(encrypted)
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decrypted, err := testSymmetricKey.Decrypt(encrypted)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted)
	assert.Exactly(t, constants.SIGNATURE_NOT_SIGNED, decrypted.GetVerification())
	assert.Exactly(t, false, decrypted.IsVerified())
}

func TestTextMessageEncryption(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")

	testPublicKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))
	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))

	// Password defined in keyring_test
	err = testPrivateKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error unlocking privateKey, got:", err)
	}

	ciphertext, err := testPublicKeyRing.Encrypt(message, testPrivateKeyRing)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := testPrivateKeyRing.Decrypt(ciphertext, testPublicKeyRing, pgp.GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
	assert.Exactly(t, constants.SIGNATURE_OK, decrypted.GetVerification())
	assert.Exactly(t, true, decrypted.IsVerified())
}

func TestBinaryMessageEncryption(t *testing.T) {
	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = NewPlainMessage(binData)

	testPublicKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))
	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))

	// Password defined in keyring_test
	err = testPrivateKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error unlocking privateKey, got:", err)
	}

	ciphertext, err := testPublicKeyRing.Encrypt(message, testPrivateKeyRing)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := testPrivateKeyRing.Decrypt(ciphertext, testPublicKeyRing, pgp.GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetBinary(), decrypted.GetBinary())
	assert.Exactly(t, constants.SIGNATURE_OK, decrypted.GetVerification())
	assert.Exactly(t, true, decrypted.IsVerified())
}
