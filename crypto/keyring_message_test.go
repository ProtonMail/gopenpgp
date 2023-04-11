package crypto

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAEADKeyRingDecryption(t *testing.T) {
	pgpMessageData, err := ioutil.ReadFile("testdata/gpg2.3-aead-pgp-message.pgp")
	if err != nil {
		t.Fatal("Expected no error when reading message data, got:", err)
	}
	pgpMessage := NewPGPMessage(pgpMessageData)

	aeadKey, err := NewKeyFromArmored(readTestFile("gpg2.3-aead-test-key.asc", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring key, got:", err)
	}

	aeadKeyUnlocked, err := aeadKey.Unlock([]byte("test"))
	if err != nil {
		t.Fatal("Expected no error when unlocking, got:", err)
	}
	kR, err := NewKeyRing(aeadKeyUnlocked)
	if err != nil {
		t.Fatal("Expected no error when creating the keyring, got:", err)
	}
	defer kR.ClearPrivateParams()

	decrypted, err := kR.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, "hello world\n", decrypted.GetString())
}

func TestTextMessageEncryptionWithSignatureAndContext(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")
	var testContext = "test-context"

	ciphertext, err := keyRingTestPublic.EncryptWithContext(message, keyRingTestPrivate, NewSigningContext(testContext, true))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := keyRingTestPrivate.DecryptWithContext(
		ciphertext,
		keyRingTestPublic,
		GetUnixTime(),
		NewVerificationContext(testContext, true, 0),
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestTextMessageEncryptionWithSignatureAndContextAndCompression(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")
	var testContext = "test-context"

	ciphertext, err := keyRingTestPublic.EncryptWithContextAndCompression(message, keyRingTestPrivate, NewSigningContext(testContext, true))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := keyRingTestPrivate.DecryptWithContext(
		ciphertext,
		keyRingTestPublic,
		GetUnixTime(),
		NewVerificationContext(testContext, true, 0),
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}
