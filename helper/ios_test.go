package helper

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/crypto"
	"github.com/stretchr/testify/assert"
)

func TestIOSSignedMessageDecryption(t *testing.T) {
	testPrivateKeyRing, _ := crypto.BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	testPublicKeyRing, _ := crypto.BuildKeyRingArmored(readTestFile("mime_publicKey", false))

	// Password defined in base_test
	err := testPrivateKeyRing.Unlock(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error unlocking privateKey, got:", err)
	}

	pgpMessage, err := crypto.NewPGPMessageFromArmored(readTestFile("message_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decrypted, err := DecryptExplicitVerify(pgpMessage, testPrivateKeyRing, testPublicKeyRing, crypto.GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, constants.SIGNATURE_NO_VERIFIER, decrypted.SignatureVerificationError.Status)
	assert.Exactly(t, readTestFile("message_plaintext", true), decrypted.Message.GetString())

	testPublicKeyRing, _ = crypto.BuildKeyRingArmored(readTestFile("keyring_publicKey", false))

	pgpMessage, err = testPublicKeyRing.Encrypt(decrypted.Message, testPrivateKeyRing)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err = DecryptExplicitVerify(pgpMessage, testPrivateKeyRing, testPublicKeyRing, crypto.GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Nil(t, decrypted.SignatureVerificationError)
	assert.Exactly(t, readTestFile("message_plaintext", true), decrypted.Message.GetString())

	decrypted, err = DecryptExplicitVerify(pgpMessage, testPublicKeyRing, testPublicKeyRing, crypto.GetUnixTime())
	assert.NotNil(t, err)
	assert.Nil(t, decrypted)
}
