package helper

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/stretchr/testify/assert"
)

func TestIOSSignedMessageDecryption(t *testing.T) {
	privateKey, _ := crypto.NewKeyFromArmored(readTestFile("keyring_privateKey", false))
	// Password defined in base_test
	privateKey, err := privateKey.Unlock(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error unlocking privateKey, got:", err)
	}
	testPrivateKeyRing, _ := crypto.NewKeyRing(privateKey)

	publicKey, _ := crypto.NewKeyFromArmored(readTestFile("mime_publicKey", false))
	testPublicKeyRing, _ := crypto.NewKeyRing(publicKey)

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

	publicKey, _ = crypto.NewKeyFromArmored(readTestFile("keyring_publicKey", false))
	testPublicKeyRing, _ = crypto.NewKeyRing(publicKey)

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
