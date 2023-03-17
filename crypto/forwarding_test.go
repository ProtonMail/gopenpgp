package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardeeDecryption(t *testing.T) {
	//pgp.latestServerTime = 1679044110

	forwardeeKey, err := NewKeyFromArmored(readTestFile("key_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	forwardeeKeyRing, err := NewKeyRing(forwardeeKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	pgpMessage := readTestFile("message_forwardee", false)
	decryptor, err := PGP().Decryption().
		DecryptionKeys(forwardeeKeyRing).
		VerifyTime(1679044110).
		New()
	if err != nil {
		t.Fatal(err)
	}
	plainMessage, err := decryptor.Decrypt([]byte(pgpMessage), Armor)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "Message for Bob", plainMessage.String())
}
