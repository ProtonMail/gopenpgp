package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ProtonMail/gopenpgp/constants"
)

var testRandomToken []byte
func TestRandomToken(t *testing.T) {
	var err error
	testRandomToken, err = pgp.RandomToken()
	if err != nil {
		t.Fatal("Expected no error while generating default length random token, got:", err)
	}

	token40, err := pgp.RandomToken(40)
	if err != nil {
		t.Fatal("Expected no error while generating random token, got:", err)
	}

	assert.Len(t, testRandomToken, 32)
	assert.Len(t, token40, 40)
}


func TestAsymmetricKeyPacket(t *testing.T) {
	symmetricKey := &SymmetricKey{
		Key:	testRandomToken,
		Algo: constants.AES256,
	}

	privateKeyRing, _ := ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	_ = privateKeyRing.UnlockWithPassphrase(testMailboxPassword)

	keyPacket, err := privateKeyRing.EncryptSessionKey(symmetricKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	// Password defined in keyring_test
	outputSymmetricKey, err := privateKeyRing.DecryptSessionKey(keyPacket)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, symmetricKey, outputSymmetricKey)
}

func TestSymmetricKeyPacket(t *testing.T) {
	symmetricKey := &SymmetricKey{
		Key:	testRandomToken,
		Algo: constants.AES256,
	}

	password := "I like encryption"

	keyPacket, err := pgp.EncryptSessionKeySymmetric(symmetricKey, password)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	_, err = pgp.DecryptSessionKeySymmetric(keyPacket, "Wrong password")
	assert.EqualError(t, err, "password incorrect")

	outputSymmetricKey, err := pgp.DecryptSessionKeySymmetric(keyPacket, password)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, symmetricKey, outputSymmetricKey)
}
