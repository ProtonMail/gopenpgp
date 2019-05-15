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
		t.Fatal("Expected no error while generating random token, got:", err)
	}

	assert.Len(t, testRandomToken, 32)
}

func TestRandomTokenWith(t *testing.T) {
	token, err := pgp.RandomTokenWith(40)
	if err != nil {
		t.Fatal("Expected no error while generating random token, got:", err)
	}

	assert.Len(t, token, 40)
}

func TestAsymmetricKeyPacket(t *testing.T) {
	symmetricKey := &SymmetricKey{
		Key:	testRandomToken,
		Algo: constants.AES256,
	}

	privateKeyRing, _ := ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	publicKey, _ := testPrivateKeyRing.GetArmoredPublicKey()

	keyPacket, err := pgp.KeyPacketWithPublicKey(symmetricKey, publicKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	// Password defined in keyring_test
	outputSymmetricKey, err := pgp.GetSessionFromKeyPacket(keyPacket, privateKeyRing, testMailboxPassword)
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

	keyPacket, err := pgp.SymmetricKeyPacketWithPassword(symmetricKey, password)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	_, err = pgp.GetSessionFromSymmetricPacket(keyPacket, "Wrong password")
	assert.EqualError(t, err, "password incorrect")

	outputSymmetricKey, err := pgp.GetSessionFromSymmetricPacket(keyPacket, password)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, symmetricKey, outputSymmetricKey)
}
