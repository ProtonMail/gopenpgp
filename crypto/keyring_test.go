package crypto

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/stretchr/testify/assert"
)

var decodedSymmetricKey, _ = base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")

var testSymmetricKey = &SymmetricKey{
	Key:  decodedSymmetricKey,
	Algo: constants.AES256,
}

var testWrongSymmetricKey = &SymmetricKey{
	Key:  []byte("WrongPass"),
	Algo: constants.AES256,
}

// Corresponding key in testdata/keyring_privateKey
const testMailboxPassword = "apple"

// Corresponding key in testdata/keyring_privateKeyLegacy
// const testMailboxPasswordLegacy = "123"

const testToken = "d79ca194a22810a5363eeddfdef7dfbc327c6229"

var (
	testPrivateKeyRing *KeyRing
	testPublicKeyRing  *KeyRing
)

var testIdentity = &Identity{
	Name:  "UserID",
	Email: "",
}

func init() {
	var err error

	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	if err != nil {
		panic(err)
	}

	testPublicKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))
	if err != nil {
		panic(err)
	}

	err = testPrivateKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		panic(err)
	}
}

func TestKeyRing_Decrypt(t *testing.T) {
	decString, _, err := testPrivateKeyRing.DecryptMessage(readTestFile("keyring_token", false), nil, 0)
	if err != nil {
		t.Fatal("Cannot decrypt token:", err)
	}

	assert.Exactly(t, testToken, decString)
}

func TestKeyRing_Encrypt(t *testing.T) {
	encrypted, err := testPublicKeyRing.EncryptMessage(testToken, testPrivateKeyRing, true)
	if err != nil {
		t.Fatal("Cannot encrypt token:", err)
	}

	// We can't just check if encrypted == testEncryptedToken
	// Decrypt instead
	ss, verified, err := testPrivateKeyRing.DecryptMessage(encrypted, testPrivateKeyRing, pgp.GetTimeUnix())
	if err != nil {
		t.Fatal("Cannot decrypt token:", err)
	}

	assert.Exactly(t, testToken, ss)
	assert.Exactly(t, constants.SIGNATURE_OK, verified)
}

func TestKeyRing_ArmoredPublicKeyString(t *testing.T) {
	s, err := testPrivateKeyRing.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Expected no error while getting armored public key, got:", err)
	}

	// Decode armored keys
	block, err := armor.Decode(strings.NewReader(s))
	if err != nil {
		t.Fatal("Expected no error while decoding armored public key, got:", err)
	}

	expected, err := armor.Decode(strings.NewReader(readTestFile("keyring_publicKey", false)))
	if err != nil {
		t.Fatal("Expected no error while decoding expected armored public key, got:", err)
	}

	assert.Exactly(t, expected.Type, block.Type)

	b, err := ioutil.ReadAll(block.Body)
	if err != nil {
		t.Fatal("Expected no error while reading armored public key body, got:", err)
	}

	eb, err := ioutil.ReadAll(expected.Body)
	if err != nil {
		t.Fatal("Expected no error while reading expected armored public key body, got:", err)
	}

	assert.Exactly(t, eb, b)
}

func TestCheckPassphrase(t *testing.T) {
	encryptedKeyRing, _ := ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	isCorrect := encryptedKeyRing.CheckPassphrase("Wrong password")
	assert.Exactly(t, false, isCorrect)

	isCorrect = encryptedKeyRing.CheckPassphrase(testMailboxPassword)
	assert.Exactly(t, true, isCorrect)
}

func TestIdentities(t *testing.T) {
	identities := testPrivateKeyRing.Identities()
	assert.Len(t, identities, 1)
	assert.Exactly(t, identities[0], testIdentity)
}


func TestFilterExpiredKeys(t *testing.T) {
	expiredKey, _ := ReadArmoredKeyRing(strings.NewReader(readTestFile("key_expiredKey", false)))
	keys := []*KeyRing {testPrivateKeyRing, expiredKey}
	unexpired, err := FilterExpiredKeys(keys)

	if err != nil {
		t.Fatal("Expected no error while filtering expired keyrings, got:", err)
	}

	assert.Len(t, unexpired, 1)
	assert.Exactly(t, unexpired[0], testPrivateKeyRing)
}
