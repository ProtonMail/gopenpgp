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
var testMailboxPassword = [][]byte{ []byte("apple") }
var testWrongPassword = [][]byte{ []byte("wrong") }

// Corresponding key in testdata/keyring_privateKeyLegacy
// const testMailboxPasswordLegacy = [][]byte{ []byte("123") }

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

	testPrivateKeyRing, err = BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		panic(err)
	}

	testPublicKeyRing, err = BuildKeyRingArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		panic(err)
	}

	testPrivateKeyRing, err = testPrivateKeyRing.Unlock(testMailboxPassword)
	if err != nil {
		panic(err)
	}
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
	encryptedKeyRing, _ := BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	decryptedKeyRing, err := encryptedKeyRing.Unlock(testMailboxPassword) // Verify that the unlocked keyring is a copy

	isCorrect, err := encryptedKeyRing.CheckPassphrases(testWrongPassword)
	if err != nil {
		t.Fatal("Expected no error while checking wrong passphrase, got:", err)
	}
	assert.Exactly(t, false, isCorrect)

	_, err = decryptedKeyRing.CheckPassphrases(testWrongPassword)
	assert.NotNil(t, err)

	isCorrect, err = encryptedKeyRing.CheckPassphrases(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error while checking correct passphrase, got:", err)
	}
	assert.Exactly(t, true, isCorrect)
}

func TestIdentities(t *testing.T) {
	identities := testPrivateKeyRing.Identities()
	assert.Len(t, identities, 1)
	assert.Exactly(t, identities[0], testIdentity)
}

func TestFilterExpiredKeys(t *testing.T) {
	expiredKey, _ := BuildKeyRingArmored(readTestFile("key_expiredKey", false))
	keys := []*KeyRing{testPrivateKeyRing, expiredKey}
	unexpired, err := FilterExpiredKeys(keys)

	if err != nil {
		t.Fatal("Expected no error while filtering expired keyrings, got:", err)
	}

	assert.Len(t, unexpired, 1)
	assert.Exactly(t, unexpired[0], testPrivateKeyRing)
}

func TestGetPublicKey(t *testing.T) {
	publicKey, err := testPrivateKeyRing.GetPublicKey()
	if err != nil {
		t.Fatal("Expected no error while obtaining public key, got:", err)
	}

	publicKeyRing, err := BuildKeyRing(publicKey)
	if err != nil {
		t.Fatal("Expected no error while creating public key ring, got:", err)
	}

	privateFingerprint, err := testPrivateKeyRing.GetFingerprint()
	if err != nil {
		t.Fatal("Expected no error while extracting private fingerprint, got:", err)
	}

	publicFingerprint, err := publicKeyRing.GetFingerprint()
	if err != nil {
		t.Fatal("Expected no error while extracting public fingerprint, got:", err)
	}

	assert.Exactly(t, privateFingerprint, publicFingerprint)
}

func TestKeyIds(t *testing.T) {
	keyIDs := testPrivateKeyRing.KeyIds()
	var assertKeyIDs = []uint64{4518840640391470884}
	assert.Exactly(t, assertKeyIDs, keyIDs)
}

func TestMutlipleKeyRing(t *testing.T) {
	testPublicKeyRing, _ = BuildKeyRingArmored(readTestFile("keyring_publicKey", false))
	assert.Exactly(t, 1, len(testPublicKeyRing.entities))

	ids := testPublicKeyRing.KeyIds()
	assert.Exactly(t, uint64(0x3eb6259edf21df24), ids[0])

	err = testPublicKeyRing.ReadFrom(strings.NewReader(readTestFile("mime_publicKey", false)), true)
	if err != nil {
		t.Fatal("Expected no error while adding a key to the keyring, got:", err)
	}

	assert.Exactly(t, 2, len(testPublicKeyRing.entities))

	ids = testPublicKeyRing.KeyIds()
	assert.Exactly(t, uint64(0x3eb6259edf21df24), ids[0])
	assert.Exactly(t, uint64(0x374130b32ee1e5ea), ids[1])

	singleKey := testPublicKeyRing.FirstKey()
	assert.Exactly(t, 1, len(singleKey.entities))

	ids = singleKey.KeyIds()
	assert.Exactly(t, uint64(0x3eb6259edf21df24), ids[0])
}
