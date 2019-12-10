package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/rsa"
)

var testSymmetricKey []byte

// Corresponding key in testdata/keyring_privateKey
var testMailboxPassword = []byte("apple")

// Corresponding key in testdata/keyring_privateKeyLegacy
// const testMailboxPasswordLegacy = [][]byte{ []byte("123") }

var (
	keyRingTestPrivate  *KeyRing
	keyRingTestPublic   *KeyRing
	keyRingTestMultiple *KeyRing
)

var testIdentity = &Identity{
	Name:  "UserID",
	Email: "",
}

func initKeyRings() {
	var err error

	testSymmetricKey, err = RandomToken(32)
	if err != nil {
		panic("Expected no error while generating random token, got:" + err.Error())
	}

	privateKey, err := NewKeyFromArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		panic("Expected no error while unarmoring private key, got:" + err.Error())
	}

	keyRingTestPrivate, err = NewKeyRing(privateKey)
	if err == nil {
		panic("Able to create a keyring with a locked key")
	}

	unlockedKey, err := privateKey.Unlock(testMailboxPassword)
	if err != nil {
		panic("Expected no error while unlocking private key, got:" + err.Error())
	}

	keyRingTestPrivate, err = NewKeyRing(unlockedKey)
	if err != nil {
		panic("Expected no error while building private keyring, got:" + err.Error())
	}

	publicKey, err := NewKeyFromArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		panic("Expected no error while unarmoring public key, got:" + err.Error())
	}

	keyRingTestPublic, err = NewKeyRing(publicKey)
	if err != nil {
		panic("Expected no error while building public keyring, got:" + err.Error())
	}

	keyRingTestMultiple, err = NewKeyRing(nil)
	if err != nil {
		panic("Expected no error while building empty keyring, got:" + err.Error())
	}

	err = keyRingTestMultiple.AddKey(keyTestRSA)
	if err != nil {
		panic("Expected no error while adding RSA key to keyring, got:" + err.Error())
	}

	err = keyRingTestMultiple.AddKey(keyTestEC)
	if err != nil {
		panic("Expected no error while adding EC key to keyring, got:" + err.Error())
	}

	err = keyRingTestMultiple.AddKey(unlockedKey)
	if err != nil {
		panic("Expected no error while adding unlocked key to keyring, got:" + err.Error())
	}
}

func TestIdentities(t *testing.T) {
	identities := keyRingTestPrivate.GetIdentities()
	assert.Len(t, identities, 1)
	assert.Exactly(t, identities[0], testIdentity)
}

func TestFilterExpiredKeys(t *testing.T) {
	expiredKey, err := NewKeyFromArmored(readTestFile("key_expiredKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor expired key:", err)
	}

	expiredKeyRing, err := NewKeyRing(expiredKey)
	if err != nil {
		t.Fatal("Cannot create keyring with expired key:", err)
	}

	keys := []*KeyRing{keyRingTestPrivate, expiredKeyRing}
	unexpired, err := FilterExpiredKeys(keys)

	if err != nil {
		t.Fatal("Expected no error while filtering expired keyrings, got:", err)
	}

	assert.Len(t, unexpired, 1)
	assert.Exactly(t, unexpired[0].KeyIds(), keyRingTestPrivate.KeyIds())
}

func TestKeyIds(t *testing.T) {
	keyIDs := keyRingTestPrivate.KeyIds()
	var assertKeyIDs = []uint64{4518840640391470884}
	assert.Exactly(t, assertKeyIDs, keyIDs)
}

func TestMultipleKeyRing(t *testing.T) {
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))
	assert.Exactly(t, 3, keyRingTestMultiple.CountEntities())
	assert.Exactly(t, 3, keyRingTestMultiple.CountDecryptionEntities())

	assert.Exactly(t, 3, len(keyRingTestMultiple.GetKeys()))

	testKey, err := keyRingTestMultiple.GetKey(1)
	if err != nil {
		t.Fatal("Expected no error while extracting key, got:", err)
	}
	assert.Exactly(t, keyTestEC, testKey)

	_, err = keyRingTestMultiple.GetKey(3)
	assert.NotNil(t, err)

	singleKeyRing, err := keyRingTestMultiple.FirstKey()
	if err != nil {
		t.Fatal("Expected no error while filtering the first key, got:", err)
	}
	assert.Exactly(t, 1, len(singleKeyRing.entities))
	assert.Exactly(t, 1, singleKeyRing.CountEntities())
	assert.Exactly(t, 1, singleKeyRing.CountDecryptionEntities())
}

func TestClearPrivateKey(t *testing.T) {
	keyRingCopy, err := keyRingTestMultiple.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}

	for _, key := range keyRingCopy.GetKeys() {
		assert.Nil(t, clearPrivateKey(key.entity.PrivateKey.PrivateKey))
	}

	keys := keyRingCopy.GetKeys()
	assertRSACleared(t, keys[0].entity.PrivateKey.PrivateKey.(*rsa.PrivateKey))
	assertEdDSACleared(t, keys[1].entity.PrivateKey.PrivateKey.(ed25519.PrivateKey))
	assertRSACleared(t, keys[2].entity.PrivateKey.PrivateKey.(*rsa.PrivateKey))
}

func TestClearPrivateWithSubkeys(t *testing.T) {
	keyRingCopy, err := keyRingTestMultiple.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}

	for _, key := range keyRingCopy.GetKeys() {
		assert.Exactly(t, 2, key.clearPrivateWithSubkeys())
	}

	keys := keyRingCopy.GetKeys()
	assertRSACleared(t, keys[0].entity.PrivateKey.PrivateKey.(*rsa.PrivateKey))
	assertRSACleared(t, keys[0].entity.Subkeys[0].PrivateKey.PrivateKey.(*rsa.PrivateKey))

	assertEdDSACleared(t, keys[1].entity.PrivateKey.PrivateKey.(ed25519.PrivateKey))
	assertECDHCleared(t, keys[1].entity.Subkeys[0].PrivateKey.PrivateKey.(*ecdh.PrivateKey))

	assertRSACleared(t, keys[2].entity.PrivateKey.PrivateKey.(*rsa.PrivateKey))
	assertRSACleared(t, keys[2].entity.Subkeys[0].PrivateKey.PrivateKey.(*rsa.PrivateKey))
}

func TestClearPrivateParams(t *testing.T) {
	keyRingCopy, err := keyRingTestMultiple.Copy()
	if err != nil {
		t.Fatal("Expected no error while copying keyring, got:", err)
	}

	for _, key := range keyRingCopy.GetKeys() {
		assert.True(t, key.IsPrivate())
		assert.True(t, key.ClearPrivateParams())
		assert.False(t, key.IsPrivate())
		assert.Nil(t, key.entity.PrivateKey)
		assert.Nil(t, key.entity.Subkeys[0].PrivateKey)
		assert.False(t, key.ClearPrivateParams())
	}
}
