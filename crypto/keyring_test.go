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

func testLockUnlock(t *testing.T, encryptedKeyRing *KeyRing) {
	decryptedKeyRing, err := encryptedKeyRing.Unlock(keyTestPassphrases) // Verify that the unlocked keyring is a copy
	if err != nil {
		t.Fatal("Expected no error while unlocking keyring, got:", err)
	}

	locked := encryptedKeyRing.IsLocked()		// Check keyring is a copy
	assert.Exactly(t, true, locked)

	unlocked := decryptedKeyRing.IsUnlocked()	// Check successful unlocking
	assert.Exactly(t, true, unlocked)

	_, err = decryptedKeyRing.Unlock(keyTestPassphrases)
	assert.NotNil(t, err)	// Verify that we can't unlock an unlocked keyring

	relockedKeyring, err := decryptedKeyRing.Lock(keyTestPassphrase)
	if err != nil {
		t.Fatal("Expected no error while locking keyring, got:", err)
	}

	unlocked = decryptedKeyRing.IsUnlocked()	// Check keyring is a copy
	assert.Exactly(t, true, unlocked)

	relocked := relockedKeyring.IsLocked()		// Check successful locking
	assert.Exactly(t, true, relocked)

	_, err = encryptedKeyRing.Lock(keyTestPassphrase)
	assert.NotNil(t, err)	// Verify that we can't lock a locked keyring
}

func TestLockUnlockRSA (t *testing.T) {
	armoredKey, err := GenerateKey(keyTestName, keyTestDomain, keyTestPassphrase, "RSA", 1024)
	if err != nil {
		t.Fatal("Expected no error while generating key, got:", err)
	}

	encryptedKeyRing, err := BuildKeyRingArmored(armoredKey)
	if err != nil {
		t.Fatal("Expected no error while building keyring, got:", err)
	}

	testLockUnlock(t, encryptedKeyRing)
}

func TestLockUnlockECC (t *testing.T) {
	armoredKey, err := GenerateKey(keyTestName, keyTestDomain, keyTestPassphrase, "x25519", 256)
	if err != nil {
		t.Fatal("Expected no error while generating key, got:", err)
	}

	encryptedKeyRing, err := BuildKeyRingArmored(armoredKey)
	if err != nil {
		t.Fatal("Expected no error while building keyring, got:", err)
	}

	testLockUnlock(t, encryptedKeyRing)
}

func TestCheckIntegrity(t *testing.T) {
	encryptedKeyRing, _ := BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	isCorrect, err := encryptedKeyRing.CheckIntegrity(testMailboxPassword)
	if err != nil {
		t.Fatal("Expected no error while checking correct passphrase, got:", err)
	}
	assert.Exactly(t, true, isCorrect)
}

func TestFailCheckIntegrity(t *testing.T) {
	// This test is done with ECC because in an RSA key we would need to replace the primes, but maintaining the moduli,
	// that is a private struct element.
	eck1, _ := GenerateKey(keyTestName, keyTestDomain, keyTestPassphrase, "x25519", 256)
	eck2, _ := GenerateKey(keyTestName, keyTestDomain, keyTestPassphrase, "x25519", 256)

	ekr1, _ := ReadArmoredKeyRing(strings.NewReader(eck1))
	ekr2, _ := ReadArmoredKeyRing(strings.NewReader(eck2))

	kr1, err := ekr1.Unlock(keyTestPassphrases)
	if err != nil {
		t.Fatal("Expected no error while locking keyring ekr1, got:", err)
	}

	kr2, err := ekr2.Unlock(keyTestPassphrases)
	if err != nil {
		t.Fatal("Expected no error while locking keyring ekr2, got:", err)
	}

	kr2.entities[0].PrivateKey.PrivateKey = kr1.entities[0].PrivateKey.PrivateKey // Swap private keys

	kr3, err := kr2.Lock(keyTestPassphrase)
	if err != nil {
		t.Fatal("Expected no error while locking keyring kr3, got:", err)
	}

	isCorrect, err := kr3.CheckPassphrases(keyTestPassphrases)
	if err != nil {
		t.Fatal("Expected no error while checking correct passphrase, got:", err)
	}

	isVerified, err := kr3.CheckIntegrity(keyTestPassphrases)
	if err != nil {
		t.Fatal("Expected no error while checking correct passphrase, got:", err)
	}

	assert.Exactly(t, true, isCorrect)
	assert.Exactly(t, false, isVerified)
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
