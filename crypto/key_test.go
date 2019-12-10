package crypto

import (
	"encoding/base64"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/rsa"

	"github.com/stretchr/testify/assert"
)

const keyTestName = "Max Mustermann"
const keyTestDomain = "max.mustermann@protonmail.ch"

var keyTestPassphrase = []byte("I love GNU")

var (
	keyTestArmoredRSA string
	keyTestArmoredEC  string
	keyTestRSA        *Key
	keyTestEC         *Key
)

func initGenerateKeys() {
	var err error
	keyTestRSA, err = GenerateKey(keyTestName, keyTestDomain, "rsa", 1024)
	if err != nil {
		panic("Cannot generate RSA key:" + err.Error())
	}

	keyTestEC, err = GenerateKey(keyTestName, keyTestDomain, "x25519", 256)
	if err != nil {
		panic("Cannot generate EC key:" + err.Error())
	}
}

func initArmoredKeys() {
	var err error
	lockedRSA, err := keyTestRSA.Lock(keyTestPassphrase)
	if err != nil {
		panic("Cannot lock RSA key:" + err.Error())
	}

	keyTestArmoredRSA, err = lockedRSA.Armor()
	if err != nil {
		panic("Cannot armor protected RSA key:" + err.Error())
	}

	lockedEC, err := keyTestEC.Lock(keyTestPassphrase)
	if err != nil {
		panic("Cannot lock EC key:" + err.Error())
	}

	keyTestArmoredEC, err = lockedEC.Armor()
	if err != nil {
		panic("Cannot armor protected EC key:" + err.Error())
	}
}

func TestArmorKeys(t *testing.T) {
	var err error
	noPasswordRSA, err := keyTestRSA.Armor()
	if err != nil {
		t.Fatal("Cannot armor unprotected RSA key:" + err.Error())
	}

	noPasswordEC, err := keyTestEC.Armor()
	if err != nil {
		t.Fatal("Cannot armor unprotected EC key:" + err.Error())
	}

	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$")
	assert.Regexp(t, rTest, noPasswordRSA)
	assert.Regexp(t, rTest, noPasswordEC)
	assert.Regexp(t, rTest, keyTestArmoredRSA)
	assert.Regexp(t, rTest, keyTestArmoredEC)
}

func TestLockUnlockKeys(t *testing.T) {
	testLockUnlockKey(t, keyTestArmoredRSA, keyTestPassphrase)
	testLockUnlockKey(t, keyTestArmoredEC, keyTestPassphrase)
	testLockUnlockKey(t, readTestFile("keyring_privateKey", false), testMailboxPassword)

	publicKey, err := NewKeyFromArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}

	_, err = publicKey.IsLocked()
	if err == nil {
		t.Fatal("Should not be able to check locked on public key:")
	}

	_, err = publicKey.IsUnlocked()
	if err == nil {
		t.Fatal("Should not be able to check unlocked on public key:")
	}

	_, err = publicKey.Unlock(testMailboxPassword)
	if err == nil {
		t.Fatal("Should not be able to unlock public key:")
	}

	_, err = publicKey.Lock(keyTestPassphrase)
	if err == nil {
		t.Fatal("Should not be able to lock public key:")
	}
}

func testLockUnlockKey(t *testing.T, armoredKey string, pass []byte) {
	var err error

	lockedKey, err := NewKeyFromArmored(armoredKey)
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}

	// Check if key is locked
	locked, err := lockedKey.IsLocked()
	if err != nil {
		t.Fatal("Cannot check if key is unlocked:", err)
	}

	if !locked {
		t.Fatal("Key should be fully locked")
	}

	unlockedKey, err := lockedKey.Unlock(pass)
	if err != nil {
		t.Fatal("Cannot unlock key:", err)
	}

	// Check if key was successfully unlocked
	unlocked, err := unlockedKey.IsUnlocked()
	if err != nil {
		t.Fatal("Cannot check if key is unlocked:", err)
	}

	if !unlocked {
		t.Fatal("Key should be fully unlocked")
	}

	// Check if action is performed on copy
	locked, err = lockedKey.IsLocked()
	if err != nil {
		t.Fatal("Cannot check if key is unlocked:", err)
	}

	if !locked {
		t.Fatal("Key should be fully locked")
	}

	// re-lock key
	relockedKey, err := unlockedKey.Lock(keyTestPassphrase)
	if err != nil {
		t.Fatal("Cannot lock key:", err)
	}

	// Check if key was successfully locked
	relocked, err := relockedKey.IsLocked()
	if err != nil {
		t.Fatal("Cannot check if key is unlocked:", err)
	}

	if !relocked {
		t.Fatal("Key should be fully locked")
	}

	// Check if action is performed on copy
	unlocked, err = unlockedKey.IsUnlocked()
	if err != nil {
		t.Fatal("Cannot check if key is unlocked:", err)
	}

	if !unlocked {
		t.Fatal("Key should be fully unlocked")
	}
}

func ExampleKey_PrintFingerprints() {
	keyringKey, _ := NewKeyFromArmored(readTestFile("keyring_publicKey", false))
	keyringKey.PrintFingerprints()
	// Output:
	// SubKey:37e4bcf09b36e34012d10c0247dc67b5cb8267f6
	// PrimaryKey:6e8ba229b0cccaf6962f97953eb6259edf21df24
}

func TestIsExpired(t *testing.T) {
	assert.Exactly(t, false, keyTestRSA.IsExpired())
	assert.Exactly(t, false, keyTestEC.IsExpired())

	expiredKey, err := NewKeyFromArmored(readTestFile("key_expiredKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor expired key:", err)
	}

	futureKey, err := NewKeyFromArmored(readTestFile("key_futureKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor future key:", err)
	}

	assert.Exactly(t, true, expiredKey.IsExpired())
	assert.Exactly(t, true, futureKey.IsExpired())
}

func TestGenerateKeyWithPrimes(t *testing.T) {
	prime1, _ := base64.StdEncoding.DecodeString(
		"/thF8zjjk6fFx/y9NId35NFx8JTA7jvHEl+gI0dp9dIl9trmeZb+ESZ8f7bNXUmTI8j271kyenlrVJiqwqk80Q==")
	prime2, _ := base64.StdEncoding.DecodeString(
		"0HyyG/TShsw7yObD+DDP9Ze39ye1Redljx+KOZ3iNDmuuwwI1/5y44rD/ezAsE7A188NsotMDTSy5xtfHmu0xQ==")
	prime3, _ := base64.StdEncoding.DecodeString(
		"3OyJpAdnQXNjPNzI1u3BWDmPrzWw099E0UfJj5oJJILSbsAg/DDrmrdrIZDt7f24d06HCnTErCNWjvFJ3Kdq4w==")
	prime4, _ := base64.StdEncoding.DecodeString(
		"58UEDXTX29Q9JqvuE3Tn+Qj275CXBnJbA8IVM4d05cPYAZ6H43bPN01pbJqJTJw/cuFxs+8C+HNw3/MGQOExqw==")

	staticRsaKey, err := GenerateRSAKeyWithPrimes(keyTestName, keyTestDomain, 1024, prime1, prime2, prime3, prime4)
	if err != nil {
		t.Fatal("Cannot generate RSA key with primes:", err)
	}

	pk := staticRsaKey.entity.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	assert.Exactly(t, prime1, pk.Primes[0].Bytes())
	assert.Exactly(t, prime2, pk.Primes[1].Bytes())
}

func TestCheckIntegrity(t *testing.T) {
	isVerified, err := keyTestRSA.Check()
	if err != nil {
		t.Fatal("Expected no error while checking correct passphrase, got:", err)
	}

	assert.Exactly(t, true, isVerified)
}

func TestFailCheckIntegrity(t *testing.T) {
	// This test is done with ECC because in an RSA key we would need to replace the primes, but maintaining the moduli,
	// that is a private struct element.
	k1, _ := GenerateKey(keyTestName, keyTestDomain, "x25519", 256)
	k2, _ := GenerateKey(keyTestName, keyTestDomain, "x25519", 256)

	k1.entity.PrivateKey.PrivateKey = k2.entity.PrivateKey.PrivateKey // Swap private keys

	k3, err := k1.Copy()
	if err != nil {
		t.Fatal("Expected no error while locking keyring kr3, got:", err)
	}

	isVerified, err := k3.Check()
	if err != nil {
		t.Fatal("Expected no error while checking correct passphrase, got:", err)
	}

	assert.Exactly(t, false, isVerified)
}

func TestArmorPublicKey(t *testing.T) {
	publicKey, err := keyTestRSA.GetPublicKey()
	if err != nil {
		t.Fatal("Expected no error while obtaining public key, got:", err)
	}

	decodedKey, err := NewKey(publicKey)
	if err != nil {
		t.Fatal("Expected no error while creating public key ring, got:", err)
	}

	privateFingerprint := keyTestRSA.GetFingerprint()
	publicFingerprint := decodedKey.GetFingerprint()

	assert.Exactly(t, privateFingerprint, publicFingerprint)
}

func TestGetArmoredPublicKey(t *testing.T) {
	privateKey, err := NewKeyFromArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		t.Fatal("Expected no error while unarmouring private key, got:", err)
	}

	s, err := privateKey.GetArmoredPublicKey()
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
