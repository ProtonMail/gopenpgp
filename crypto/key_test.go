package crypto

import (
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/profile"
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
	clock := NewConstantClock(testTime)
	keyTestRSA, err = generateKey(
		keyTestName,
		keyTestDomain,
		clock,
		profile.RFC4880(),
		constants.StandardSecurity,
		0,
	)
	if err != nil {
		panic("Cannot generate RSA key:" + err.Error())
	}
	keyTestEC, err = generateKey(
		keyTestName,
		keyTestDomain,
		clock,
		profile.GnuPG(),
		constants.StandardSecurity,
		0,
	)
	if err != nil {
		panic("Cannot generate EC key:" + err.Error())
	}
}

func initArmoredKeys() {
	var err error
	lockedRSA, err := testPGP.LockKey(keyTestRSA, keyTestPassphrase)
	if err != nil {
		panic("Cannot lock RSA key:" + err.Error())
	}

	keyTestArmoredRSA, err = lockedRSA.Armor()
	if err != nil {
		panic("Cannot armor protected RSA key:" + err.Error())
	}

	lockedEC, err := testPGP.LockKey(keyTestEC, keyTestPassphrase)
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

	rTest := regexp.MustCompile(`(?s)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$`)
	assert.Regexp(t, rTest, noPasswordRSA)
	assert.Regexp(t, rTest, noPasswordEC)
	assert.Regexp(t, rTest, keyTestArmoredRSA)
	assert.Regexp(t, rTest, keyTestArmoredEC)
}

func TestArmorKeysWithCustomHeader(t *testing.T) {
	comment := "User-defined private key comment"
	version := "User-defined private key version"
	armored, err := keyTestRSA.ArmorWithCustomHeaders(comment, version)
	if err != nil {
		t.Fatal("Could not armor the private key:", err)
	}

	assert.Contains(t, armored, "Comment: "+comment)
	assert.Contains(t, armored, "Version: "+version)
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

	_, err = testPGP.LockKey(publicKey, keyTestPassphrase)
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
	relockedKey, err := testPGP.LockKey(unlockedKey, keyTestPassphrase)
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
	assert.Exactly(t, false, keyTestRSA.IsExpired(testTime))
	assert.Exactly(t, false, keyTestEC.IsExpired(testTime))

	expiredKey, err := NewKeyFromArmored(readTestFile("key_expiredKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor expired key:", err)
	}

	futureKey, err := NewKeyFromArmored(readTestFile("key_futureKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor future key:", err)
	}

	assert.Exactly(t, true, expiredKey.IsExpired(testTime))
	assert.Exactly(t, true, futureKey.IsExpired(testTime))
}

func TestGetPublicKey(t *testing.T) {
	publicKey, err := keyTestRSA.GetPublicKey()
	if err != nil {
		t.Fatal("Expected no error while obtaining public key, got:", err)
	}

	decodedKey, err := NewKey(publicKey)
	if err != nil {
		t.Fatal("Expected no error while creating public key, got:", err)
	}

	privateFingerprint := keyTestRSA.GetFingerprint()
	publicFingerprint := decodedKey.GetFingerprint()

	assert.False(t, decodedKey.IsPrivate())
	assert.True(t, keyTestRSA.IsPrivate())
	assert.Exactly(t, privateFingerprint, publicFingerprint)
}

func TestGetArmoredPublicKey(t *testing.T) {
	privateKey, err := NewKeyFromArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private key, got:", err)
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

	publicKey, err := keyTestRSA.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Expected no error while obtaining armored public key, got:", err)
	}

	decodedKey, err := NewKeyFromArmored(publicKey)
	if err != nil {
		t.Fatal("Expected no error while creating public key from armored, got:", err)
	}

	assert.False(t, decodedKey.IsPrivate())
	assert.True(t, keyTestRSA.IsPrivate())

	privateFingerprint := keyTestRSA.GetFingerprint()
	publicFingerprint := decodedKey.GetFingerprint()

	assert.Exactly(t, privateFingerprint, publicFingerprint)
}

func TestGetArmoredPublicKeyWithCustomHeaders(t *testing.T) {
	comment := "User-defined public key comment"
	version := "User-defined public key version"
	armored, err := keyTestRSA.GetArmoredPublicKeyWithCustomHeaders(comment, version)
	if err != nil {
		t.Fatal("Could not armor the public key:", err)
	}

	assert.Contains(t, armored, "Comment: "+comment)
	assert.Contains(t, armored, "Version: "+version)
}

func TestGetArmoredPublicKeyWithEmptyCustomHeaders(t *testing.T) {
	armored, err := keyTestRSA.GetArmoredPublicKeyWithCustomHeaders("", "")
	if err != nil {
		t.Fatal("Could not armor the public key:", err)
	}

	assert.NotContains(t, armored, "Version")
	assert.NotContains(t, armored, "Comment")
}

func TestGetSHA256FingerprintsV4(t *testing.T) {
	publicKey, err := NewKeyFromArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}

	sha256Fingerprints := publicKey.GetSHA256Fingerprints()

	assert.Len(t, sha256Fingerprints, 2)
	assert.Exactly(t, "d9ac0b857da6d2c8be985b251a9e3db31e7a1d2d832d1f07ebe838a9edce9c24", sha256Fingerprints[0])
	assert.Exactly(t, "203dfba1f8442c17e59214d9cd11985bfc5cc8721bb4a71740dd5507e58a1a0d", sha256Fingerprints[1])
}

func TestGetEntity(t *testing.T) {
	publicKey, err := NewKeyFromArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}
	entity := publicKey.GetEntity()
	selfSig, err := entity.PrimarySelfSignature(time.Unix(testTime, 0))
	if err != nil {
		t.Fatal("Expected no error, got: ", err)
	}
	assert.True(t, selfSig.FlagsValid)
	assert.IsType(t, &openpgp.Entity{}, entity)
}

func TestToPublic(t *testing.T) {
	privateKey, err := NewKeyFromArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}
	assert.True(t, privateKey.IsPrivate())

	publicKey, err := privateKey.ToPublic()
	if err != nil {
		t.Fatal("Cannot make key public:", err)
	}

	assert.False(t, publicKey.IsPrivate())
	assert.True(t, privateKey.IsPrivate())
}

func TestKeyCapabilities(t *testing.T) {
	assert.True(t, keyTestEC.CanVerify(testTime))
	assert.True(t, keyTestEC.CanEncrypt(testTime))
	assert.True(t, keyTestRSA.CanVerify(testTime))
	assert.True(t, keyTestRSA.CanEncrypt(testTime))

	publicKey, err := keyTestEC.ToPublic()
	if err != nil {
		t.Fatal("Cannot make key public:", err)
	}

	assert.True(t, publicKey.CanVerify(testTime))
	assert.True(t, publicKey.CanEncrypt(testTime))
}

const testRevokedKeyCapabilitiesTime = 1632219895

func TestRevokedKeyCapabilities(t *testing.T) {
	revokedKey, err := NewKeyFromArmored(readTestFile("key_revoked", false))
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}

	assert.False(t, revokedKey.CanVerify(testRevokedKeyCapabilitiesTime))
	assert.False(t, revokedKey.CanEncrypt(testRevokedKeyCapabilitiesTime))
	assert.False(t, revokedKey.IsExpired(testRevokedKeyCapabilitiesTime))
	assert.True(t, revokedKey.IsRevoked(testRevokedKeyCapabilitiesTime))
}

func TestUnlockMismatchingKey(t *testing.T) {
	privateKey, err := NewKeyFromArmored(readTestFile("key_mismatching_eddsa_key", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private key, got:", err)
	}

	if _, err = privateKey.Unlock([]byte("123")); err == nil {
		t.Fatalf("Mismatching private key was not detected")
	}
}

func TestKeyCompression(t *testing.T) {
	selfSig, err := keyTestEC.entity.PrimarySelfSignature(time.Time{})
	if err != nil {
		t.Fatal("no error expected, got: ", err)
	}
	assert.Equal(
		t,
		[]uint8{uint8(packet.CompressionNone), uint8(packet.CompressionZLIB)},
		selfSig.PreferredCompression,
	)
}
