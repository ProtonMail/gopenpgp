package crypto

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/ProtonMail/go-pm-crypto/constants"
	"github.com/stretchr/testify/assert"
)

const name = "richard.stallman"
const domain = "protonmail.ch"

var passphrase = "I love GNU"
var rsaKey, ecKey, rsaPublicKey, ecPublicKey string

var (
	rsaPrivateKeyRing *KeyRing
	ecPrivateKeyRing  *KeyRing
	rsaPublicKeyRing  *KeyRing
	ecPublicKeyRing   *KeyRing
)

func TestGenerateKeys(t *testing.T) {
	rsaKey, err = pmCrypto.GenerateKey(name, domain, passphrase, "rsa", 1024)
	if err != nil {
		t.Fatal("Cannot generate RSA key:", err)
	}

	ecKey, err = pmCrypto.GenerateKey(name, domain, passphrase, "x25519", 256)
	if err != nil {
		t.Fatal("Cannot generate EC key:", err)
	}

	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$")
	assert.Regexp(t, rTest, rsaKey)
	assert.Regexp(t, rTest, ecKey)
}

func TestGenerateKeyRings(t *testing.T) {
	rsaPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(rsaKey))
	if err != nil {
		t.Fatal("Cannot read RSA key:", err)
	}

	rsaPublicKey, err = rsaPrivateKeyRing.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Cannot extract RSA public key:", err)
	}

	rsaPublicKeyRing, err = ReadArmoredKeyRing(strings.NewReader(rsaPublicKey))
	if err != nil {
		t.Fatal("Cannot read RSA public key:", err)
	}

	err = rsaPrivateKeyRing.Unlock([]byte(passphrase))
	if err != nil {
		t.Fatal("Cannot decrypt RSA key:", err)
	}

	ecPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(ecKey))
	if err != nil {
		t.Fatal("Cannot read EC key:", err)
	}

	ecPublicKey, err = ecPrivateKeyRing.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Cannot extract EC public key:", err)
	}

	ecPublicKeyRing, err = ReadArmoredKeyRing(strings.NewReader(ecPublicKey))
	if err != nil {
		t.Fatal("Cannot read EC public key:", err)
	}

	err = ecPrivateKeyRing.Unlock([]byte(passphrase))
	if err != nil {
		t.Fatal("Cannot decrypt EC key:", err)
	}
}

func TestEncryptDecryptKeys(t *testing.T) {
	var pass, _ = base64.StdEncoding.DecodeString("H2CAwzpdexjxXucVYMERDiAc/td8aGPrr6ZhfMnZlLI=")
	var testSymmetricKey = &SymmetricKey{
		Key:  pass,
		Algo: constants.AES256,
	}

	packet, err := SetKey(rsaPublicKeyRing, testSymmetricKey)
	if err != nil {
		t.Fatal("Cannot encrypt keypacket with RSA keyring", err)
	}
	rsaTestSymmetricKey, err := DecryptAttKey(rsaPrivateKeyRing, packet)
	if err != nil {
		t.Fatal("Cannot decrypt keypacket with RSA keyring", err)
	}
	assert.Exactly(t, testSymmetricKey, rsaTestSymmetricKey)

	packet, err = SetKey(ecPublicKeyRing, testSymmetricKey)
	if err != nil {
		t.Fatal("Cannot encrypt keypacket with EC keyring", err)
	}
	ecTestSymmetricKey, err := DecryptAttKey(ecPrivateKeyRing, packet)
	if err != nil {
		t.Fatal("Cannot decrypt keypacket with EC keyring", err)
	}
	assert.Exactly(t, testSymmetricKey, ecTestSymmetricKey)
}

func TestUpdatePrivateKeysPassphrase(t *testing.T) {
	newPassphrase := "I like GNU"
	rsaKey, err = pmCrypto.UpdatePrivateKeyPassphrase(rsaKey, passphrase, newPassphrase)
	if err != nil {
		t.Fatal("Error in changing RSA key's passphrase:", err)
	}

	ecKey, err = pmCrypto.UpdatePrivateKeyPassphrase(ecKey, passphrase, newPassphrase)
	if err != nil {
		t.Fatal("Error in changing EC key's passphrase:", err)
	}

	passphrase = newPassphrase
}

func ExampleCheckKeys() {
	_, _ = pmCrypto.CheckKey(readTestFile("keyring_publicKey", false))
	// Output:
	// SubKey:37e4bcf09b36e34012d10c0247dc67b5cb8267f6
	// PrimaryKey:6e8ba229b0cccaf6962f97953eb6259edf21df24
}

func TestIsKeyExpired(t *testing.T) {
	rsaRes, err := pmCrypto.IsKeyExpired(rsaPublicKey)
	if err != nil {
		t.Fatal("Error in checking expiration of RSA key:", err)
	}

	ecRes, err := pmCrypto.IsKeyExpired(ecPublicKey)
	if err != nil {
		t.Fatal("Error in checking expiration of EC key:", err)
	}

	assert.Exactly(t, false, rsaRes)
	assert.Exactly(t, false, ecRes)

	pmCrypto.UpdateTime(1557754627) // 2019-05-13T13:37:07+00:00

	expRes, expErr := pmCrypto.IsKeyExpired(readTestFile("key_expiredKey", false))
	futureRes, futureErr := pmCrypto.IsKeyExpired(readTestFile("key_futureKey", false))

	assert.Exactly(t, true, expRes)
	assert.Exactly(t, true, futureRes)
	assert.EqualError(t, expErr, "keys expired")
	assert.EqualError(t, futureErr, "keys expired")
}
