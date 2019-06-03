package crypto

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.org/x/crypto/rsa"
)

const name = "Richard M. Stallman"
const domain = "rms@protonmail.ch"

var passphrase = "I love GNU"
var rsaKey, ecKey, rsaPublicKey, ecPublicKey string

var (
	rsaPrivateKeyRing *KeyRing
	ecPrivateKeyRing  *KeyRing
	rsaPublicKeyRing  *KeyRing
	ecPublicKeyRing   *KeyRing
)

func TestGenerateKeys(t *testing.T) {
	rsaKey, err = pgp.GenerateKey(name, domain, passphrase, "rsa", 1024)
	if err != nil {
		t.Fatal("Cannot generate RSA key:", err)
	}

	ecKey, err = pgp.GenerateKey(name, domain, passphrase, "x25519", 256)
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

	err = rsaPrivateKeyRing.UnlockWithPassphrase(passphrase)
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

	err = ecPrivateKeyRing.UnlockWithPassphrase(passphrase)
	if err != nil {
		t.Fatal("Cannot decrypt EC key:", err)
	}
}

func TestUpdatePrivateKeysPassphrase(t *testing.T) {
	newPassphrase := "I like GNU"
	rsaKey, err = pgp.UpdatePrivateKeyPassphrase(rsaKey, passphrase, newPassphrase)
	if err != nil {
		t.Fatal("Error in changing RSA key's passphrase:", err)
	}

	ecKey, err = pgp.UpdatePrivateKeyPassphrase(ecKey, passphrase, newPassphrase)
	if err != nil {
		t.Fatal("Error in changing EC key's passphrase:", err)
	}

	passphrase = newPassphrase
}

func ExamplePrintFingerprints() {
	_, _ = pgp.PrintFingerprints(readTestFile("keyring_publicKey", false))
	// Output:
	// SubKey:37e4bcf09b36e34012d10c0247dc67b5cb8267f6
	// PrimaryKey:6e8ba229b0cccaf6962f97953eb6259edf21df24
}

func TestIsArmoredKeyExpired(t *testing.T) {
	rsaRes, err := pgp.IsArmoredKeyExpired(rsaPublicKey)
	if err != nil {
		t.Fatal("Error in checking expiration of RSA key:", err)
	}

	ecRes, err := pgp.IsArmoredKeyExpired(ecPublicKey)
	if err != nil {
		t.Fatal("Error in checking expiration of EC key:", err)
	}

	assert.Exactly(t, false, rsaRes)
	assert.Exactly(t, false, ecRes)

	pgp.UpdateTime(1557754627) // 2019-05-13T13:37:07+00:00

	expRes, expErr := pgp.IsArmoredKeyExpired(readTestFile("key_expiredKey", false))
	futureRes, futureErr := pgp.IsArmoredKeyExpired(readTestFile("key_futureKey", false))

	assert.Exactly(t, true, expRes)
	assert.Exactly(t, true, futureRes)
	assert.EqualError(t, expErr, "keys expired")
	assert.EqualError(t, futureErr, "keys expired")
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

	staticRsaKey, err := pgp.GenerateRSAKeyWithPrimes(name, domain, passphrase, 1024, prime1, prime2, prime3, prime4)
	if err != nil {
		t.Fatal("Cannot generate RSA key:", err)
	}
	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$")
	assert.Regexp(t, rTest, staticRsaKey)

	staticRsaKeyRing, err := ReadArmoredKeyRing(strings.NewReader(staticRsaKey))
	if err != nil {
		t.Fatal("Cannot read RSA key:", err)
	}

	err = staticRsaKeyRing.UnlockWithPassphrase(passphrase)
	if err != nil {
		t.Fatal("Cannot decrypt RSA key:", err)
	}

	pk := staticRsaKeyRing.GetEntities()[0].PrivateKey.PrivateKey.(*rsa.PrivateKey)
	assert.Exactly(t, prime1, pk.Primes[1].Bytes())
	assert.Exactly(t, prime2, pk.Primes[0].Bytes())
}
