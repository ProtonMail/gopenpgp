package crypto

import (
	"github.com/stretchr/testify/assert"
	// "encoding/base64"
	"regexp"
	"testing"
)

const name = "richard.stallman"
const domain = "gnu.org"
const passphrase = "I love GNU"

var rsaKey, ecKey string

func TestGenerateRsaKey(t *testing.T) {
	var pmCrypto = PmCrypto{}
	var err error
	rsaKey, err = pmCrypto.generateKey(name, domain, passphrase, "RSA", 1024, nil, nil, nil, nil)
	if err != nil {
		t.Fatal("Cannot encrypt token:", err)
	}

	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$")
	assert.Regexp(t, rTest, rsaKey)
}

func TestGenerateECKey(t *testing.T) {
	var pmCrypto = PmCrypto{}
	var err error
	ecKey, err = pmCrypto.generateKey(name, domain, passphrase, "x25519", 1024, nil, nil, nil, nil)
	if err != nil {
		t.Fatal("Cannot encrypt token:", err)
	}

	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$")
	assert.Regexp(t, rTest, ecKey)
}
