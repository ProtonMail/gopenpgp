package crypto

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const signedPlainText = "Signed message"
const testTime = 1557754627 // 2019-05-13T13:37:07+00:00

var signingKeyRing *KeyRing
var signature, signatureBin string

func TestSignTextDetached(t *testing.T) {
	signingKeyRing, err := ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	if err != nil {
		t.Fatal("Cannot read private key:", err)
	}

	signature, err = signingKeyRing.SignTextDetached(signedPlainText, "", true)
	assert.EqualError(t, err, "gopenpgp: cannot sign message, unable to unlock signer key")

	// Password defined in keyring_test
	signature, err = signingKeyRing.SignTextDetached(signedPlainText, testMailboxPassword, true)
	if err != nil {
		t.Fatal("Cannot generate signature with encrypted key:", err)
	}

	// Reset keyring to locked state
	signingKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	// Password defined in keyring_test
	err = signingKeyRing.Unlock([]byte(testMailboxPassword))
	if err != nil {
		t.Fatal("Cannot decrypt private key:", err)
	}

	signatureDec, err := signingKeyRing.SignTextDetached(signedPlainText, "", true)
	if err != nil {
		t.Fatal("Cannot generate signature with decrypted key:", err)
	}

	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")
	assert.Regexp(t, rTest, signature)
	assert.Exactly(t, signatureDec, signature)
}

func TestSignBinDetached(t *testing.T) {
	var err error

	// Reset keyring to locked state
	signingKeyRing, _ = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	signatureBin, err = signingKeyRing.SignBinDetached([]byte(signedPlainText), "")
	assert.EqualError(t, err, "gopenpgp: cannot sign message, unable to unlock signer key")

	// Password defined in keyring_test
	signatureBin, err = signingKeyRing.SignBinDetached([]byte(signedPlainText), testMailboxPassword)
	if err != nil {
		t.Fatal("Cannot generate signature with encrypted key:", err)
	}

	rTest := regexp.MustCompile("(?s)^-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")
	assert.Regexp(t, rTest, signatureBin)
}

func TestVerifyTextDetachedSig(t *testing.T) {
	verified, err := signingKeyRing.VerifyTextDetachedSig(signature, signedPlainText, testTime, true)
	if err != nil {
		t.Fatal("Cannot verify plaintext signature:", err)
	}

	assert.Exactly(t, true, verified)
}

func TestVerifyTextDetachedSigWrong(t *testing.T) {
	verified, err := signingKeyRing.VerifyTextDetachedSig(signature, "wrong text", testTime, true)

	assert.EqualError(t, err, "gopenpgp: signer is empty")
	assert.Exactly(t, false, verified)
}

func TestVerifyBinDetachedSig(t *testing.T) {
	verified, err := signingKeyRing.VerifyBinDetachedSig(signatureBin, []byte(signedPlainText), testTime)
	if err != nil {
		t.Fatal("Cannot verify binary signature:", err)
	}

	assert.Exactly(t, true, verified)
}
