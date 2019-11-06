package crypto

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/stretchr/testify/assert"
)

const signedPlainText = "Signed message\n"
const testTime = 1557754627 // 2019-05-13T13:37:07+00:00

var signingKeyRing *KeyRing
var textSignature, binSignature *PGPSignature
var message *PlainMessage
var signatureTest = regexp.MustCompile("(?s)^-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")
var signedMessageTest = regexp.MustCompile(
	"(?s)^-----BEGIN PGP SIGNED MESSAGE-----.*-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")

func TestSignTextDetached(t *testing.T) {
	var err error

	signingKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	if err != nil {
		t.Fatal("Cannot read private key:", err)
	}

	// Password defined in keyring_test
	signingKeyRing, err = signingKeyRing.Unlock(testMailboxPassword)
	if err != nil {
		t.Fatal("Cannot decrypt private key:", err)
	}

	message = NewPlainMessageFromString(signedPlainText)
	textSignature, err = signingKeyRing.SignDetached(message)
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err := textSignature.GetArmored()
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	assert.Regexp(t, signatureTest, armoredSignature)
}

func TestVerifyTextDetachedSig(t *testing.T) {
	verificationError := signingKeyRing.VerifyDetached(message, textSignature, testTime)
	if verificationError != nil {
		t.Fatal("Cannot verify plaintext signature:", err)
	}
}

func TestVerifyTextDetachedSigWrong(t *testing.T) {
	fakeMessage := NewPlainMessageFromString("wrong text")
	verificationError := signingKeyRing.VerifyDetached(fakeMessage, textSignature, testTime)

	assert.EqualError(t, verificationError, "Signature Verification Error: Invalid signature")

	err, _ := verificationError.(SignatureVerificationError)
	assert.Exactly(t, constants.SIGNATURE_FAILED, err.Status)
}

func TestSignBinDetached(t *testing.T) {
	var err error

	binSignature, err = signingKeyRing.SignDetached(NewPlainMessage([]byte(signedPlainText)))
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err := binSignature.GetArmored()
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	assert.Regexp(t, signatureTest, armoredSignature)
}

func TestVerifyBinDetachedSig(t *testing.T) {
	verificationError := signingKeyRing.VerifyDetached(message, binSignature, testTime)
	if verificationError != nil {
		t.Fatal("Cannot verify binary signature:", err)
	}
}
