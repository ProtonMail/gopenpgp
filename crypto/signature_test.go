package crypto

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ProtonMail/gopenpgp/constants"
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
	err = signingKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		t.Fatal("Cannot decrypt private key:", err)
	}

	message, err = signingKeyRing.Sign(NewPlainMessageFromString(signedPlainText))
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armored, err :=  message.GetArmored()
	if err != nil {
		t.Fatal("Cannot armor message:", err)
	}

	assert.Regexp(t, signedMessageTest, armored)

	armoredSignature, err :=  message.GetArmoredSignature()
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	assert.Regexp(t, signatureTest, armoredSignature)
}

func TestVerifyTextDetachedSig(t *testing.T) {
	signedMessage, err := signingKeyRing.Verify(message, testTime)
	if err != nil {
		t.Fatal("Cannot verify plaintext signature:", err)
	}

	assert.Exactly(t, constants.SIGNATURE_OK, signedMessage.GetVerification())
}

func TestVerifyTextDetachedSigWrong(t *testing.T) {
	fakeMessage := NewPlainMessageFromString("wrong text")
	fakeMessage.SetSignature(message.GetSignature())
	signedMessage, err := signingKeyRing.Verify(fakeMessage, testTime)

	assert.EqualError(t, err, "gopenpgp: signer is empty")
	assert.Exactly(t, constants.SIGNATURE_FAILED, signedMessage.GetVerification())
}

func TestSignBinDetached(t *testing.T) {
	var err error

	message, err = signingKeyRing.Sign(NewPlainMessage([]byte(signedPlainText)))
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err :=  message.GetArmoredSignature()
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	assert.Regexp(t, signatureTest, armoredSignature)
}

func TestVerifyBinDetachedSig(t *testing.T) {
	signedMessage, err := signingKeyRing.Verify(message, testTime)
	if err != nil {
		t.Fatal("Cannot verify binary signature:", err)
	}

	assert.Exactly(t, constants.SIGNATURE_OK, signedMessage.GetVerification())
}
