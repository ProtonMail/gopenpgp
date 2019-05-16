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
var textMessage *CleartextMessage
var binMessage *BinaryMessage
var signatureTest = regexp.MustCompile("(?s)^-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")

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

	textMessage, textSignature, err = signingKeyRing.SignMessage(NewCleartextMessage(signedPlainText), true)
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armored, err :=  textSignature.GetArmored()
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	assert.Regexp(t, signatureTest, armored)
}

func TestSignBinDetached(t *testing.T) {
	var err error

	binMessage, binSignature, err = signingKeyRing.Sign(NewBinaryMessage([]byte(signedPlainText)))
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armored, err :=  binSignature.GetArmored()
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	assert.Regexp(t, signatureTest, armored)
}

func TestVerifyTextDetachedSig(t *testing.T) {
	signedMessage, err := signingKeyRing.VerifyMessage(textMessage, textSignature, testTime)
	if err != nil {
		t.Fatal("Cannot verify plaintext signature:", err)
	}

	assert.Exactly(t, constants.SIGNATURE_OK, signedMessage.GetVerification())
}

func TestVerifyTextDetachedSigWrong(t *testing.T) {
	signedMessage, err := signingKeyRing.VerifyMessage(NewCleartextMessage("wrong text"), textSignature, testTime)

	assert.EqualError(t, err, "gopenpgp: signer is empty")
	assert.Exactly(t, constants.SIGNATURE_FAILED, signedMessage.GetVerification())
}

func TestVerifyBinDetachedSig(t *testing.T) {
	signedMessage, err := signingKeyRing.Verify(binMessage, binSignature, testTime)
	if err != nil {
		t.Fatal("Cannot verify binary signature:", err)
	}

	assert.Exactly(t, constants.SIGNATURE_OK, signedMessage.GetVerification())
}
