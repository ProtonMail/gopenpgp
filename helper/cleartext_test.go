package helper

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const signedPlainText = "Signed message\n"
const testTime = 1557754627 // 2019-05-13T13:37:07+00:00
var signedMessageTest = regexp.MustCompile(
	"(?s)^-----BEGIN PGP SIGNED MESSAGE-----.*-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")

func TestSignClearText(t *testing.T) {
	// Password defined in base_test
	armored, err := SignCleartextMessageArmored(
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,
		signedPlainText,
	)

	if err != nil {
		t.Fatal("Cannot armor message:", err)
	}

	assert.Regexp(t, signedMessageTest, armored)

	verified, err := VerifyCleartextMessageArmored(
		readTestFile("keyring_publicKey", false),
		armored,
		pgp.GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Cannot verify message:", err)
	}

	assert.Exactly(t, canonicalizeAndTrim(signedPlainText), verified)
}

func TestMessageCanonicalizeAndTrim(t *testing.T) {
	text := "Hi  \ntest!\r\n\n"
	canon := canonicalizeAndTrim(text)
	assert.Exactly(t, "Hi\r\ntest!\r\n\r\n", canon)
}
