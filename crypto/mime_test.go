package crypto

import (
	"github.com/stretchr/testify/assert"
	"github.com/ProtonMail/go-pm-crypto/internal"
	"io/ioutil"
	"strings"
	"testing"
)

// Corresponding key in testdata/mime_privateKey
const privateKeyPassword = "test"

// define call back interface
type Callbacks struct {
	Testing *testing.T
}

func (t *Callbacks) OnBody(body string, mimetype string) {
	assert.Exactly(t.Testing, readTestFile("mime_decryptedBody"), body)
}

func (t Callbacks) OnAttachment(headers string, data []byte) {
	assert.Exactly(t.Testing, 1, data)
}

func (t Callbacks) OnEncryptedHeaders(headers string) {
	assert.Exactly(t.Testing, "", headers)
}

func (t Callbacks) OnVerified(verified int) {
}

func (t Callbacks) OnError(err error) {
	t.Testing.Fatal("Error in decrypting MIME message: ", err)
}

func TestDecrypt(t *testing.T) {
	var pmCrypto = PmCrypto{}
	callbacks := Callbacks{
		Testing: t,
	}

	block, err := internal.Unarmor(readTestFile("mime_publicKey"))
	if err != nil {
		t.Fatal("Cannot unarmor public key: ", err)
	}

	publicKeyUnarmored, _ := ioutil.ReadAll(block.Body)

	block, err = internal.Unarmor(readTestFile("mime_privateKey"))
	if err != nil {
		t.Fatal("Cannot unarmor private key: ", err)
	}

	privateKeyUnarmored, _ := ioutil.ReadAll(block.Body)

	pmCrypto.DecryptMIMEMessage(
		readTestFile("mime_pgpMessage"),
		pmCrypto.BuildKeyRingNoError(publicKeyUnarmored),
		pmCrypto.BuildKeyRingNoError(privateKeyUnarmored),
		privateKeyPassword,
		&callbacks,
		pmCrypto.GetTimeUnix())
}

func TestParse(t *testing.T) {
	var pmCrypto = PmCrypto{}

	body, _, atts, attHeaders, err := pmCrypto.parseMIME(readTestFile("mime_testMessage"), nil)

	if err != nil {
		t.Error("Expected no error while parsing message, got:", err)
	}

	_ = atts
	_ = attHeaders

	bodyData, _ := body.GetBody()
	assert.Exactly(t, strings.Trim(readTestFile("mime_decodedBody"), "\n"), bodyData)
	assert.Exactly(t, readTestFile("mime_decodedBodyHeaders"), body.GetHeaders())
	assert.Exactly(t, 2, len(atts))
}
