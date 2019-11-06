package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Corresponding key in testdata/mime_privateKey
var privateKeyPassword = [][]byte {[]byte("test")}

// define call back interface
type Callbacks struct {
	Testing *testing.T
}

func (t *Callbacks) OnBody(body string, mimetype string) {
	assert.Exactly(t.Testing, readTestFile("mime_decryptedBody", false), body)
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
	callbacks := Callbacks{
		Testing: t,
	}
	privateKeyRing, _ := BuildKeyRingArmored(readTestFile("mime_privateKey", false))

	privateKeyRing, err = privateKeyRing.Unlock(privateKeyPassword)
	if err != nil {
		t.Fatal("Cannot unlock private key:", err)
	}

	message, err := NewPGPMessageFromArmored(readTestFile("mime_pgpMessage", false))
	if err != nil {
		t.Fatal("Cannot decode armored message:", err)
	}

	privateKeyRing.DecryptMIMEMessage(
		message,
		nil,
		&callbacks,
		GetUnixTime())
}

func TestParse(t *testing.T) {
	body, atts, attHeaders, err := parseMIME(readTestFile("mime_testMessage", false), nil)

	if err != nil {
		t.Error("Expected no error while parsing message, got:", err)
	}

	_ = atts
	_ = attHeaders

	bodyData, _ := body.GetBody()
	assert.Exactly(t, readTestFile("mime_decodedBody", true), bodyData)
	assert.Exactly(t, readTestFile("mime_decodedBodyHeaders", false), body.GetHeaders())
	assert.Exactly(t, 2, len(atts))
}
