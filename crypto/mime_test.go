package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Corresponding key in testdata/mime_privateKey.
var MIMEKeyPassword = []byte("test")

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

	privateKey, err := NewKeyFromArmored(readTestFile("mime_privateKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor private key:", err)
	}

	privateKey, err = privateKey.Unlock(MIMEKeyPassword)
	if err != nil {
		t.Fatal("Cannot unlock private key:", err)
	}

	privateKeyRing, err := NewKeyRing(privateKey)
	if err != nil {
		t.Fatal("Cannot create private keyring:", err)
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
	body, atts, attHeaders, sigErr, err := parseMIME(readTestFile("mime_testMessage", false), nil)

	if err != nil {
		t.Fatal("Expected no error while parsing message, got:", err)
	}

	if sigErr != nil {
		t.Fatal("Expected no signature verification error while parsing message, got:", sigErr)
	}

	_ = atts
	_ = attHeaders

	bodyData, _ := body.GetBody()
	assert.Exactly(t, readTestFile("mime_decodedBody", true), bodyData)
	assert.Exactly(t, readTestFile("mime_decodedBodyHeaders", false), body.GetHeaders())
	assert.Exactly(t, 2, len(atts))
}

func TestDecryptSync(t *testing.T) {
	privateKey, err := NewKeyFromArmored(readTestFile("mime_privateKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor private key:", err)
	}

	privateKey, err = privateKey.Unlock(MIMEKeyPassword)
	if err != nil {
		t.Fatal("Cannot unlock private key:", err)
	}

	privateKeyRing, err := NewKeyRing(privateKey)
	if err != nil {
		t.Fatal("Cannot create private keyring:", err)
	}

	message, err := NewPGPMessageFromArmored(readTestFile("mime_pgpMessage", false))
	if err != nil {
		t.Fatal("Cannot decode armored message:", err)
	}

	mimeMessage, err := privateKeyRing.DecryptMIMEMessageSync(
		message,
		nil,
		GetUnixTime(),
	)

	if err != nil {
		t.Fatal("Cannot decrypt message:", err)
	}

	assert.Exactly(t, readTestFile("mime_decryptedBody", false), mimeMessage.BodyContent)
	if mimeMessage.SignatureError != nil {
		t.Fatal("Cannot verify message:", mimeMessage.SignatureError)
	}
	assert.Exactly(t, 0, len(mimeMessage.Attachments), "attachments are not empty")
	assert.Exactly(t, 1, len(mimeMessage.Headers), "headers are not empty")
	assert.Exactly(t, "", mimeMessage.Headers[0])
}
