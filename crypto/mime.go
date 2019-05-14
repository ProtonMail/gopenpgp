package crypto

import (
	"bytes"
	"io/ioutil"
	"net/mail"
	"net/textproto"
	"strings"

	pmmime "github.com/ProtonMail/go-mime"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func (pm PmCrypto) parseMIME(
	mimeBody string, verifierKey *KeyRing,
) (*pmmime.BodyCollector, int, []string, []string, error) {
	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return nil, 0, nil, nil, err
	}
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pm.getTimeGenerator()}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	printAccepter := pmmime.NewMIMEPrinter()
	bodyCollector := pmmime.NewBodyCollector(printAccepter)
	attachmentsCollector := pmmime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := pmmime.NewMimeVisitor(attachmentsCollector)

	var pgpKering openpgp.KeyRing
	if verifierKey != nil {
		pgpKering = verifierKey.entities
	}

	signatureCollector := newSignatureCollector(mimeVisitor, pgpKering, config)

	err = pmmime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)

	verified := signatureCollector.verified
	body := bodyCollector
	atts := attachmentsCollector.GetAttachments()
	attHeaders := attachmentsCollector.GetAttHeaders()

	return body, verified, atts, attHeaders, err
}

// MIMECallbacks defines a call back methods to process MIME message
type MIMECallbacks interface {
	OnBody(body string, mimetype string)
	OnAttachment(headers string, data []byte)
	// Encrypted headers can be an attachment and thus be placed at the end of the mime structure
	OnEncryptedHeaders(headers string)
	OnVerified(verified int)
	OnError(err error)
}

// DecryptMIMEMessage decrypts a MIME message
func (pm *PmCrypto) DecryptMIMEMessage(
	encryptedText string, verifierKey, privateKeyRing *KeyRing,
	passphrase string, callbacks MIMECallbacks, verifyTime int64,
) {
	decsignverify, err := pm.DecryptMessageVerify(encryptedText, verifierKey, privateKeyRing, passphrase, verifyTime)
	if err != nil {
		callbacks.OnError(err)
		return
	}

	body, verified, attachments, attachmentHeaders, err := pm.parseMIME(decsignverify.Plaintext, verifierKey)
	if err != nil {
		callbacks.OnError(err)
		return
	}
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.OnBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.OnAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.OnEncryptedHeaders("")
	if decsignverify.Verify == notSigned {
		callbacks.OnVerified(verified)
	} else {
		callbacks.OnVerified(decsignverify.Verify)
	}
}
