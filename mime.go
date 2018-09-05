package pmcrypto

import (
	"proton/pmmime"
	"net/mail"
	"strings"
	"golang.org/x/crypto/openpgp/packet"
	"net/textproto"
	"io/ioutil"
	"bytes"
	"golang.org/x/crypto/openpgp"
)

// ======================== Attachments Collector  ==============
// Collect contents of all attachment parts and return
// them as a string




func (o OpenPGP) parseMIME(mimeBody string, verifierKey []byte) (*pmmime.BodyCollector, int, []string, []string, error) {
	privKey := bytes.NewReader(verifierKey)
	privKeyEntries, err := openpgp.ReadKeyRing(privKey)

	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return nil, 0, nil, nil, err
	}
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: o.getTimeGenerator()}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)

	printAccepter := pmmime.NewMIMEPrinter()
	bodyCollector := pmmime.NewBodyCollector(printAccepter)
	attachmentsCollector := pmmime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := pmmime.NewMimeVisitor(attachmentsCollector)
	signatureCollector := NewSignatureCollector(mimeVisitor, privKeyEntries, config)
	err = pmmime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)

	verified := signatureCollector.verified
	body := bodyCollector
	atts := attachmentsCollector.GetAttachments()
	attHeaders := attachmentsCollector.GetAttHeaders()

	return body, verified, atts, attHeaders, nil
}

// define call back interface
type MIMECallbacks interface {
	onBody(body string, mimetype string)
	onAttachment(headers string, data []byte)
	// Encrypted headers can be an attachment and thus be placed at the end of the mime structure
	onEncryptedHeaders(headers string)
	onVerified(verified int)
	onError(err error)
}

func (o *OpenPGP) decryptMIMEMessage(encryptedText string, verifierKey []byte, privateKeys []byte,
	passphrase string, callbacks MIMECallbacks, verifyTime int64) {
	decsignverify, err := o.decryptMessageVerifyAllBin(encryptedText, verifierKey, privateKeys, passphrase, verifyTime)
	if err != nil {
		callbacks.onError(err)
		return
	}

	body, verified, attachments, attachmentHeaders, err := o.parseMIME(decsignverify.Plaintext, verifierKey)
	if err != nil {
		callbacks.onError(err)
		return
	}
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.onBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.onAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.onEncryptedHeaders("")
	if decsignverify.Verify == notSigned {
		callbacks.onVerified(verified)
	} else {
		callbacks.onVerified(decsignverify.Verify)
	}
}