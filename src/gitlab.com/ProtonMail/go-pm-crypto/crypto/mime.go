package crypto

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


func (pm PmCrypto) parseMIME(mimeBody string, verifierKey []byte) (*pmmime.BodyCollector, int, []string, []string, error) {
	pubKey := bytes.NewReader(verifierKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKey)

	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return nil, 0, nil, nil, err
	}
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pm.getTimeGenerator()}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)

	printAccepter := pmmime.NewMIMEPrinter()
	bodyCollector := pmmime.NewBodyCollector(printAccepter)
	attachmentsCollector := pmmime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := pmmime.NewMimeVisitor(attachmentsCollector)
	signatureCollector := newSignatureCollector(mimeVisitor, pubKeyEntries, config)
	err = pmmime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)

	verified := signatureCollector.verified
	body := bodyCollector
	atts := attachmentsCollector.GetAttachments()
	attHeaders := attachmentsCollector.GetAttHeaders()

	return body, verified, atts, attHeaders, nil
}

// define call back interface
type MIMECallbacks interface {
	OnBody(body string, mimetype string)
	OnAttachment(headers string, data []byte)
	// Encrypted headers can be an attachment and thus be placed at the end of the mime structure
	OnEncryptedHeaders(headers string)
	OnVerified(verified int)
	OnError(err error)
}

func (pm *PmCrypto) DecryptMIMEMessage(encryptedText string, verifierKey []byte, privateKeys []byte,
	passphrase string, callbacks MIMECallbacks, verifyTime int64) {
	decsignverify, err := pm.decryptMessageVerifyAllBin(encryptedText, verifierKey, privateKeys, passphrase, verifyTime)
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