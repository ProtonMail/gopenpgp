package pmcrypto

import (
	"net/mail"
	"strings"
	"net/textproto"
	"io/ioutil"
	"bytes"
	"mimeparser"
)

func parseMIME(mimeBody string) (body *mimeparser.BodyCollector, atts, attHeaders []string, err error) {

	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return
	}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)

	printAccepter := mimeparser.NewMIMEPrinter()
	bodyCollector := mimeparser.NewBodyCollector(printAccepter)
	attachmentsCollector := mimeparser.NewAttachmentsCollector(bodyCollector)
	err = mimeparser.VisitAll(bytes.NewReader(mmBodyData), h, attachmentsCollector)

	body = bodyCollector
	atts = attachmentsCollector.GetAttachments()
	attHeaders = attachmentsCollector.GetAttHeaders()

	return
}



// define call back interface
type MIMECallbacks interface {
	onBody(body string, mimetype string)
	onAttachment(headers string, data []byte)
	// Encrypted headers can be an attachment and thus be placed at the end of the mime structure
	onEncryptedHeaders(headers string)
}

func (o *OpenPGP) decryptMIMEMessage(encryptedText string, verifierKey string, privateKeys []byte,
		passphrase string, callbacks MIMECallbacks, verifyTime int64) (verifier int, err error) {
	decsignverify, error := o.DecryptMessageVerifyPrivbinkeys(encryptedText, verifierKey, privateKeys, passphrase, verifyTime)
	if (error != nil) {
		return 0, error
	}

	body, attachments, attachmentHeaders, error := parseMIME(decsignverify.Plaintext
	if (error != nil) {
		return 0, error
	})
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.onBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.onAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.onEncryptedHeaders("")

	// Todo verify the signature included in the attachment

	return verifier, nil
}