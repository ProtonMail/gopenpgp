package crypto

import (
	"bytes"
	"github.com/ProtonMail/go-pm-crypto/armor"
	"github.com/ProtonMail/go-pm-mime"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"io/ioutil"
	"net/mail"
	"net/textproto"
	"strings"
)

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
	// TODO: build was failing on this unused 'str' variable. This code looks like WIP
	//str, err := armor.ArmorKey(verifierKey)
	_, err = armor.ArmorKey(verifierKey)

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

func (pm *PmCrypto) DecryptMIMEMessage(encryptedText string, verifierKey []byte, privateKeyRing *KeyRing,
	passphrase string, callbacks MIMECallbacks, verifyTime int64) {
	decsignverify, err := pm.decryptMessageVerify(encryptedText, verifierKey, privateKeyRing, passphrase, verifyTime)
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
