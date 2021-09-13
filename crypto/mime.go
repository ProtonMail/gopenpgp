package crypto

import (
	"bytes"
	"io/ioutil"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gomime "github.com/ProtonMail/go-mime"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/pkg/errors"
)

// MIMECallbacks defines callback methods to process a MIME message.
type MIMECallbacks interface {
	OnBody(body string, mimetype string)
	OnAttachment(headers string, data []byte)
	// Encrypted headers can be in an attachment and thus be placed at the end of the mime structure.
	OnEncryptedHeaders(headers string)
	OnVerified(verified int)
	OnError(err error)
}

// DecryptMIMEMessage decrypts a MIME message.
func (keyRing *KeyRing) DecryptMIMEMessage(
	message *PGPMessage, verifyKey *KeyRing, callbacks MIMECallbacks, verifyTime int64,
) {
	decryptedMessage, err := keyRing.Decrypt(message, verifyKey, verifyTime)
	if err != nil {
		callbacks.OnError(err)
		return
	}

	body, attachments, attachmentHeaders, sigErr, err := parseMIME(string(decryptedMessage.GetBinary()), verifyKey)
	if err != nil {
		callbacks.OnError(err)
		return
	}
	if sigErr != nil {
		callbacks.OnError(err) // This is wrong and should use OnVerified instead
		return
	}
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.OnBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.OnAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.OnEncryptedHeaders("")
}

type MIMEMessage struct {
	Headers        []string
	BodyMIMEType   string
	BodyContent    string
	Attachments    []*Attachment
	SignatureError *SignatureVerificationError
}

type Attachment struct {
	Header  string
	Content []byte
}

// DecryptMIMEMessageSync decrypts a MIME message.
func (keyRing *KeyRing) DecryptMIMEMessageSync(
	message *PGPMessage, verifyKey *KeyRing, verifyTime int64,
) (*MIMEMessage, error) {
	decryptedMessage, err := keyRing.Decrypt(message, verifyKey, verifyTime)
	var mimeMessage MIMEMessage
	if err != nil {
		castedErr := &SignatureVerificationError{}
		isType := errors.As(err, castedErr)
		if !isType {
			return nil, err
		}
		mimeMessage.SignatureError = castedErr
	}
	body, attachments, attachmentHeaders, sigErr, err := parseMIME(string(decryptedMessage.GetBinary()), verifyKey)
	if err != nil {
		return nil, err
	}
	if mimeMessage.SignatureError != nil &&
		mimeMessage.SignatureError.Status == constants.SIGNATURE_NOT_SIGNED {
		mimeMessage.SignatureError = sigErr
	}
	bodyContent, bodyMimeType := body.GetBody()
	mimeMessage.BodyContent = bodyContent
	mimeMessage.BodyMIMEType = bodyMimeType
	for i := 0; i < len(attachments); i++ {
		mimeMessage.Attachments = append(mimeMessage.Attachments, &Attachment{
			Header:  attachmentHeaders[i],
			Content: []byte(attachments[i]),
		})
	}
	mimeMessage.Headers = []string{""} // TODO, parse headers
	return &mimeMessage, nil
}

// ----- INTERNAL FUNCTIONS -----

func parseMIME(
	mimeBody string, verifierKey *KeyRing,
) (*gomime.BodyCollector, []string, []string, *SignatureVerificationError, error) {
	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "gopenpgp: error in reading message body data")
	}

	printAccepter := gomime.NewMIMEPrinter()
	bodyCollector := gomime.NewBodyCollector(printAccepter)
	attachmentsCollector := gomime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := gomime.NewMimeVisitor(attachmentsCollector)

	var pgpKering openpgp.KeyRing
	if verifierKey != nil {
		pgpKering = verifierKey.entities
	}

	signatureCollector := newSignatureCollector(mimeVisitor, pgpKering, config)

	err = gomime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)
	var signatureError *SignatureVerificationError
	if verifierKey != nil {
		signatureError = signatureCollector.verified
	}

	return bodyCollector,
		attachmentsCollector.GetAttachments(),
		attachmentsCollector.GetAttHeaders(),
		signatureError,
		err
}
