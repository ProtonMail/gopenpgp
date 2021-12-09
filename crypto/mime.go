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
	var embeddedSigError *SignatureVerificationError
	if err != nil {
		sigErr := &SignatureVerificationError{}
		isSigError := errors.As(err, sigErr)
		if !isSigError {
			callbacks.OnError(err)
			return
		} else {
			embeddedSigError = sigErr
		}
	}
	body, attachments, attachmentHeaders, err := parseMIME(string(decryptedMessage.GetBinary()), verifyKey)
	var mimeSigError *SignatureVerificationError
	if err != nil {
		sigErr := &SignatureVerificationError{}
		isSigError := errors.As(err, sigErr)
		if !isSigError {
			callbacks.OnError(err)
			return
		} else {
			mimeSigError = sigErr
		}
	}
	// We only consider the signature to be failed if both embedded and mime verification failed
	if embeddedSigError != nil && mimeSigError != nil {
		callbacks.OnError(embeddedSigError)
		callbacks.OnError(mimeSigError)
		return
	}
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.OnBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.OnAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.OnEncryptedHeaders("")
}

// ----- INTERNAL FUNCTIONS -----

func parseMIME(
	mimeBody string, verifierKey *KeyRing,
) (*gomime.BodyCollector, []string, []string, error) {
	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "gopenpgp: error in reading message body data")
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
	if err == nil && verifierKey != nil {
		err = signatureCollector.verified
	}

	return bodyCollector,
		attachmentsCollector.GetAttachments(),
		attachmentsCollector.GetAttHeaders(),
		err
}
