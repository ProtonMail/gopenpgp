package crypto

import (
	"bytes"
	"io/ioutil"
	"net/mail"
	"net/textproto"
	"sort"
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
	embeddedSigError, err := separateSigError(err)
	if err != nil {
		callbacks.OnError(err)
		return
	}
	body, attachments, attachmentHeaders, err := parseMIME(string(decryptedMessage.GetBinary()), verifyKey)
	mimeSigError, err := separateSigError(err)
	if err != nil {
		callbacks.OnError(err)
		return
	}
	// We only consider the signature to be failed if both embedded and mime verification failed
	if embeddedSigError != nil && mimeSigError != nil {
		callbacks.OnError(embeddedSigError)
		callbacks.OnError(mimeSigError)
		callbacks.OnVerified(prioritizeSignatureErrors(embeddedSigError, mimeSigError))
		return
	} else if verifyKey != nil {
		callbacks.OnVerified(constants.SIGNATURE_OK)
	}
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.OnBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.OnAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.OnEncryptedHeaders("")
}

// ----- INTERNAL FUNCTIONS -----

type signatureErrorList []*SignatureVerificationError

func (l signatureErrorList) Len() int { return len(l) }
func (l signatureErrorList) Less(i, j int) bool {
	return l[i].Status > l[j].Status
}
func (l signatureErrorList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

func prioritizeSignatureErrors(signatureErrs ...*SignatureVerificationError) int {
	var nonNilSigErrs []*SignatureVerificationError
	for _, err := range signatureErrs {
		if err != nil {
			nonNilSigErrs = append(nonNilSigErrs, err)
		}
	}
	sort.Sort(signatureErrorList(nonNilSigErrs))
	if len(nonNilSigErrs) == 0 {
		return constants.SIGNATURE_OK
	}
	return nonNilSigErrs[0].Status
}

func separateSigError(err error) (*SignatureVerificationError, error) {
	sigErr := &SignatureVerificationError{}
	isSigError := errors.As(err, sigErr)
	if isSigError {
		return sigErr, nil
	}
	return nil, err
}

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
