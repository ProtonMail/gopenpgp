package mime

import (
	"bytes"
	"io/ioutil"
	"net/mail"
	"net/textproto"

	gomime "github.com/ProtonMail/go-mime"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/internal"
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

type decryption struct {
	DecryptionHandle crypto.PGPDecryption
	VerifyHandle     crypto.PGPVerify
}

func NewDecryptionFromHandles(
	decryptionHandle crypto.PGPDecryption,
	verifyHandle crypto.PGPVerify,
) (*decryption, error) {
	if decryptionHandle == nil {
		return nil, errors.New("gopenpgp: no decryption handle provided")
	}
	return &decryption{
		DecryptionHandle: decryptionHandle,
		VerifyHandle:     verifyHandle,
	}, nil
}

func NewDecryption(
	pgp *crypto.PGPHandle,
	decryptionKeys *crypto.KeyRing,
	verifyKey *crypto.KeyRing,
	verifyTime int64,
) (*decryption, error) {
	decryptHandle, err := pgp.Decryption().
		DecryptionKeys(decryptionKeys).
		VerifyKeys(verifyKey).
		VerifyTime(verifyTime).New()
	if err != nil {
		return nil, err
	}
	var verifyHandle crypto.PGPVerify
	if verifyKey != nil {
		verifyHandle, err = pgp.Verify().
			VerifyKeys(verifyKey).
			VerifyTime(verifyTime).
			New()
		if err != nil {
			return nil, err
		}
	}
	return &decryption{
		DecryptionHandle: decryptHandle,
		VerifyHandle:     verifyHandle,
	}, nil
}

// DecryptMIMEMessage decrypts a MIME message.
func (d *decryption) DecryptMIMEMessage(
	message []byte,
	callbacks MIMECallbacks,
) {
	decResult, err := d.DecryptionHandle.Decrypt(message)
	if err != nil {
		callbacks.OnError(err)
		return
	}
	decryptedMessage := decResult.Result()
	embeddedSigError, _ := separateSigError(decResult.SignatureError())

	body, attachments, attachmentHeaders, err := d.parseMIME(decryptedMessage)
	mimeSigError, err := separateSigError(err)
	if err != nil {
		callbacks.OnError(err)
		return
	}
	// We only consider the signature to be failed if both embedded and mime verification failed
	if decResult.HasSignatureError() && mimeSigError != nil {
		callbacks.OnError(embeddedSigError)
		callbacks.OnError(mimeSigError)
		callbacks.OnVerified(prioritizeSignatureErrors(embeddedSigError, mimeSigError))
	} else if d.VerifyHandle != nil {
		callbacks.OnVerified(constants.SIGNATURE_OK)
	}
	bodyContent, bodyMimeType := body.GetBody()
	bodyContentSanitized := internal.SanitizeString(bodyContent)
	callbacks.OnBody(bodyContentSanitized, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.OnAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.OnEncryptedHeaders("")
}

// ----- INTERNAL FUNCTIONS -----

func prioritizeSignatureErrors(signatureErrs ...*crypto.SignatureVerificationError) (maxError int) {
	// select error with the highest value, if any
	// FAILED > NO VERIFIER > NOT SIGNED > SIGNATURE OK
	maxError = constants.SIGNATURE_OK
	for _, err := range signatureErrs {
		if err.Status > maxError {
			maxError = err.Status
		}
	}
	return
}

func separateSigError(err error) (*crypto.SignatureVerificationError, error) {
	sigErr := &crypto.SignatureVerificationError{}
	if errors.As(err, sigErr) {
		return sigErr, nil
	}
	return nil, err
}

func (d *decryption) parseMIME(
	mimeBody []byte,
) (*gomime.BodyCollector, []string, []string, error) {
	mm, err := mail.ReadMessage(bytes.NewReader(mimeBody))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "gopenpgp: error in reading message body data")
	}

	printAccepter := gomime.NewMIMEPrinter()
	bodyCollector := gomime.NewBodyCollector(printAccepter)
	attachmentsCollector := gomime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := gomime.NewMimeVisitor(attachmentsCollector)

	signatureCollector := newSignatureCollector(mimeVisitor, d.VerifyHandle)

	err = gomime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)
	if err == nil && d.VerifyHandle != nil {
		err = signatureCollector.verified
	}

	return bodyCollector,
		attachmentsCollector.GetAttachments(),
		attachmentsCollector.GetAttHeaders(),
		err
}
