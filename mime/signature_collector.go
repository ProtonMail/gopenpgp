package mime

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime"
	"net/textproto"

	pgpErrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/internal"

	gomime "github.com/ProtonMail/go-mime"
	"github.com/pkg/errors"
)

// signatureCollector structure.
type signatureCollector struct {
	verifyHandle crypto.PGPVerify
	target       gomime.VisitAcceptor
	signature    string
	verified     error
}

func newSignatureCollector(
	targetAcceptor gomime.VisitAcceptor, handle crypto.PGPVerify,
) *signatureCollector {
	return &signatureCollector{
		target:       targetAcceptor,
		verifyHandle: handle,
	}
}

// Accept collects the signature.
func (sc *signatureCollector) Accept(
	part io.Reader, header textproto.MIMEHeader,
	hasPlainSibling, isFirst, isLast bool,
) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))

	if parentMediaType != "multipart/signed" {
		sc.verified = newSignatureNotSigned()
		return sc.target.Accept(part, header, hasPlainSibling, isFirst, isLast)
	}

	newPart, rawBody := gomime.GetRawMimePart(part, "--"+params["boundary"])
	multiparts, multipartHeaders, err := gomime.GetMultipartParts(newPart, params)
	if err != nil {
		return err
	}

	hasPlainChild := false
	for _, header := range multipartHeaders {
		mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
		hasPlainChild = (mediaType == "text/plain")
	}
	if len(multiparts) != 2 {
		sc.verified = newSignatureNotSigned()
		// Invalid multipart/signed format just pass along
		if _, err = ioutil.ReadAll(rawBody); err != nil {
			return errors.Wrap(err, "mime: error in reading raw message body")
		}

		for i, p := range multiparts {
			if err = sc.target.Accept(p, multipartHeaders[i], hasPlainChild, true, true); err != nil {
				return err
			}
		}
		return nil
	}

	// actual multipart/signed format
	err = sc.target.Accept(multiparts[0], multipartHeaders[0], hasPlainChild, true, true)
	if err != nil {
		return errors.Wrap(err, "mime: error in parsing body")
	}

	partData, err := ioutil.ReadAll(multiparts[1])
	if err != nil {
		return errors.Wrap(err, "mime: error in ready part data")
	}

	decodedPart := gomime.DecodeContentEncoding(
		bytes.NewReader(partData),
		multipartHeaders[1].Get("Content-Transfer-Encoding"))

	buffer, err := ioutil.ReadAll(decodedPart)
	if err != nil {
		return errors.Wrap(err, "mime: error in reading decoded data")
	}
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	buffer, err = gomime.DecodeCharset(buffer, mediaType, params)
	if err != nil {
		return errors.Wrap(err, "mime: error in decoding charset")
	}
	sc.signature = string(buffer)
	str, _ := ioutil.ReadAll(rawBody)
	canonicalizedBody := internal.CanonicalizeBytes(internal.TrimEachLineBytes(str))
	if sc.verifyHandle != nil {
		verifyResult, err := sc.verifyHandle.VerifyDetached(canonicalizedBody, buffer, crypto.Armor)
		if errors.Is(err, pgpErrors.ErrUnknownIssuer) {
			return newSignatureNoVerifier()
		}
		if err != nil {
			return errors.Wrap(err, "mime: signature verification failed")
		}
		sc.verified = verifyResult.SignatureError()
	} else {
		sc.verified = newSignatureNoVerifier()
	}

	return nil
}

// GetSignature collected by Accept.
func (sc signatureCollector) GetSignature() string {
	return sc.signature
}

// newSignatureNotSigned creates a new SignatureVerificationError, type
// SignatureNotSigned.
func newSignatureNotSigned() crypto.SignatureVerificationError {
	return crypto.SignatureVerificationError{
		Status:  constants.SIGNATURE_NOT_SIGNED,
		Message: "Missing signature",
	}
}

// newSignatureNoVerifier creates a new SignatureVerificationError, type
// SignatureNoVerifier.
func newSignatureNoVerifier() crypto.SignatureVerificationError {
	return crypto.SignatureVerificationError{
		Status:  constants.SIGNATURE_NO_VERIFIER,
		Message: "No matching signature",
	}
}

func newSignatureFailed(cause error) crypto.SignatureVerificationError {
	return crypto.SignatureVerificationError{
		Status:  constants.SIGNATURE_FAILED,
		Message: "Invalid signature",
		Cause:   cause,
	}
}
