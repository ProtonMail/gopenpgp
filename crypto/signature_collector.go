package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime"
	"net/textproto"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gomime "github.com/ProtonMail/go-mime"
	"github.com/pkg/errors"
)

// SignatureCollector structure.
type SignatureCollector struct {
	config    *packet.Config
	keyring   openpgp.KeyRing
	target    gomime.VisitAcceptor
	signature string
	verified  *SignatureVerificationError
}

func newSignatureCollector(
	targetAcceptor gomime.VisitAcceptor, keyring openpgp.KeyRing, config *packet.Config,
) *SignatureCollector {
	return &SignatureCollector{
		target:  targetAcceptor,
		config:  config,
		keyring: keyring,
	}
}

// Accept collects the signature.
func (sc *SignatureCollector) Accept(
	part io.Reader, header textproto.MIMEHeader,
	hasPlainSibling, isFirst, isLast bool,
) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))

	if parentMediaType != "multipart/signed" {
		return sc.target.Accept(part, header, hasPlainSibling, isFirst, isLast)
	}

	newPart, rawBody := gomime.GetRawMimePart(part, "--"+params["boundary"])
	multiparts, multipartHeaders, err := gomime.GetMultipartParts(newPart, params)
	if err != nil {
		return
	}

	hasPlainChild := false
	for _, header := range multipartHeaders {
		mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
		hasPlainChild = (mediaType == "text/plain")
	}
	if len(multiparts) != 2 {
		sigErr := newSignatureNotSigned()
		sc.verified = &sigErr
		// Invalid multipart/signed format just pass along
		if _, err = ioutil.ReadAll(rawBody); err != nil {
			return errors.Wrap(err, "gopenpgp: error in reading raw message body")
		}

		for i, p := range multiparts {
			if err = sc.target.Accept(p, multipartHeaders[i], hasPlainChild, true, true); err != nil {
				return
			}
		}
		return
	}

	// actual multipart/signed format
	err = sc.target.Accept(multiparts[0], multipartHeaders[0], hasPlainChild, true, true)
	if err != nil {
		return errors.Wrap(err, "gopenpgp: error in parsing body")
	}

	partData, err := ioutil.ReadAll(multiparts[1])
	if err != nil {
		return errors.Wrap(err, "gopenpgp: error in ready part data")
	}

	decodedPart := gomime.DecodeContentEncoding(
		bytes.NewReader(partData),
		multipartHeaders[1].Get("Content-Transfer-Encoding"))

	buffer, err := ioutil.ReadAll(decodedPart)
	if err != nil {
		return errors.Wrap(err, "gopenpgp: error in reading decoded data")
	}
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	buffer, err = gomime.DecodeCharset(buffer, mediaType, params)
	if err != nil {
		return errors.Wrap(err, "gopenpgp: error in decoding charset")
	}
	sc.signature = string(buffer)
	str, _ := ioutil.ReadAll(rawBody)
	rawBody = bytes.NewReader(str)
	if sc.keyring != nil {
		_, err = openpgp.CheckArmoredDetachedSignature(sc.keyring, rawBody, bytes.NewReader(buffer), sc.config)

		if err != nil {
			sigErr := newSignatureFailed()
			sc.verified = &sigErr
		} else {
			sc.verified = nil
		}
	} else {
		sigErr := newSignatureNoVerifier()
		sc.verified = &sigErr
	}

	return nil
}

// GetSignature collected by Accept.
func (sc SignatureCollector) GetSignature() string {
	return sc.signature
}
