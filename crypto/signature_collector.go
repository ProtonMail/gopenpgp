package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime"
	"net/textproto"

	gomime "github.com/ProtonMail/go-mime"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// SignatureCollector structure
type SignatureCollector struct {
	config    *packet.Config
	keyring   openpgp.KeyRing
	target    gomime.VisitAcceptor
	signature string
	verified  error
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

// Accept collects the signature
func (sc *SignatureCollector) Accept(
	part io.Reader, header textproto.MIMEHeader,
	hasPlainSibling, isFirst, isLast bool,
) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if parentMediaType == "multipart/signed" {
		newPart, rawBody := gomime.GetRawMimePart(part, "--"+params["boundary"])
		var multiparts []io.Reader
		var multipartHeaders []textproto.MIMEHeader
		if multiparts, multipartHeaders, err = gomime.GetMultipartParts(newPart, params); err == nil {
			hasPlainChild := false
			for _, header := range multipartHeaders {
				mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
				if mediaType == "text/plain" {
					hasPlainChild = true
				}
			}
			if len(multiparts) != 2 {
				sc.verified = newSignatureNotSigned()
				// Invalid multipart/signed format just pass along
				_, err = ioutil.ReadAll(rawBody)
				if err != nil {
					return err
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
				return err
			}

			partData, err := ioutil.ReadAll(multiparts[1])
			if err != nil {
				return err
			}

			decodedPart := gomime.DecodeContentEncoding(
				bytes.NewReader(partData),
				multipartHeaders[1].Get("Content-Transfer-Encoding"))

			buffer, err := ioutil.ReadAll(decodedPart)
			if err != nil {
				return err
			}
			buffer, err = gomime.DecodeCharset(buffer, params)
			if err != nil {
				return err
			}
			sc.signature = string(buffer)
			str, _ := ioutil.ReadAll(rawBody)
			rawBody = bytes.NewReader(str)
			if sc.keyring != nil {
				_, err = openpgp.CheckArmoredDetachedSignature(sc.keyring, rawBody, bytes.NewReader(buffer), sc.config)

				if err != nil {
					sc.verified = newSignatureFailed()
				} else {
					sc.verified = nil
				}
			} else {
				sc.verified = newSignatureNoVerifier()
			}
			return nil
		}
		return
	}
	err = sc.target.Accept(part, header, hasPlainSibling, isFirst, isLast)
	if err != nil {
		return err
	}

	return nil
}

// GetSignature collected by Accept
func (sc SignatureCollector) GetSignature() string {
	return sc.signature
}
