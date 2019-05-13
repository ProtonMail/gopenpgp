package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime"
	"net/textproto"

	"github.com/ProtonMail/go-pm-mime"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// SignatureCollector structure
type SignatureCollector struct {
	config    *packet.Config
	keyring   openpgp.KeyRing
	target    pmmime.VisitAcceptor
	signature string
	verified  int
}

func newSignatureCollector(targetAcceptor pmmime.VisitAcceptor, keyring openpgp.KeyRing, config *packet.Config) *SignatureCollector {
	return &SignatureCollector{
		target:  targetAcceptor,
		config:  config,
		keyring: keyring,
	}
}

// Accept
func (sc *SignatureCollector) Accept(part io.Reader, header textproto.MIMEHeader, hasPlainSibling bool, isFirst, isLast bool) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if parentMediaType == "multipart/signed" {
		newPart, rawBody := pmmime.GetRawMimePart(part, "--" + params["boundary"])
		var multiparts []io.Reader
		var multipartHeaders []textproto.MIMEHeader
		if multiparts, multipartHeaders, err = pmmime.GetMultipartParts(newPart, params); err == nil {
			hasPlainChild := false
			for _, header := range multipartHeaders {
				mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
				if mediaType == "text/plain" {
					hasPlainChild = true
				}
			}
			if len(multiparts) != 2 {
				sc.verified = notSigned
				// Invalid multipart/signed format just pass along
				ioutil.ReadAll(rawBody)
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
				return
			}

			partData, _ := ioutil.ReadAll(multiparts[1])
			decodedPart := pmmime.DecodeContentEncoding(bytes.NewReader(partData), multipartHeaders[1].Get("Content-Transfer-Encoding"))
			buffer, err := ioutil.ReadAll(decodedPart)
			if err != nil {
				return err
			}
			buffer, err = pmmime.DecodeCharset(buffer, params)
			if err != nil {
				return err
			}
			sc.signature = string(buffer)
			str, _ := ioutil.ReadAll(rawBody)
			rawBody = bytes.NewReader(str)
			if sc.keyring != nil {
				_, err = openpgp.CheckArmoredDetachedSignature(sc.keyring, rawBody, bytes.NewReader(buffer), sc.config)

				if err != nil {
					sc.verified = failed
				} else {
					sc.verified = ok
				}
			} else {
				sc.verified = noVerifier
			}
			return nil
		}
		return
	}
	sc.target.Accept(part, header, hasPlainSibling, isFirst, isLast)
	return nil
}

// GetSignature
func (sc SignatureCollector) GetSignature() string {
	return sc.signature
}
