package crypto

import (
	"bufio"
	"bytes"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/textproto"
	"proton/pmmime"
)

type SignatureCollector struct {
	config    *packet.Config
	keyring   openpgp.KeyRing
	target    pmmime.VisitAcceptor
	signature string
	verified  int
}

func newSignatureCollector(targetAccepter pmmime.VisitAcceptor, keyring openpgp.KeyRing, config *packet.Config) *SignatureCollector {
	return &SignatureCollector{
		target:  targetAccepter,
		config:  config,
		keyring: keyring,
	}
}

func getRawMimePart(rawdata io.Reader, boundary string) (io.Reader, io.Reader) {
	b, _ := ioutil.ReadAll(rawdata)
	tee := bytes.NewReader(b)

	reader := bufio.NewReader(bytes.NewReader(b))
	byteBoundary := []byte(boundary)
	bodyBuffer := &bytes.Buffer{}
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			return tee, bytes.NewReader(bodyBuffer.Bytes())
		}
		if bytes.HasPrefix(line, byteBoundary) {
			break
		}
	}
	lineEndingLength := 0
	for {
		line, isPrefix, err := reader.ReadLine()
		if err != nil {
			return tee, bytes.NewReader(bodyBuffer.Bytes())
		}
		if bytes.HasPrefix(line, byteBoundary) {
			break
		}
		lineEndingLength = 0
		bodyBuffer.Write(line)
		if !isPrefix {
			reader.UnreadByte()
			reader.UnreadByte()
			token, _ := reader.ReadByte()
			if token == '\r' {
				lineEndingLength++
				bodyBuffer.WriteByte(token)
			}
			lineEndingLength++
			bodyBuffer.WriteByte(token)
		}
	}
	ioutil.ReadAll(reader)
	data := bodyBuffer.Bytes()
	return tee, bytes.NewReader(data[0 : len(data)-lineEndingLength])
}

func (sc *SignatureCollector) Accept(part io.Reader, header textproto.MIMEHeader, hasPlainSibling bool, isFirst, isLast bool) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if parentMediaType == "multipart/signed" {
		newPart, rawBody := getRawMimePart(part, "--"+params["boundary"])
		var multiparts []io.Reader
		var multipartHeaders []textproto.MIMEHeader
		if multiparts, multipartHeaders, err = mime.GetMultipartParts(newPart, params); err != nil {
			return
		} else {
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

func (ac SignatureCollector) GetSignature() string {
	return ac.signature
}
