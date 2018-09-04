package pmcrypto

import (
	"net/mail"
	"strings"
	"net/textproto"
	"io/ioutil"
	"bytes"
	"proton/pmmime"
	"io"
	log "github.com/Sirupsen/logrus"
	"mime"
	"mime/multipart"
	"bufio"
	"fmt"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp"
)



func DecodePart(partReader io.Reader, header textproto.MIMEHeader) (decodedPart io.Reader) {
	decodedPart = pmmime.DecodeContentEncoding(partReader, header.Get("Content-Transfer-Encoding"))
	if decodedPart == nil {
		log.Warnf("Unsupported Content-Transfer-Encoding '%v'", header.Get("Content-Transfer-Encoding"))
		decodedPart = partReader
	}
	return
}

// ======================== Attachments Collector  ==============
// Collect contents of all attachment parts and return
// them as a string

type SignatureCollector struct {
	config     	packet.Config
	keyring	    openpgp.KeyRing
	target      pmmime.VisitAcceptor
	signature 	string
	verified	int
}

func NewSignatureCollector(config packet.Config, targetAccepter pmmime.VisitAcceptor) *SignatureCollector {
	return &SignatureCollector{
		target:     targetAccepter,
		config: 	config,

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
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			return tee, bytes.NewReader(bodyBuffer.Bytes())
		}
		if bytes.HasPrefix(line, byteBoundary) {
			break
		}
		bodyBuffer.Write(line)
	}
	ioutil.ReadAll(reader)
	return tee, bytes.NewReader(bodyBuffer.Bytes())
}

func getMultipartParts(r io.Reader, params map[string]string) (parts []io.Reader, headers []textproto.MIMEHeader, err error) {
	mr := multipart.NewReader(r, params["boundary"])
	parts = []io.Reader{}
	headers = []textproto.MIMEHeader{}
	var p *multipart.Part
	for {
		p, err = mr.NextPart()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return
		}
		b, _ := ioutil.ReadAll(p)
		buffer := bytes.NewBuffer(b)

		parts = append(parts, buffer)
		headers = append(headers, p.Header)
	}
	return
}

func verifyMime(body io.Reader, bodyHeader textproto.MIMEHeader, signature io.Reader) (err error) {
	rawData, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}

	decodedBodyStream := pmmime.DecodeContentEncoding(bytes.NewReader(rawData), bodyHeader.Get("Content-Transfer-Encoding"))

}

func (sc *SignatureCollector) Accept(part io.Reader, header textproto.MIMEHeader, hasPlainSibling bool, isFirst, isLast bool) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if parentMediaType == "multipart/signed" {
		newPart, rawBody := getRawMimePart(part, params["boundary"])
		var multiparts []io.Reader
		var multipartHeaders []textproto.MIMEHeader
		if multiparts, multipartHeaders, err = getMultipartParts(newPart, params); err != nil {
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

			_, err = openpgp.CheckArmoredDetachedSignature(sc.keyring, rawBody, bytes.NewReader(buffer), &sc.config)

			if err != nil {
				sc.verified = failed
			} else {
				sc.verified = ok
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




func (openpgp OpenPGP) ParseMIME(mimeBody string, verifierKey []byte) (body *pmmime.BodyCollector, atts, attHeaders []string, err error) {

	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return
	}
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: openpgp.getTimeGenerator() }

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)

	printAccepter := pmmime.NewMIMEPrinter()
	bodyCollector := pmmime.NewBodyCollector(printAccepter)
	attachmentsCollector := pmmime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := pmmime.NewMimeVisitor(attachmentsCollector)
	signatureCollector := NewSignatureCollector(config, mimeVisitor)
	err = pmmime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)

	body = bodyCollector
	atts = attachmentsCollector.GetAttachments()
	attHeaders = attachmentsCollector.GetAttHeaders()

	return
}

/*

func CheckDetachedSignature(keyring KeyRing, signed, signature io.Reader, config *packet.Config) (signer *Entity, err error) {
	var issuerKeyId uint64
	var hashFunc crypto.Hash
	var sigType packet.SignatureType
	var keys []Key
	var p packet.Packet

	packets := packet.NewReader(signature)
	for {
		p, err = packets.Next()
		if err == io.EOF {
			return nil, errors.ErrUnknownIssuer
		}
		if err != nil {
			return nil, err
		}

		switch sig := p.(type) {
		case *packet.Signature:
			if sig.IssuerKeyId == nil {
				return nil, errors.StructuralError("signature doesn't have an issuer")
			}
			issuerKeyId = *sig.IssuerKeyId
			hashFunc = sig.Hash
			sigType = sig.SigType
		case *packet.SignatureV3:
			issuerKeyId = sig.IssuerKeyId
			hashFunc = sig.Hash
			sigType = sig.SigType
		default:
			return nil, errors.StructuralError("non signature packet found")
		}

		keys = keyring.KeysByIdUsage(issuerKeyId, packet.KeyFlagSign)
		if len(keys) > 0 {
			break
		}
	}

	if len(keys) == 0 {
		panic("unreachable")
	}

	h, wrappedHash, err := hashForSignature(hashFunc, sigType)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(wrappedHash, signed); err != nil && err != io.EOF {
		return nil, err
	}

	for _, key := range keys {
		switch sig := p.(type) {
		case *packet.Signature:
			err = key.PublicKey.VerifySignature(h, sig)
			if err == nil && sig.KeyExpired(config.Now()) {
				err = errors.ErrSignatureExpired
			}
		case *packet.SignatureV3:
			err = key.PublicKey.VerifySignatureV3(h, sig)
		default:
			panic("unreachable")
		}

		if err == errors.ErrSignatureExpired {
			return key.Entity, err
		}

		if err == nil {
			return key.Entity, nil
		}
	}

	return nil, err
}

// define call back interface
type MIMECallbacks interface {
	onBody(body string, mimetype string)
	onAttachment(headers string, data []byte)
	// Encrypted headers can be an attachment and thus be placed at the end of the mime structure
	onEncryptedHeaders(headers string)
}
func (o *OpenPGP) DecryptMessageVerifyBinKeyPrivbinkeys(encryptedText string, veriferKey []byte, privateKeys []byte, passphrase string, verifyTime int64) (*DecryptSignedVerify, error) {
	return o.decryptMessageVerifyAllBin(encryptedText, veriferKey, privateKeys, passphrase, verifyTime)
}

func (o *OpenPGP) decryptMIMEMessage(encryptedText string, verifierKey string, privateKeys []byte,
	passphrase string, callbacks MIMECallbacks, verifyTime int64) (verifier int, err error) {
	decsignverify, err := o.DecryptMessageVerifyPrivbinkeys(encryptedText, verifierKey, privateKeys, passphrase, verifyTime)
	if (err != nil) {
		return 0, err
	}

	body, attachments, attachmentHeaders, err := parseMIME(decsignverify.Plaintext)
	if (err != nil) {
		return 0, err
	}
	bodyContent, bodyMimeType := body.GetBody()
	callbacks.onBody(bodyContent, bodyMimeType)
	for i := 0; i < len(attachments); i++ {
		callbacks.onAttachment(attachmentHeaders[i], []byte(attachments[i]))
	}
	callbacks.onEncryptedHeaders("")

	// Todo verify the signature included in the attachment

	return verifier, nil
}*/