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
	target     pmmime.VisitAcceptor
	signature 	string
}

func NewSignatureCollector(targetAccepter pmmime.VisitAcceptor) *SignatureCollector {
	return &SignatureCollector{
		target:     targetAccepter,
	}
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

func (sc *SignatureCollector) Accept(part io.Reader, header textproto.MIMEHeader, hasPlainSibling bool, isFirst, isLast bool) (err error) {
	parentMediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if parentMediaType == "multipart/signed" {
		var multiparts []io.Reader
		var multipartHeaders []textproto.MIMEHeader
		if multiparts, multipartHeaders, err = getMultipartParts(part, params); err != nil {
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
				// Invalid multipart/signed format just pass along
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
			decodedPart := pmmime.DecodeContentEncoding(bytes.NewReader(partData), header.Get("Content-Transfer-Encoding"))
			buffer, err := ioutil.ReadAll(decodedPart)
			if err != nil {
				return err
			}
			buffer, err = pmmime.DecodeCharset(buffer, params)
			if err != nil {
				return err
			}
			sc.signature = string(buffer)
			return err
		}
		return
	}
	sc.target.Accept(part, header, hasPlainSibling, isFirst, isLast)
	return nil
}


func (ac SignatureCollector) GetSignature() string {
	return ac.signature
}


func ParseMIME(mimeBody string) (body *pmmime.BodyCollector, atts, attHeaders []string, err error) {

	mm, err := mail.ReadMessage(strings.NewReader(mimeBody))
	if err != nil {
		return
	}

	h := textproto.MIMEHeader(mm.Header)
	mmBodyData, err := ioutil.ReadAll(mm.Body)

	printAccepter := pmmime.NewMIMEPrinter()
	bodyCollector := pmmime.NewBodyCollector(printAccepter)
	attachmentsCollector := pmmime.NewAttachmentsCollector(bodyCollector)
	mimeVisitor := pmmime.NewMimeVisitor(attachmentsCollector)
	signatureCollector := NewSignatureCollector(mimeVisitor)
	err = pmmime.VisitAll(bytes.NewReader(mmBodyData), h, signatureCollector)

	body = bodyCollector
	atts = attachmentsCollector.GetAttachments()
	attHeaders = attachmentsCollector.GetAttHeaders()

	return
}

/*

// define call back interface
type MIMECallbacks interface {
	onBody(body string, mimetype string)
	onAttachment(headers string, data []byte)
	// Encrypted headers can be an attachment and thus be placed at the end of the mime structure
	onEncryptedHeaders(headers string)
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