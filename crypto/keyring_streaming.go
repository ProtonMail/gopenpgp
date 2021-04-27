package crypto

import (
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

var EOF = io.EOF

func IsEOF(err error) bool {
	return errors.Is(err, EOF)
}

type Reader interface {
	Read([]byte) (int, error)
}

type Writer interface {
	Write([]byte) (int, error)
}

type WriteCloser interface {
	Write([]byte) (int, error)
	Close() error
}

func (keyRing *KeyRing) EncryptStream(
	pgpMessageWriter Writer,
	isBinary bool,
	filename string,
	modTime int64,
	privateKey *KeyRing,
) (plainMessageWriter WriteCloser, err error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}
	var signEntity *openpgp.Entity

	if privateKey != nil && len(privateKey.entities) > 0 {
		var err error
		signEntity, err = privateKey.getSigningEntity()
		if err != nil {
			return nil, err
		}
	}

	hints := &openpgp.FileHints{
		IsBinary: isBinary,
		FileName: filename,
		ModTime:  time.Unix(modTime, 0),
	}

	if isBinary {
		plainMessageWriter, err = openpgp.Encrypt(pgpMessageWriter, keyRing.entities, signEntity, hints, config)
	} else {
		plainMessageWriter, err = openpgp.EncryptText(pgpMessageWriter, keyRing.entities, signEntity, hints, config)
	}
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return plainMessageWriter, nil
}

type PlainMessageReader struct {
	Data     Reader
	TextType bool
	Filename string
	Time     uint32
}

func (keyRing *KeyRing) DecryptStream(
	message Reader, verifyKey *KeyRing, verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	privKeyEntries := keyRing.entities
	var additionalEntries openpgp.EntityList

	if verifyKey != nil {
		additionalEntries = verifyKey.entities
	}

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	config := &packet.Config{Time: getTimeGenerator()}

	messageDetails, err := openpgp.ReadMessage(message, privKeyEntries, nil, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}

	if verifyKey != nil {
		processSignatureExpiration(messageDetails, verifyTime)
		err = verifyDetailsSignature(messageDetails, verifyKey)
	}

	return &PlainMessageReader{
		Data:     messageDetails.UnverifiedBody,
		TextType: !messageDetails.LiteralData.IsBinary,
		Filename: messageDetails.LiteralData.FileName,
		Time:     messageDetails.LiteralData.Time,
	}, err
}
