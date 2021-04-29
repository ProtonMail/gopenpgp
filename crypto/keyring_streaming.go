package crypto

import (
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

func IsEOF(err error) bool {
	return errors.Is(err, io.EOF)
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
	signKeyRing *KeyRing,
) (plainMessageWriter WriteCloser, err error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}

	hints := &openpgp.FileHints{
		IsBinary: isBinary,
		FileName: filename,
		ModTime:  time.Unix(modTime, 0),
	}

	plainMessageWriter, err = asymmetricEncryptStream(hints, pgpMessageWriter, keyRing, signKeyRing, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return plainMessageWriter, nil
}

type PlainMessageReader struct {
	md            *openpgp.MessageDetails
	verifyKeyRing *KeyRing
	verifyTime    int64
}

func (msg *PlainMessageReader) IsBinary() bool {
	return msg.md.LiteralData.IsBinary
}

func (msg *PlainMessageReader) GetFilename() string {
	return msg.md.LiteralData.FileName
}

func (msg *PlainMessageReader) GetModificationTime() string {
	return msg.md.LiteralData.FileName
}

func (msg *PlainMessageReader) Read(b []byte) (int, error) {
	return msg.md.UnverifiedBody.Read(b)
}

func (msg *PlainMessageReader) VerifySignature() (err error) {
	if msg.verifyKeyRing != nil {
		processSignatureExpiration(msg.md, msg.verifyTime)
		err = verifyDetailsSignature(msg.md, msg.verifyKeyRing)
	}
	return
}

func (keyRing *KeyRing) DecryptStream(
	message Reader,
	verifyKeyRing *KeyRing, verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	messageDetails, err := asymmetricDecryptStream(
		message,
		keyRing,
		verifyKeyRing,
	)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}

	return &PlainMessageReader{
		messageDetails,
		verifyKeyRing,
		verifyTime,
	}, err
}
