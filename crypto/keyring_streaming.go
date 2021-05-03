package crypto

import (
	"bytes"
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
	Read(b []byte) (n int, err error)
}

type Writer interface {
	Write(b []byte) (n int, err error)
}

type WriteCloser interface {
	Write(b []byte) (n int, err error)
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

	plainMessageWriter, err = asymmetricEncryptStream(hints, pgpMessageWriter, pgpMessageWriter, keyRing, signKeyRing, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return plainMessageWriter, nil
}

type PlainMessageReader struct {
	details       *openpgp.MessageDetails
	verifyKeyRing *KeyRing
	verifyTime    int64
	readAll       bool
}

type EncryptSplitResult struct {
	KeyPacket          []byte
	PlainMessageWriter WriteCloser
}

func (keyRing *KeyRing) EncryptSplitStream(
	dataPacketWriter Writer,
	isBinary bool,
	filename string,
	modTime int64,
	signKeyRing *KeyRing,
) (*EncryptSplitResult, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}

	hints := &openpgp.FileHints{
		IsBinary: isBinary,
		FileName: filename,
		ModTime:  time.Unix(modTime, 0),
	}
	var keyPacketBuf bytes.Buffer
	plainMessageWriter, err := asymmetricEncryptStream(hints, &keyPacketBuf, dataPacketWriter, keyRing, signKeyRing, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	keyPacket := keyPacketBuf.Bytes()
	return &EncryptSplitResult{keyPacket, plainMessageWriter}, nil
}

func (msg *PlainMessageReader) IsBinary() bool {
	return msg.details.LiteralData.IsBinary
}

func (msg *PlainMessageReader) GetFilename() string {
	return msg.details.LiteralData.FileName
}

func (msg *PlainMessageReader) GetModificationTime() string {
	return msg.details.LiteralData.FileName
}

func (msg *PlainMessageReader) Read(b []byte) (n int, err error) {
	n, err = msg.details.UnverifiedBody.Read(b)
	if errors.Is(err, io.EOF) {
		msg.readAll = true
	}
	return
}

func (msg *PlainMessageReader) VerifySignature() (err error) {
	if !msg.readAll {
		return errors.New("gopenpg: Can't verify the signature until the message reader has been read entirely")
	}
	if msg.verifyKeyRing != nil {
		processSignatureExpiration(msg.details, msg.verifyTime)
		err = verifyDetailsSignature(msg.details, msg.verifyKeyRing)
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
		false,
	}, err
}

func (keyRing *KeyRing) DecryptSplitStream(
	keypacket []byte,
	dataPacketReader Reader,
	verifyKeyRing *KeyRing, verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	messageReader := io.MultiReader(
		bytes.NewReader(keypacket),
		dataPacketReader,
	)
	return keyRing.DecryptStream(
		messageReader,
		verifyKeyRing,
		verifyTime,
	)
}
