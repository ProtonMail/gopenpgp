package crypto

import (
	"bytes"
	"crypto"
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

// SignDetachedStream generates and returns a PGPSignature for a given message Reader.
func (keyRing *KeyRing) SignDetachedStream(message Reader) (*PGPSignature, error) {
	signEntity, err := keyRing.getSigningEntity()
	if err != nil {
		return nil, err
	}

	config := &packet.Config{DefaultHash: crypto.SHA512, Time: getTimeGenerator()}
	var outBuf bytes.Buffer
	// sign bin
	if err := openpgp.DetachSign(&outBuf, signEntity, message, config); err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in signing")
	}

	return NewPGPSignature(outBuf.Bytes()), nil
}

// VerifyDetachedStream verifies a message reader with a detached PGPSignature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetachedStream(message Reader, signature *PGPSignature, verifyTime int64) error {
	return verifySignature(
		keyRing.entities,
		message,
		signature.GetBinary(),
		verifyTime,
	)
}

// SignDetachedEncryptedStream generates and returns a PGPMessage
// containing an encrypted detached signature for a given PlainMessage.
func (keyRing *KeyRing) SignDetachedEncryptedStream(message Reader, encryptionKeyRing *KeyRing) (encryptedSignature *PGPMessage, err error) {
	if encryptionKeyRing == nil {
		return nil, errors.New("gopenpgp: no encryption key ring provided")
	}
	signature, err := keyRing.SignDetachedStream(message)
	if err != nil {
		return nil, err
	}
	plainMessage := NewPlainMessage(signature.GetBinary())
	encryptedSignature, err = encryptionKeyRing.Encrypt(plainMessage, nil)
	return
}

// VerifyDetachedEncryptedStream verifies a PlainMessage
// with a PGPMessage containing an encrypted detached signature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetachedEncryptedStream(message Reader, encryptedSignature *PGPMessage, decryptionKeyRing *KeyRing, verifyTime int64) error {
	if decryptionKeyRing == nil {
		return errors.New("gopenpgp: no decryption key ring provided")
	}
	plainMessage, err := decryptionKeyRing.Decrypt(encryptedSignature, nil, 0)
	if err != nil {
		return err
	}
	signature := NewPGPSignature(plainMessage.GetBinary())
	return keyRing.VerifyDetachedStream(message, signature, verifyTime)
}
