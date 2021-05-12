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

type Reader interface {
	Read(b []byte) (n int, err error)
}

type Writer interface {
	Write(b []byte) (n int, err error)
}

type WriteCloser interface {
	Write(b []byte) (n int, err error)
	Close() (err error)
}

// EncryptStream is used to encrypt data as a Writer.
// It takes a writer for the encrypted data and returns a writer for the plaintext data
// If signKeyRing is not nil, it is used to do an embedded signature.
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
		return nil, err
	}
	return plainMessageWriter, nil
}

// EncryptSplitResult is used to wrap the encryption writecloser while storing the key packet.
type EncryptSplitResult struct {
	isClosed           bool
	keyPacketBuf       *bytes.Buffer
	keyPacket          []byte
	plainMessageWriter WriteCloser // The writer to writer plaintext data in.
}

func (res *EncryptSplitResult) Write(b []byte) (n int, err error) {
	return res.plainMessageWriter.Write(b)
}

func (res *EncryptSplitResult) Close() (err error) {
	err = res.plainMessageWriter.Close()
	if err != nil {
		return err
	}
	res.isClosed = true
	res.keyPacket = res.keyPacketBuf.Bytes()
	return nil
}

// GetKeyPacket returns the Public-Key Encrypted Session Key Packets (https://datatracker.ietf.org/doc/html/rfc4880#section-5.1).
// This can be retrieved only after the message has been fully written and the writer is closed.
func (res *EncryptSplitResult) GetKeyPacket() (keyPacket []byte, err error) {
	if !res.isClosed {
		return nil, errors.New("gopenpgp: can't access key packet until the message writer has been closed")
	}
	return res.keyPacket, nil
}

// EncryptSplitStream is used to encrypt data as a stream.
// It takes a writer for the encrypted data packet
// and returns a writer for the plaintext data and the key packet.
// If signKeyRing is not nil, it is used to do an embedded signature.
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
		return nil, err
	}
	return &EncryptSplitResult{
		keyPacketBuf:       &keyPacketBuf,
		plainMessageWriter: plainMessageWriter,
	}, nil
}

// PlainMessageReader is used to wrap the data of the decrypted plain message.
// It can be used to read the decrypted data and verify the embedded signature.
type PlainMessageReader struct {
	details       *openpgp.MessageDetails
	verifyKeyRing *KeyRing
	verifyTime    int64
	readAll       bool
}

// IsBinary returns whether the message is binary or text.
func (msg *PlainMessageReader) IsBinary() bool {
	return msg.details.LiteralData.IsBinary
}

// GetFilename returns the filename of the message.
func (msg *PlainMessageReader) GetFilename() string {
	return msg.details.LiteralData.FileName
}

// GetModificationTime returns the modification time of the message.
func (msg *PlainMessageReader) GetModificationTime() int64 {
	return int64(msg.details.LiteralData.Time)
}

// Read is used to access the message decrypted data.
// Makes PlainMessageReader implement the Reader interface.
func (msg *PlainMessageReader) Read(b []byte) (n int, err error) {
	n, err = msg.details.UnverifiedBody.Read(b)
	if errors.Is(err, io.EOF) {
		msg.readAll = true
	}
	return
}

// VerifySignature is used to verify that the signature is valid.
// This method needs to be called once all the data has been read.
// It will return an error if the signature is invalid
// or if the message hasn't been read entirely.
func (msg *PlainMessageReader) VerifySignature() (err error) {
	if !msg.readAll {
		return errors.New("gopenpg: can't verify the signature until the message reader has been read entirely")
	}
	if msg.verifyKeyRing != nil {
		processSignatureExpiration(msg.details, msg.verifyTime)
		err = verifyDetailsSignature(msg.details, msg.verifyKeyRing)
	}
	return
}

// DecryptStream is used to decrypt a pgp message as a Reader.
// It takes a reader for the message data
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
func (keyRing *KeyRing) DecryptStream(
	message Reader,
	verifyKeyRing *KeyRing,
	verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	messageDetails, err := asymmetricDecryptStream(
		message,
		keyRing,
		verifyKeyRing,
	)
	if err != nil {
		return nil, err
	}

	return &PlainMessageReader{
		messageDetails,
		verifyKeyRing,
		verifyTime,
		false,
	}, err
}

// DecryptSplitStream is used to decrypt a split pgp message as a Reader.
// It takes a key packet and a reader for the data packet
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
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
func (keyRing *KeyRing) VerifyDetachedStream(
	message Reader,
	signature *PGPSignature,
	verifyTime int64,
) error {
	return verifySignature(
		keyRing.entities,
		message,
		signature.GetBinary(),
		verifyTime,
	)
}

// SignDetachedEncryptedStream generates and returns a PGPMessage
// containing an encrypted detached signature for a given message Reader.
func (keyRing *KeyRing) SignDetachedEncryptedStream(
	message Reader,
	encryptionKeyRing *KeyRing,
) (encryptedSignature *PGPMessage, err error) {
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
func (keyRing *KeyRing) VerifyDetachedEncryptedStream(
	message Reader,
	encryptedSignature *PGPMessage,
	decryptionKeyRing *KeyRing,
	verifyTime int64,
) error {
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
