package crypto

import (
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

type signAndEncryptWriteCloser struct {
	signWriter    WriteCloser
	encryptWriter WriteCloser
}

func (w *signAndEncryptWriteCloser) Write(b []byte) (int, error) {
	return w.signWriter.Write(b)
}

func (w *signAndEncryptWriteCloser) Close() error {
	if err := w.signWriter.Close(); err != nil {
		return err
	}
	return w.encryptWriter.Close()
}

// EncryptStream is used to encrypt data as a Writer.
// It takes a writer for the encrypted data packet and returns a writer for the plaintext data.
// If signKeyRing is not nil, it is used to do an embedded signature.
func (sk *SessionKey) EncryptStream(
	dataPacketWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
) (plainMessageWriter WriteCloser, err error) {
	dc, err := sk.GetCipherFunc()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to encrypt with session key")
	}

	config := &packet.Config{
		Time:          getTimeGenerator(),
		DefaultCipher: dc,
	}
	var signEntity *openpgp.Entity
	if signKeyRing != nil {
		signEntity, err = signKeyRing.getSigningEntity()
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to sign")
		}
	}

	if plainMessageMetadata == nil {
		// Use sensible default metadata
		plainMessageMetadata = &PlainMessageMetadata{
			IsBinary: true,
			Filename: "",
			ModTime:  GetUnixTime(),
		}
	}

	encryptWriter, signWriter, err := encryptStreamWithSessionKey(
		plainMessageMetadata.IsBinary,
		plainMessageMetadata.Filename,
		uint32(plainMessageMetadata.ModTime),
		dataPacketWriter,
		sk,
		signEntity,
		config,
	)

	if err != nil {
		return nil, err
	}
	if signWriter != nil {
		plainMessageWriter = &signAndEncryptWriteCloser{signWriter, encryptWriter}
	} else {
		plainMessageWriter = encryptWriter
	}
	return plainMessageWriter, err
}

// DecryptStream is used to decrypt a data packet as a Reader.
// It takes a reader for the data packet
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
func (sk *SessionKey) DecryptStream(
	dataPacketReader Reader,
	verifyKeyRing *KeyRing,
	verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	messageDetails, err := decryptStreamWithSessionKey(
		sk,
		dataPacketReader,
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
