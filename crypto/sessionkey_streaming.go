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
	err := w.signWriter.Close()
	if err != nil {
		return err
	}
	return w.encryptWriter.Close()
}

func (sk *SessionKey) EncryptStream(
	dataPacketWriter Writer,
	isBinary bool,
	filename string,
	modTime int64,
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

	encryptWriter, signWriter, err := encryptStreamWithSessionKey(
		isBinary,
		filename,
		uint32(modTime),
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

func (sk *SessionKey) DecryptStream(
	dataPacketReader Reader,
	verifyKeyRing *KeyRing, verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	messageDetails, err := decryptStreamWithSessionKey(
		sk,
		dataPacketReader,
		verifyKeyRing,
		verifyTime,
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
