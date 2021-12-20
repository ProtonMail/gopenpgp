package crypto

import (
	"bytes"
	"crypto"
	"io"
	"io/ioutil"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/pkg/errors"
)

// Encrypt encrypts a PlainMessage, outputs a PGPMessage.
// If an unlocked private key is also provided it will also sign the message.
// * message    : The plaintext input as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
func (keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}
	encrypted, err := asymmetricEncrypt(message, keyRing, privateKey, config)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// EncryptWithCompression encrypts with compression support a PlainMessage to PGPMessage using public/private keys.
// * message : The plain data as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
// * output  : The encrypted data as PGPMessage.
func (keyRing *KeyRing) EncryptWithCompression(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error) {
	config := &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		Time:                   getTimeGenerator(),
		DefaultCompressionAlgo: constants.DefaultCompression,
		CompressionConfig:      &packet.CompressionConfig{Level: constants.DefaultCompressionLevel},
	}

	encrypted, err := asymmetricEncrypt(message, keyRing, privateKey, config)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// Decrypt decrypts encrypted string using pgp keys, returning a PlainMessage
// * message    : The encrypted input as a PGPMessage
// * verifyKey  : Public key for signature verification (optional)
// * verifyTime : Time at verification (necessary only if verifyKey is not nil)
//
// When verifyKey is not provided, then verifyTime should be zero, and
// signature verification will be ignored.
func (keyRing *KeyRing) Decrypt(
	message *PGPMessage, verifyKey *KeyRing, verifyTime int64,
) (*PlainMessage, error) {
	return asymmetricDecrypt(message.NewReader(), keyRing, verifyKey, verifyTime)
}

// SignDetached generates and returns a PGPSignature for a given PlainMessage.
func (keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error) {
	signEntity, err := keyRing.getSigningEntity()
	if err != nil {
		return nil, err
	}

	config := &packet.Config{DefaultHash: crypto.SHA512, Time: getTimeGenerator()}
	var outBuf bytes.Buffer
	// sign bin
	if err := openpgp.DetachSign(&outBuf, signEntity, message.NewReader(), config); err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in signing")
	}

	return NewPGPSignature(outBuf.Bytes()), nil
}

// VerifyDetached verifies a PlainMessage with a detached PGPSignature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) error {
	return verifySignature(
		keyRing.entities,
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
	)
}

// SignDetachedEncrypted generates and returns a PGPMessage
// containing an encrypted detached signature for a given PlainMessage.
func (keyRing *KeyRing) SignDetachedEncrypted(message *PlainMessage, encryptionKeyRing *KeyRing) (encryptedSignature *PGPMessage, err error) {
	if encryptionKeyRing == nil {
		return nil, errors.New("gopenpgp: no encryption key ring provided")
	}
	signature, err := keyRing.SignDetached(message)
	if err != nil {
		return nil, err
	}
	plainMessage := NewPlainMessage(signature.GetBinary())
	encryptedSignature, err = encryptionKeyRing.Encrypt(plainMessage, nil)
	return
}

// VerifyDetachedEncrypted verifies a PlainMessage
// with a PGPMessage containing an encrypted detached signature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetachedEncrypted(message *PlainMessage, encryptedSignature *PGPMessage, decryptionKeyRing *KeyRing, verifyTime int64) error {
	if decryptionKeyRing == nil {
		return errors.New("gopenpgp: no decryption key ring provided")
	}
	plainMessage, err := decryptionKeyRing.Decrypt(encryptedSignature, nil, 0)
	if err != nil {
		return err
	}
	signature := NewPGPSignature(plainMessage.GetBinary())
	return keyRing.VerifyDetached(message, signature, verifyTime)
}

// GetVerifiedSignatureTimestamp verifies a PlainMessage with a detached PGPSignature
// returns the creation time of the signature if it succeeds
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) GetVerifiedSignatureTimestamp(message *PlainMessage, signature *PGPSignature, verifyTime int64) (int64, error) {
	packets := packet.NewReader(bytes.NewReader(signature.Data))
	var err error
	var p packet.Packet
	for {
		p, err = packets.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			continue
		}
		sigPacket, ok := p.(*packet.Signature)
		if !ok {
			continue
		}
		var outBuf bytes.Buffer
		err = sigPacket.Serialize(&outBuf)
		if err != nil {
			continue
		}
		err = verifySignature(
			keyRing.entities,
			message.NewReader(),
			outBuf.Bytes(),
			verifyTime,
		)
		if err != nil {
			continue
		}
		return sigPacket.CreationTime.Unix(), nil
	}
	return 0, errors.Wrap(err, "gopenpgp: can't verify any signature packets")
}

// ------ INTERNAL FUNCTIONS -------

// Core for encryption+signature (non-streaming) functions.
func asymmetricEncrypt(
	plainMessage *PlainMessage,
	publicKey, privateKey *KeyRing,
	config *packet.Config,
) ([]byte, error) {
	var outBuf bytes.Buffer
	var encryptWriter io.WriteCloser
	var err error

	hints := &openpgp.FileHints{
		IsBinary: plainMessage.IsBinary(),
		FileName: plainMessage.Filename,
		ModTime:  plainMessage.getFormattedTime(),
	}

	encryptWriter, err = asymmetricEncryptStream(hints, &outBuf, &outBuf, publicKey, privateKey, config)
	if err != nil {
		return nil, err
	}

	_, err = encryptWriter.Write(plainMessage.GetBinary())
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in writing to message")
	}

	err = encryptWriter.Close()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in closing message")
	}

	return outBuf.Bytes(), nil
}

// Core for encryption+signature (all) functions.
func asymmetricEncryptStream(
	hints *openpgp.FileHints,
	keyPacketWriter io.Writer,
	dataPacketWriter io.Writer,
	publicKey, privateKey *KeyRing,
	config *packet.Config,
) (encryptWriter io.WriteCloser, err error) {
	var signEntity *openpgp.Entity

	if privateKey != nil && len(privateKey.entities) > 0 {
		var err error
		signEntity, err = privateKey.getSigningEntity()
		if err != nil {
			return nil, err
		}
	}

	if hints.IsBinary {
		encryptWriter, err = openpgp.EncryptSplit(keyPacketWriter, dataPacketWriter, publicKey.entities, signEntity, hints, config)
	} else {
		encryptWriter, err = openpgp.EncryptTextSplit(keyPacketWriter, dataPacketWriter, publicKey.entities, signEntity, hints, config)
	}
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return encryptWriter, nil
}

// Core for decryption+verification (non streaming) functions.
func asymmetricDecrypt(
	encryptedIO io.Reader, privateKey *KeyRing, verifyKey *KeyRing, verifyTime int64,
) (message *PlainMessage, err error) {
	messageDetails, err := asymmetricDecryptStream(
		encryptedIO,
		privateKey,
		verifyKey,
		verifyTime,
	)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(messageDetails.UnverifiedBody)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message body")
	}

	if verifyKey != nil {
		processSignatureExpiration(messageDetails, verifyTime)
		err = verifyDetailsSignature(messageDetails, verifyKey)
	}

	return &PlainMessage{
		Data:     body,
		TextType: !messageDetails.LiteralData.IsBinary,
		Filename: messageDetails.LiteralData.FileName,
		Time:     messageDetails.LiteralData.Time,
	}, err
}

// Core for decryption+verification (all) functions.
func asymmetricDecryptStream(
	encryptedIO io.Reader,
	privateKey *KeyRing,
	verifyKey *KeyRing,
	verifyTime int64,
) (messageDetails *openpgp.MessageDetails, err error) {
	privKeyEntries := privateKey.entities
	var additionalEntries openpgp.EntityList

	if verifyKey != nil {
		additionalEntries = verifyKey.entities
	}

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	config := &packet.Config{
		Time: func() time.Time {
			if verifyTime == 0 {
				/*
					We default to current time while decrypting and verifying
					but the caller will remove signature expiration errors later on.
					See processSignatureExpiration().
				*/
				return getNow()
			}
			return time.Unix(verifyTime, 0)
		},
	}

	messageDetails, err = openpgp.ReadMessage(encryptedIO, privKeyEntries, nil, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}
	return messageDetails, err
}
