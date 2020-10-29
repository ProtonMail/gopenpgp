package crypto

import (
	"bytes"
	"crypto"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// Encrypt encrypts a PlainMessage, outputs a PGPMessage.
// If an unlocked private key is also provided it will also sign the message.
// * message    : The plaintext input as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
func (keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error) {
	encrypted, err := asymmetricEncrypt(message, keyRing, privateKey)
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

// VerifyDetached verifies a PlainMessage with embedded a PGPSignature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) error {
	return verifySignature(
		keyRing.entities,
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
	)
}

// ------ INTERNAL FUNCTIONS -------

// Core for encryption+signature functions.
func asymmetricEncrypt(plainMessage *PlainMessage, publicKey, privateKey *KeyRing) ([]byte, error) {
	var outBuf bytes.Buffer
	var encryptWriter io.WriteCloser
	var signEntity *openpgp.Entity
	var err error

	if privateKey != nil && len(privateKey.entities) > 0 {
		var err error
		signEntity, err = privateKey.getSigningEntity()
		if err != nil {
			return nil, err
		}
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}

	hints := &openpgp.FileHints{
		IsBinary: plainMessage.IsBinary(),
		FileName: plainMessage.Filename,
		ModTime:  plainMessage.getFormattedTime(),
	}

	if plainMessage.IsBinary() {
		encryptWriter, err = openpgp.Encrypt(&outBuf, publicKey.entities, signEntity, hints, config)
	} else {
		encryptWriter, err = openpgp.EncryptText(&outBuf, publicKey.entities, signEntity, hints, config)
	}
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
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

// Core for decryption+verification functions.
func asymmetricDecrypt(
	encryptedIO io.Reader, privateKey *KeyRing, verifyKey *KeyRing, verifyTime int64,
) (message *PlainMessage, err error) {
	privKeyEntries := privateKey.entities
	var additionalEntries openpgp.EntityList

	if verifyKey != nil {
		additionalEntries = verifyKey.entities
	}

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	config := &packet.Config{Time: getTimeGenerator()}

	messageDetails, err := openpgp.ReadMessage(encryptedIO, privKeyEntries, nil, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message")
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
