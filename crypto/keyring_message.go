package crypto

import (
	"bytes"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pkg/errors"
)

// Encrypt encrypts a PlainMessage, outputs a PGPMessage.
// If an unlocked private key is also provided it will also sign the message.
// * message    : The plaintext input as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
func (keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error) {
	return asymmetricEncrypt(message, keyRing, privateKey, false, nil)
}

// EncryptWithContext encrypts a PlainMessage, outputs a PGPMessage.
// If an unlocked private key is also provided it will also sign the message.
// * message    : The plaintext input as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
// * signingContext : (optional) the context for the signature.
func (keyRing *KeyRing) EncryptWithContext(message *PlainMessage, privateKey *KeyRing, signingContext *SigningContext) (*PGPMessage, error) {
	return asymmetricEncrypt(message, keyRing, privateKey, false, signingContext)
}

// EncryptWithCompression encrypts with compression support a PlainMessage to PGPMessage using public/private keys.
// * message : The plain data as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
// * output  : The encrypted data as PGPMessage.
func (keyRing *KeyRing) EncryptWithCompression(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error) {
	return asymmetricEncrypt(message, keyRing, privateKey, true, nil)
}

// EncryptWithContextAndCompression encrypts with compression support a PlainMessage to PGPMessage using public/private keys.
// * message : The plain data as a PlainMessage.
// * privateKey : (optional) an unlocked private keyring to include signature in the message.
// * signingContext : (optional) the context for the signature.
// * output  : The encrypted data as PGPMessage.
func (keyRing *KeyRing) EncryptWithContextAndCompression(message *PlainMessage, privateKey *KeyRing, signingContext *SigningContext) (*PGPMessage, error) {
	return asymmetricEncrypt(message, keyRing, privateKey, true, signingContext)
}

// Decrypt decrypts encrypted string using pgp keys, returning a PlainMessage
// * message    : The encrypted input as a PGPMessage
// * verifyKey  : Public key for signature verification (optional)
// * verifyTime : Time at verification (necessary only if verifyKey is not nil)
// * verificationContext : (optional) the context for the signature verification.
//
// When verifyKey is not provided, then verifyTime should be zero, and
// signature verification will be ignored.
func (keyRing *KeyRing) Decrypt(
	message *PGPMessage, verifyKey *KeyRing, verifyTime int64,
) (*PlainMessage, error) {
	return asymmetricDecrypt(message.NewReader(), keyRing, verifyKey, verifyTime, nil)
}

// DecryptWithContext decrypts encrypted string using pgp keys, returning a PlainMessage
// * message    : The encrypted input as a PGPMessage
// * verifyKey  : Public key for signature verification (optional)
// * verifyTime : Time at verification (necessary only if verifyKey is not nil)
// * verificationContext : (optional) the context for the signature verification.
//
// When verifyKey is not provided, then verifyTime should be zero, and
// signature verification will be ignored.
func (keyRing *KeyRing) DecryptWithContext(
	message *PGPMessage,
	verifyKey *KeyRing,
	verifyTime int64,
	verificationContext *VerificationContext,
) (*PlainMessage, error) {
	return asymmetricDecrypt(message.NewReader(), keyRing, verifyKey, verifyTime, verificationContext)
}

// SignDetached generates and returns a PGPSignature for a given PlainMessage.
func (keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error) {
	return keyRing.SignDetachedWithContext(message, nil)
}

// SignDetachedWithContext generates and returns a PGPSignature for a given PlainMessage.
// If a context is provided, it is added to the signature as notation data
// with the name set in `constants.SignatureContextName`.
func (keyRing *KeyRing) SignDetachedWithContext(message *PlainMessage, context *SigningContext) (*PGPSignature, error) {
	return signMessageDetached(
		keyRing,
		message.NewReader(),
		message.IsBinary(),
		context,
	)
}

// VerifyDetached verifies a PlainMessage with a detached PGPSignature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) error {
	_, err := verifySignature(
		keyRing.entities,
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
		nil,
	)
	return err
}

// VerifyDetachedWithContext verifies a PlainMessage with a detached PGPSignature
// and returns a SignatureVerificationError if fails.
// If a context is provided, it verifies that the signature is valid in the given context, using
// the signature notation with name the name set in `constants.SignatureContextName`.
func (keyRing *KeyRing) VerifyDetachedWithContext(message *PlainMessage, signature *PGPSignature, verifyTime int64, verificationContext *VerificationContext) error {
	_, err := verifySignature(
		keyRing.entities,
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
		verificationContext,
	)
	return err
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
	sigPacket, err := verifySignature(
		keyRing.entities,
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
		nil,
	)
	if err != nil {
		return 0, err
	}
	return sigPacket.CreationTime.Unix(), nil
}

// GetVerifiedSignatureTimestampWithContext verifies a PlainMessage with a detached PGPSignature
// returns the creation time of the signature if it succeeds
// and returns a SignatureVerificationError if fails.
// If a context is provided, it verifies that the signature is valid in the given context, using
// the signature notation with name the name set in `constants.SignatureContextName`.
func (keyRing *KeyRing) GetVerifiedSignatureTimestampWithContext(
	message *PlainMessage,
	signature *PGPSignature,
	verifyTime int64,
	verificationContext *VerificationContext,
) (int64, error) {
	sigPacket, err := verifySignature(
		keyRing.entities,
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
		verificationContext,
	)
	if err != nil {
		return 0, err
	}
	return sigPacket.CreationTime.Unix(), nil
}

// ------ INTERNAL FUNCTIONS -------

// Core for encryption+signature (non-streaming) functions.
func asymmetricEncrypt(
	plainMessage *PlainMessage,
	publicKey, privateKey *KeyRing,
	compress bool,
	signingContext *SigningContext,
) (*PGPMessage, error) {
	var outBuf bytes.Buffer
	var encryptWriter io.WriteCloser
	var err error

	hints := &openpgp.FileHints{
		IsUTF8:   plainMessage.IsUTF8(),
		FileName: plainMessage.Filename,
		ModTime:  plainMessage.getFormattedTime(),
	}

	encryptWriter, err = asymmetricEncryptStream(hints, &outBuf, &outBuf, publicKey, nil, privateKey, compress, signingContext, nil)
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

	return &PGPMessage{outBuf.Bytes()}, nil
}
