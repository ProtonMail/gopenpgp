package crypto

import (
	"bytes"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/internal"

	"github.com/pkg/errors"
)

// decryptionHandle collects the configuration parameters to decrypt a pgp message.
// The fields in the struct allow to customize the decryption.
type decryptionHandle struct {
	// DecryptionKeyRing provides the secret keys for decrypting the pgp message.
	// Assumes the the message was encrypted towards a public key in DecryptionKeyRing.
	// If nil, set another field for the type of decryption: SessionKey or Password
	DecryptionKeyRing *KeyRing
	// SessionKeys provides one or more session keys for decrypting the pgp message.
	// Assumes the the message was encrypted with one of the session keys provided.
	// If nil, set another field for the type of decryption: DecryptionKeyRing or Password
	SessionKeys []*SessionKey
	// Passwords provides passwords for decrypting the pgp message.
	// Assumes the the message was encrypted with on of the keys derived from the passwords.
	// If nil, set another field for the type of decryption: DecryptionKeyRing or SessionKey
	Passwords [][]byte
	// VerifyKeyRing provides a set of public keys to verify the signature of the pgp message, if any.
	// If nil, the signatures are not verified.
	VerifyKeyRing *KeyRing
	// VerificationContext provides a verification context for the signature of the pgp message, if any.
	// Only considered if VerifyKeyRing is not nil.
	VerificationContext *VerificationContext
	// DisableIntendedRecipients indicates if the signature verification should not check if
	// the decryption key matches the intended recipients of the message.
	// If disabled, the decryption throws no error in a non-matching case.
	DisableIntendedRecipients    bool
	DisableVerifyTimeCheck       bool
	DisableStrictMessageParsing  bool
	DisableAutomaticTextSanitize bool
	RetrieveSessionKey           bool
	IsUTF8                       bool
	clock                        Clock
	profile                      EncryptionProfile
}

// --- Default decryption handle to build from

func defaultDecryptionHandle(profile EncryptionProfile, clock Clock) *decryptionHandle {
	return &decryptionHandle{
		clock:   clock,
		profile: profile,
	}
}

// --- Implements PGPDecryption interface

// DecryptingReader returns a wrapper around underlying encryptedMessage Reader, such that any read-operation
// via the wrapper results in a decrypted read of the message.
// The returned reader PlainMessageReader offers a method to verify signatures after the message has been read.
// Decryption parameters are configured via the DecryptionParams struct.
func (dh *decryptionHandle) DecryptingReader(encryptedMessage Reader, encoding int8) (plainMessageReader *VerifyDataReader, err error) {
	err = dh.validate()
	if err != nil {
		return
	}
	pgpSplitReader := isPGPSplitReader(encryptedMessage)
	if pgpSplitReader != nil {
		return dh.decryptingReader(pgpSplitReader, pgpSplitReader.Signature(), encoding)
	}
	return dh.decryptingReader(encryptedMessage, nil, encoding)
}

// Decrypt decrypts a pgp message as byte slice, and outputs the plaintext,
// but does not return an error if signature verification fails.
// Instead, the output struct contains a potential signature error.
func (dh *decryptionHandle) Decrypt(pgpMessage []byte, encoding int8) (*VerifiedDataResult, error) {
	messageReader := bytes.NewReader(pgpMessage)
	plainMessageReader, err := dh.DecryptingReader(messageReader, encoding)
	if err != nil {
		return nil, err
	}
	return plainMessageReader.ReadAllAndVerifySignature()
}

func (dh *decryptionHandle) DecryptDetached(pgpMessage []byte, encryptedDetachedSig []byte, encoding int8) (*VerifiedDataResult, error) {
	reader := &pgpSplitReader{
		encMessage: bytes.NewReader(pgpMessage),
	}
	if encryptedDetachedSig != nil {
		reader.encSignature = bytes.NewReader(encryptedDetachedSig)
	}
	verifier, err := dh.DecryptingReader(reader, encoding)
	if err != nil {
		return nil, err
	}
	return verifier.ReadAllAndVerifySignature()
}

func (dh *decryptionHandle) DecryptSessionKey(keyPackets []byte) (sk *SessionKey, err error) {
	if len(dh.Passwords) > 0 {
		for _, passwordCandidate := range dh.Passwords {
			sk, err = decryptSessionKeyWithPassword(keyPackets, passwordCandidate)
			if err == nil {
				return
			}
		}
		return
	} else if dh.DecryptionKeyRing != nil {
		return decryptSessionKey(dh.DecryptionKeyRing, keyPackets)
	} else {
		return nil, errors.New("gopenpgp: no decryption key or password provided")
	}
}

func (dh *decryptionHandle) ClearPrivateParams() {
	if dh.DecryptionKeyRing != nil {
		dh.DecryptionKeyRing.ClearPrivateParams()
	}
	if len(dh.SessionKeys) > 0 {
		for _, sk := range dh.SessionKeys {
			sk.Clear()
		}
	}
	if len(dh.Passwords) > 0 {
		for _, password := range dh.Passwords {
			clearMem(password)
		}
	}
}

func (dh *decryptionHandle) validate() error {
	keyMaterialPresent := false
	if dh.DecryptionKeyRing != nil {
		keyMaterialPresent = true
	}
	if len(dh.Passwords) > 0 {
		if keyMaterialPresent {
			return errors.New("openpgp: more than one decryption key material provided")
		}
		keyMaterialPresent = true
	}
	if len(dh.SessionKeys) > 0 {
		keyMaterialPresent = true
	}
	if !keyMaterialPresent {
		return errors.New("openpgp: no decryption key material provided")
	}
	return nil
}

func (dh *decryptionHandle) decryptingReader(encryptedMessage Reader, encryptedSignature Reader, encoding int8) (plainMessageReader *VerifyDataReader, err error) {
	err = dh.validate()
	if err != nil {
		return
	}
	var armored bool
	encryptedMessage, armored = unarmorInput(encoding, encryptedMessage)
	var armoredBlock *armor.Block
	if armored {
		// Wrap encryptedMessage with decode armor reader.
		armoredBlock, err = armor.Decode(encryptedMessage)
		if err != nil {
			err = errors.Wrap(err, "gopenpgp: unarmor failed for pgp message")
			return
		}
		encryptedMessage = armoredBlock.Body
	}
	if encryptedSignature != nil {
		encryptedSignature, armored = unarmorInput(encoding, encryptedSignature)
		if armored {
			// Wrap encryptedSignature with decode armor reader.
			armoredBlock, err = armor.Decode(encryptedSignature)
			if err != nil {
				err = errors.Wrap(err, "gopenpgp: unarmor failed for pgp encrypted signature message")
				return
			}
			encryptedSignature = armoredBlock.Body
		}
	}

	if len(dh.SessionKeys) > 0 {
		// Decrypt with session key.
		if encryptedSignature != nil {
			plainMessageReader, err = dh.decryptStreamAndVerifyDetached(encryptedMessage, encryptedSignature)
		} else {
			plainMessageReader, err = dh.decryptStreamWithSession(encryptedMessage)
		}
	} else if dh.DecryptionKeyRing != nil {
		// Decrypt with keyring.
		if encryptedSignature != nil {
			plainMessageReader, err = dh.decryptStreamAndVerifyDetached(encryptedMessage, encryptedSignature)
		} else {
			plainMessageReader, err = dh.decryptStream(encryptedMessage)
		}

	} else if len(dh.Passwords) > 0 {
		// Decrypt with password.
		if encryptedSignature != nil {
			plainMessageReader, err = dh.decryptStreamAndVerifyDetached(encryptedMessage, encryptedSignature)
		} else {
			plainMessageReader, err = dh.decryptStream(encryptedMessage)
		}
	} else {
		// No decryption material provided.
		err = errors.New("gopenpgp: no decryption key ring, session key, or password provided")
	}
	if err != nil {
		return nil, err
	}
	if dh.IsUTF8 {
		plainMessageReader.internalReader = internal.NewSanitizeReader(plainMessageReader.internalReader)
	}
	return
}

func isPGPSplitReader(w Reader) PGPSplitReader {
	v, ok := interface{}(w).(PGPSplitReader)
	if ok {
		return v
	}
	v, ok = interface{}(&w).(PGPSplitReader)
	if ok {
		return v
	}
	return nil
}
