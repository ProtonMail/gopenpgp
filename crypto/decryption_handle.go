package crypto

import (
	"bytes"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/pkg/errors"
)

// decryptionHandle collects the configuration parameters to decrypt a pgp message.
// The fields in the struct allow to customize the decryption.
type decryptionHandle struct {
	// DecryptionKeyRing provides the secret keys for decrypting the pgp message.
	// Assumes the the message was encrypted towards a public key in DecryptionKeyRing.
	// If nil, set another field for the type of decryption: SessionKey or Password
	DecryptionKeyRing *KeyRing
	// SessionKey provides a session key for decrypting the pgp message.
	// Assumes the the message was encrypted with session key provided.
	// If nil, set another field for the type of decryption: DecryptionKeyRing or Password
	SessionKey *SessionKey
	// Password provides a password for decrypting the pgp message.
	// Assumes the the message was encrypted with a key derived from the password.
	// If nil, set another field for the type of decryption: DecryptionKeyRing or SessionKey
	Password []byte
	// VerifyKeyRing provides a set of public keys to verify the signature of the pgp message, if any.
	// If nil, the signatures are not verified.
	VerifyKeyRing *KeyRing
	// VerificationContext provides a verification context for the signature of the pgp message, if any.
	// Only considered if VerifyKeyRing is not nil.
	VerificationContext *VerificationContext
	// DisableIntendedRecipients indicates if the signature verification should not check if
	// the decryption key matches the intended recipients of the message.
	// If disabled, the decryption throws no error in a non-matching case.
	DisableIntendedRecipients bool
	// Armored indicates if the pgp message input to the decryption function is armored or not.
	// In the default case, it assumes that the message is not armored.
	Armored                bool
	DisableVerifyTimeCheck bool
	RetrieveSessionKey     bool
	clock                  Clock
}

// --- Default decryption handle to build from

func defaultDecryptionHandle(clock Clock) *decryptionHandle {
	return &decryptionHandle{
		clock: clock,
	}
}

// --- Implements PGPDecryption interface

// DecryptingReader returns a wrapper around underlying encryptedMessage Reader, such that any read-operation
// via the wrapper results in a decrypted read of the message.
// The returned reader PlainMessageReader offers a method to verify signatures after the message has been read.
// Decryption parameters are configured via the DecryptionParams struct.
func (dh *decryptionHandle) DecryptingReader(encryptedMessage Reader) (plainMessageReader *VerifyDataReader, err error) {
	err = dh.validate()
	if err != nil {
		return
	}
	pgpSplitReader := isPGPSplitReader(encryptedMessage)
	if pgpSplitReader != nil {
		return dh.decryptingReader(pgpSplitReader, pgpSplitReader.Signature())
	}
	return dh.decryptingReader(encryptedMessage, nil)
}

// Decrypt decrypts a pgp message as byte slice, and outputs the plaintext,
// but does not return an error if signature verification fails.
// Instead, the output struct contains a potential signature error.
func (dh *decryptionHandle) Decrypt(pgpMessage []byte) (*VerifiedDataResult, error) {
	messageReader := bytes.NewReader(pgpMessage)
	plainMessageReader, err := dh.DecryptingReader(messageReader)
	if err != nil {
		return nil, err
	}
	return plainMessageReader.ReadAllAndVerifySignature()
}

func (dh *decryptionHandle) DecryptDetached(pgpMessage []byte, encryptedDetachedSig []byte) (*VerifiedDataResult, error) {
	reader := &pgpSplitReader{
		encMessage: bytes.NewReader(pgpMessage),
	}
	if encryptedDetachedSig != nil {
		reader.encSignature = bytes.NewReader(encryptedDetachedSig)
	}
	verifier, err := dh.DecryptingReader(reader)
	if err != nil {
		return nil, err
	}
	return verifier.ReadAllAndVerifySignature()
}

func (dh *decryptionHandle) DecryptSessionKey(keyPackets []byte) (*SessionKey, error) {
	if dh.Password != nil {
		return decryptSessionKeyWithPassword(keyPackets, dh.Password)
	} else if dh.DecryptionKeyRing != nil {
		return decryptSessionKey(dh.DecryptionKeyRing, keyPackets)
	} else {
		return nil, errors.New("gopenpgp: no decryption key or password provided")
	}
}

func (dh *decryptionHandle) ArmoredInput() bool {
	return dh.Armored
}

func (dh *decryptionHandle) ClearPrivateParams() {
	if dh.DecryptionKeyRing != nil {
		dh.DecryptionKeyRing.ClearPrivateParams()
	}
	if dh.SessionKey != nil {
		dh.SessionKey.Clear()
	}
	if dh.Password != nil {
		clearMem(dh.Password)
	}
}

func (dh *decryptionHandle) validate() error {
	keyMaterialPresent := false
	if dh.DecryptionKeyRing != nil {
		keyMaterialPresent = true
	}
	if dh.Password != nil {
		if keyMaterialPresent {
			return errors.New("openpgp: more than one decryption key material provided")
		}
		keyMaterialPresent = true
	}
	if dh.SessionKey != nil {
		keyMaterialPresent = true
	}
	if !keyMaterialPresent {
		return errors.New("openpgp: no decryption key material provided")
	}
	return nil
}

func (dh *decryptionHandle) decryptingReader(encryptedMessage Reader, encryptedSignature Reader) (plainMessageReader *VerifyDataReader, err error) {
	err = dh.validate()
	if err != nil {
		return
	}
	var armoredBlock *armor.Block
	if dh.Armored {
		// Wrap encryptedMessage with decode armor reader.
		armoredBlock, err = armor.Decode(encryptedMessage)
		if err != nil {
			err = errors.Wrap(err, "gopenpgp: unarmor failed for pgp message")
			return
		}
		encryptedMessage = armoredBlock.Body
	}
	if dh.Armored && encryptedSignature != nil {
		// Wrap encryptedSignature with decode armor reader.
		armoredBlock, err = armor.Decode(encryptedSignature)
		if err != nil {
			err = errors.Wrap(err, "gopenpgp: unarmor failed for pgp encrypted signature message")
			return
		}
		encryptedSignature = armoredBlock.Body
	}

	if dh.SessionKey != nil {
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

	} else if dh.Password != nil {
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
