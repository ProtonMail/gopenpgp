package crypto

import (
	"io"

	"github.com/ProtonMail/go-crypto/v2/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
	"github.com/pkg/errors"
)

// encryptionHandle collects the configuration parameters for encrypting a message.
// Use a encryptionHandleBuilder to create a handle.
type encryptionHandle struct {
	// Recipients contains the public keys to which
	// the message should be encrypted to.
	// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
	// The recipients are included in the intended recipient fingerprint list
	// of the signature, if a signature is present.
	// If nil, set another field for the type of encryption: HiddenRecipients, SessionKey, or Password
	Recipients *KeyRing
	// HiddenRecipients contains the public keys to which
	// the message should be encrypted to.
	// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
	// The hidden recipients are NOT included in the intended recipient fingerprint list
	// of the signature, if a signature is present.
	// If nil, set another field for the type of encryption: Recipients, SessionKey, or Password
	HiddenRecipients *KeyRing
	// SessionKey defines the session key the message should be encrypted with.
	// Triggers session key encryption with the included session key.
	// If nil, set another field for the type of encryption: Recipients, HiddenRecipients, or Password
	SessionKey *SessionKey
	// Password defines a password the message should be encrypted with.
	// Triggers password based encryption with a key derived from the password.
	// If nil, set another field for the type of encryption: Recipients, HiddenRecipients, or SessionKey
	Password []byte
	// SignKeyRing provides an unlocked key ring to include signature in the message.
	// If nil, no signature is inlcuded.
	SignKeyRing *KeyRing
	// SigningContext provides a signing context for the signature in the message.
	// SignKeyRing has to be set if a SigningContext is provided.
	SigningContext *SigningContext
	// DetachedSignature indicates if a separate encrypted detached signature
	// should be created
	DetachedSignature bool
	// ArmorHeaders provides armor headers if the message is armored.
	// Only considered if Armored is set to true.
	ArmorHeaders map[string]string
	// Compression indicates if the plaintext should be compressed before encryption.
	// If set true, the message is compressed before encryption.
	Compression bool
	IsUTF8      bool
	profile     EncryptionProfile
	clock       Clock
}

// --- Default decryption handle to build from

func defaultEncryptionHandle(profile EncryptionProfile, clock Clock) *encryptionHandle {
	return &encryptionHandle{
		profile: profile,
		clock:   clock,
	}
}

// --- Implements PGPEncryption interface

// EncryptingWriter returns a wrapper around underlying outputWriter io.Writer, such that any write-operation
// via the wrapper results in a write to an encrypted PGP message.
// The returned PGP message WriteCloser must be closed after the plaintext has been written.
func (eh *encryptionHandle) EncryptingWriter(outputWriter Writer, encoding PGPEncoding) (messageWriter WriteCloser, err error) {
	pgpMessageWriter := isPGPMessageWriter(outputWriter)
	if pgpMessageWriter != nil {
		return eh.encryptingWriters(pgpMessageWriter.Keys(), pgpMessageWriter, pgpMessageWriter.Signature(), nil, encoding.armorOutput())
	}
	if eh.DetachedSignature {
		return nil, errors.New("gopenpgp: no pgp split writer provided for the detached signature")
	}
	return eh.encryptingWriters(nil, outputWriter, nil, nil, encoding.armorOutput())
}

// Encrypt encrypts a binary message, and outputs a PGPMessage.
func (eh *encryptionHandle) Encrypt(message []byte) (*PGPMessage, error) {
	pgpMessageBuffer := NewPGPMessageBuffer()
	// Enforce that for a PGPMessage struct the output should not be armored.
	encryptingWriter, err := eh.EncryptingWriter(pgpMessageBuffer, Bytes)
	if err != nil {
		return nil, err
	}
	_, err = encryptingWriter.Write(message)
	if err != nil {
		return nil, err
	}
	err = encryptingWriter.Close()
	if err != nil {
		return nil, err
	}
	return pgpMessageBuffer.PGPMessage(), nil
}

func (eh *encryptionHandle) EncryptSessionKey(sessionKey *SessionKey) ([]byte, error) {
	config := eh.profile.EncryptionConfig()
	config.Time = NewConstantClock(eh.clock().Unix())
	if eh.Password != nil {
		return encryptSessionKeyWithPassword(sessionKey, eh.Password, config)
	} else if eh.Recipients != nil || eh.HiddenRecipients != nil {
		return encryptSessionKey(eh.Recipients, eh.HiddenRecipients, sessionKey, config)
	} else {
		return nil, errors.New("gopenpgp: no password or recipients in encryption handle")
	}
}

// --- Helper methods on encryption handle

func (dp *encryptionHandle) validate() error {
	keyMaterialPresent := false
	if dp.Recipients != nil || dp.HiddenRecipients != nil {
		keyMaterialPresent = true
	}
	if dp.Password != nil {
		if keyMaterialPresent {
			return errors.New("gopenpgp: more than one encryption key material provided")
		}
		keyMaterialPresent = true
	}
	if dp.SessionKey != nil {
		keyMaterialPresent = true
	}
	if !keyMaterialPresent {
		return errors.New("gopenpgp: no encryption key material provided")
	}

	if dp.SignKeyRing == nil && dp.SigningContext != nil {
		return errors.New("gopenpgp: no signing key but signing context provided")
	}

	if dp.SignKeyRing == nil && dp.DetachedSignature {
		return errors.New("gopenpgp: no signing key provided for detached signature")
	}
	return nil
}

type armoredWriteCloser struct {
	armorWriter    WriteCloser
	messageWriter  WriteCloser
	armorSigWriter WriteCloser
}

func (w *armoredWriteCloser) Write(b []byte) (int, error) {
	return w.messageWriter.Write(b)
}

func (w *armoredWriteCloser) Close() error {
	if err := w.messageWriter.Close(); err != nil {
		return err
	}
	if w.armorSigWriter != nil {
		if err := w.armorSigWriter.Close(); err != nil {
			return err
		}
	}
	return w.armorWriter.Close()
}

func (eh *encryptionHandle) ClearPrivateParams() {
	if eh.SignKeyRing != nil {
		eh.SignKeyRing.ClearPrivateParams()
	}
	if eh.SessionKey != nil {
		eh.SessionKey.Clear()
	}
	if eh.Password != nil {
		clearMem(eh.Password)
	}
}

func (eh *encryptionHandle) encryptingWriters(keys, data, detachedSignature Writer, meta *LiteralMetadata, armorOutput bool) (messageWriter WriteCloser, err error) {
	var armorWriter WriteCloser
	var armorSigWriter WriteCloser
	err = eh.validate()
	if err != nil {
		return
	}

	if eh.DetachedSignature && detachedSignature == nil {
		err = errors.New("gopenpgp: no output provided for the detached signature")
		return
	}

	if armorOutput {
		// Wrap armored writer
		if eh.ArmorHeaders == nil {
			eh.ArmorHeaders = internal.ArmorHeaders
		}
		armorWriter, err = armor.Encode(data, constants.PGPMessageHeader, eh.ArmorHeaders)
		data = armorWriter
		if err != nil {
			return
		}
		if eh.DetachedSignature {
			armorSigWriter, err = armor.Encode(detachedSignature, constants.PGPMessageHeader, eh.ArmorHeaders)
			detachedSignature = armorSigWriter
			if err != nil {
				return
			}
		}
		if keys != nil {
			err = errors.New("gopenpgp: armor is not allowed if key packets are written separately")
			return
		}
	}
	if keys == nil {
		// No writer for key packets provided,
		// write the key packets at the beginning of each message.
		if eh.DetachedSignature {
			keys = io.MultiWriter(data, detachedSignature)
		} else {
			keys = data
		}
	}
	if eh.Recipients.CountEntities() > 0 ||
		eh.HiddenRecipients.CountEntities() > 0 {
		// Encrypt towards recipients
		if !eh.DetachedSignature {
			// Signature is inside the ciphertext.
			messageWriter, err = eh.encryptStream(keys, data, meta)
		} else {
			// Encrypted detached signature separate from the ciphertext.
			messageWriter, err = eh.encryptSignDetachedStreamToRecipients(meta, detachedSignature, data, keys)
		}

	} else if eh.Password != nil {
		// Encrypt with a password
		if !eh.DetachedSignature {
			messageWriter, err = eh.encryptStreamWithPassword(keys, data, meta)
		} else {
			messageWriter, err = eh.encryptSignDetachedStreamToRecipients(meta, detachedSignature, data, keys)
		}
	} else if eh.SessionKey != nil {
		// Encrypt towards session key
		if !eh.DetachedSignature {
			messageWriter, err = eh.encryptStreamWithSessionKey(data, meta)
		} else {
			messageWriter, err = eh.encryptSignDetachedStreamWithSessionKey(meta, detachedSignature, data)
		}
	} else {
		// No encryption material provided
		err = errors.New("gopenpgp: no encryption key ring, session key, or password provided")
	}

	if armorOutput {
		// Wrap armored writer
		messageWriter = &armoredWriteCloser{
			armorWriter:    armorWriter,
			messageWriter:  messageWriter,
			armorSigWriter: armorSigWriter,
		}
	}
	return
}

func isPGPMessageWriter(w Writer) PGPSplitWriter {
	v, ok := interface{}(w).(PGPSplitWriter)
	if ok {
		return v
	}
	v, ok = interface{}(&w).(PGPSplitWriter)
	if ok {
		return v
	}
	return nil
}
