package crypto

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
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
	// If nil, no signature is included.
	SignKeyRing *KeyRing
	// SigningContext provides a signing context for the signature in the message.
	// SignKeyRing has to be set if a SigningContext is provided.
	SigningContext *SigningContext
	// ArmorHeaders provides armor headers if the message is armored.
	// Only considered if Armored is set to true.
	ArmorHeaders map[string]string
	// Compression indicates if the plaintext should be compressed before encryption.
	// constants.NoCompression: none, constants.DefaultCompression: profile default
	// constants.ZIPCompression: zip, constants.ZLIBCompression: zlib
	Compression int8
	// DetachedSignature indicates if a separate encrypted detached signature
	// should be created
	DetachedSignature bool
	IsUTF8            bool
	// ExternalSignature allows to include an external signature into
	// the encrypted message.
	ExternalSignature []byte
	profile           EncryptionProfile

	encryptionTimeOverride Clock
	clock                  Clock
}

// --- Default decryption handle to build from

func defaultEncryptionHandle(profile EncryptionProfile, clock Clock) *encryptionHandle {
	return &encryptionHandle{
		profile: profile,
		clock:   clock,
	}
}

// --- Implements PGPEncryption interface

// EncryptingWriter returns a wrapper around underlying output Writer,
// such that any write-operation via the wrapper results in a write to an encrypted pgp message.
// If the output Writer is of type PGPSplitWriter, the output can be split to multiple writers
// for different parts of the message. For example to write key packets and encrypted data packets
// to different writers or to write a detached signature separately.
// The encoding argument defines the output encoding, i.e., Bytes or Armored
// The returned pgp message WriteCloser must be closed after the plaintext has been written.
func (eh *encryptionHandle) EncryptingWriter(outputWriter Writer, encoding int8) (messageWriter WriteCloser, err error) {
	pgpSplitWriter := castToPGPSplitWriter(outputWriter)
	if pgpSplitWriter != nil {
		return eh.encryptingWriters(pgpSplitWriter.Keys(), pgpSplitWriter, pgpSplitWriter.Signature(), nil, armorOutput(encoding))
	}
	if eh.DetachedSignature {
		return nil, errors.New("gopenpgp: no pgp split writer provided for the detached signature")
	}
	return eh.encryptingWriters(nil, outputWriter, nil, nil, armorOutput(encoding))
}

// Encrypt encrypts a plaintext message.
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

// EncryptSessionKey encrypts a session key with the encryption handle.
// To encrypt a session key, the handle must contain either recipients or a password.
func (eh *encryptionHandle) EncryptSessionKey(sessionKey *SessionKey) ([]byte, error) {
	config := eh.profile.EncryptionConfig()
	config.Time = NewConstantClock(eh.clock().Unix())
	switch {
	case eh.Password != nil:
		return encryptSessionKeyWithPassword(sessionKey, eh.Password, config)
	case eh.Recipients != nil || eh.HiddenRecipients != nil:
		encryptionTimeOverride := config.Now()
		if eh.encryptionTimeOverride != nil {
			encryptionTimeOverride = eh.encryptionTimeOverride()
		}
		return encryptSessionKey(eh.Recipients, eh.HiddenRecipients, sessionKey, encryptionTimeOverride, config)
	}
	return nil, errors.New("gopenpgp: no password or recipients in encryption handle")
}

// --- Helper methods on encryption handle

func (eh *encryptionHandle) validate() error {
	if eh.Recipients == nil &&
		eh.HiddenRecipients == nil &&
		eh.Password == nil &&
		eh.SessionKey == nil {
		return errors.New("gopenpgp: no encryption key material provided")
	}

	if eh.SignKeyRing == nil && eh.SigningContext != nil {
		return errors.New("gopenpgp: no signing key but signing context provided")
	}

	if eh.SignKeyRing == nil && eh.DetachedSignature {
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

// ClearPrivateParams clears all private key material contained in EncryptionHandle from memory.
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
		return nil, err
	}

	if eh.DetachedSignature && detachedSignature == nil {
		return nil, errors.New("gopenpgp: no output provided for the detached signature")
	}

	if armorOutput {
		// Wrap armored writer
		if eh.ArmorHeaders == nil {
			eh.ArmorHeaders = internal.ArmorHeaders
		}
		armorWriter, err = armor.EncodeWithChecksumOption(data, constants.PGPMessageHeader, eh.ArmorHeaders, false)
		data = armorWriter
		if err != nil {
			return nil, err
		}
		if eh.DetachedSignature {
			armorSigWriter, err = armor.EncodeWithChecksumOption(detachedSignature, constants.PGPMessageHeader, eh.ArmorHeaders, false)
			detachedSignature = armorSigWriter
			if err != nil {
				return nil, err
			}
		}
		if keys != nil {
			return nil, errors.New("gopenpgp: armor is not allowed if key packets are written separately")
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
	switch {
	case eh.Recipients.CountEntities() > 0 || eh.HiddenRecipients.CountEntities() > 0:
		// Encrypt towards recipients
		if !eh.DetachedSignature {
			// Signature is inside the ciphertext.
			messageWriter, err = eh.encryptStream(keys, data, meta)
		} else {
			// Encrypted detached signature separate from the ciphertext.
			messageWriter, err = eh.encryptSignDetachedStreamToRecipients(meta, detachedSignature, data, keys)
		}
	case eh.Password != nil:
		// Encrypt with a password
		if !eh.DetachedSignature {
			messageWriter, err = eh.encryptStreamWithPassword(keys, data, meta)
		} else {
			messageWriter, err = eh.encryptSignDetachedStreamToRecipients(meta, detachedSignature, data, keys)
		}
	case eh.SessionKey != nil:
		// Encrypt towards session key
		if !eh.DetachedSignature {
			messageWriter, err = eh.encryptStreamWithSessionKey(data, meta)
		} else {
			messageWriter, err = eh.encryptSignDetachedStreamWithSessionKey(meta, detachedSignature, data)
		}
	default:
		// No encryption material provided
		err = errors.New("gopenpgp: no encryption key ring, session key, or password provided")
	}
	if err != nil {
		return nil, err
	}
	if armorOutput {
		// Wrap armored writer
		messageWriter = &armoredWriteCloser{
			armorWriter:    armorWriter,
			messageWriter:  messageWriter,
			armorSigWriter: armorSigWriter,
		}
	}
	if eh.IsUTF8 {
		messageWriter = internal.NewUtf8CheckWriteCloser(
			openpgp.NewCanonicalTextWriteCloser(messageWriter),
		)
	}
	return messageWriter, nil
}

func castToPGPSplitWriter(w Writer) PGPSplitWriter {
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
