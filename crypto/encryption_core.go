package crypto

import (
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/pkg/errors"
)

// pgpSplitWriter type implements the PGPSplitWriter
// interface.
type pgpSplitWriter struct {
	keyPackets        Writer
	ciphertext        Writer
	detachedSignature Writer
}

//  pgpSplitWriter implements the PGPSplitWriter interface

func (mw *pgpSplitWriter) Keys() Writer {
	return mw.keyPackets
}

func (mw *pgpSplitWriter) Write(b []byte) (int, error) {
	return mw.ciphertext.Write(b)
}

func (mw *pgpSplitWriter) Signature() Writer {
	return mw.detachedSignature
}

// NewPGPSplitWriter creates a type that implements the PGPSplitWriter interface
// for encrypting a plaintext where the output PGP packets should be written to the different streams provided.
// Key packets are written to keyPackets whereas the encrypted data packets are written to encPackets.
// The encrypted detached signature data is written to encSigPacket.
func NewPGPSplitWriter(keyPackets Writer, encPackets Writer, encSigPacket Writer) PGPSplitWriter {
	return &pgpSplitWriter{
		keyPackets:        keyPackets,
		ciphertext:        encPackets,
		detachedSignature: encSigPacket,
	}
}

// NewPGPSplitWriterKeyAndData creates a type that implements the PGPSplitWriter interface
// for encrypting a plaintext where the output PGP packets should be written to the different streams provided.
// Key packets are written to keyPackets whereas the encrypted data packets are written to encPackets.
func NewPGPSplitWriterKeyAndData(keyPackets Writer, encPackets Writer) PGPSplitWriter {
	return NewPGPSplitWriter(keyPackets, encPackets, nil)
}

// NewPGPSplitWriterDetachedSignature creates a type that implements the PGPSplitWriter interface
// for encrypting a plaintext where the output PGP messages should be written to the different streams provided.
// The encrypted data message is written to encMessage whereas the encrypted detached signature is written to
// encSigMessage.
func NewPGPSplitWriterDetachedSignature(encMessage Writer, encSigMessage Writer) PGPSplitWriter {
	return NewPGPSplitWriter(nil, encMessage, encSigMessage)
}

// NewPGPSplitWriterFromWriter creates a type that implements the PGPSplitWriter interface
// for encrypting a plaintext where the output PGP messages to the provided Writer.
func NewPGPSplitWriterFromWriter(writer Writer) PGPSplitWriter {
	return NewPGPSplitWriter(writer, writer, nil)
}

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

func (eh *encryptionHandle) prepareEncryptAndSign(
	plainMessageMetadata *LiteralMetadata,
) (hints *openpgp.FileHints, config *packet.Config, signEntities []*openpgp.Entity, err error) {
	hints = &openpgp.FileHints{
		FileName: plainMessageMetadata.Filename(),
		IsUTF8:   eh.IsUTF8,
		ModTime:  time.Unix(plainMessageMetadata.Time(), 0),
	}

	config = eh.profile.EncryptionConfig()
	config.Time = eh.clock

	compressionConfig := eh.selectCompression()
	config.DefaultCompressionAlgo = compressionConfig.DefaultCompressionAlgo
	config.CompressionConfig = compressionConfig.CompressionConfig

	if eh.SigningContext != nil {
		config.SignatureNotations = append(config.SignatureNotations, eh.SigningContext.getNotation())
	}

	if eh.SignKeyRing != nil && len(eh.SignKeyRing.entities) > 0 {
		signEntities, err = eh.SignKeyRing.signingEntities()
		if err != nil {
			return
		}
	}
	return
}

func (eh *encryptionHandle) encryptStream(
	keyPacketWriter Writer,
	dataPacketWriter Writer,
	plainMessageMetadata *LiteralMetadata,
) (plainMessageWriter WriteCloser, err error) {
	var sessionKeyBytes []byte
	var additionalPasswords [][]byte
	if eh.SessionKey != nil {
		sessionKeyBytes = eh.SessionKey.Key
	}
	if eh.Password != nil {
		additionalPasswords = [][]byte{eh.Password}
	}
	hints, config, signers, err := eh.prepareEncryptAndSign(plainMessageMetadata)
	if err != nil {
		return nil, err
	}
	var encryptionTimeOverride *time.Time
	if eh.encryptionTimeOverride != nil {
		encryptionTime := eh.encryptionTimeOverride()
		encryptionTimeOverride = &encryptionTime
	}
	plainMessageWriter, err = openpgp.EncryptWithParams(
		dataPacketWriter,
		eh.Recipients.getEntities(),
		eh.HiddenRecipients.getEntities(),
		&openpgp.EncryptParams{
			KeyWriter:      keyPacketWriter,
			Signers:        signers,
			Hints:          hints,
			SessionKey:     sessionKeyBytes,
			Passwords:      additionalPasswords,
			Config:         config,
			TextSig:        eh.IsUTF8,
			OutsideSig:     eh.ExternalSignature,
			EncryptionTime: encryptionTimeOverride,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return plainMessageWriter, nil
}

func (eh *encryptionHandle) encryptStreamWithPassword(
	keyPacketWriter Writer,
	dataPacketWriter Writer,
	plainMessageMetadata *LiteralMetadata,
) (plainMessageWriter io.WriteCloser, err error) {
	var sessionKeyBytes []byte
	if eh.SessionKey != nil {
		sessionKeyBytes = eh.SessionKey.Key
	}
	hints, config, signers, err := eh.prepareEncryptAndSign(plainMessageMetadata)
	if err != nil {
		return
	}
	plainMessageWriter, err = openpgp.SymmetricallyEncryptWithParams(
		eh.Password,
		dataPacketWriter,
		&openpgp.EncryptParams{
			KeyWriter:  keyPacketWriter,
			Signers:    signers,
			Hints:      hints,
			SessionKey: sessionKeyBytes,
			Config:     config,
			TextSig:    eh.IsUTF8,
			OutsideSig: eh.ExternalSignature,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return plainMessageWriter, nil
}

func (eh *encryptionHandle) encryptStreamWithSessionKey(
	dataPacketWriter Writer,
	plainMessageMetadata *LiteralMetadata,
) (plainMessageWriter WriteCloser, err error) {
	encryptWriter, signWriter, err := eh.encryptStreamWithSessionKeyHelper(
		plainMessageMetadata,
		dataPacketWriter,
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

func (eh *encryptionHandle) encryptStreamWithSessionKeyHelper(
	plainMessageMetadata *LiteralMetadata,
	dataPacketWriter io.Writer,
) (encryptWriter, signWriter io.WriteCloser, err error) {
	hints, config, signers, err := eh.prepareEncryptAndSign(plainMessageMetadata)
	if err != nil {
		return nil, nil, err
	}

	if !eh.SessionKey.v6 {
		config.DefaultCipher, err = eh.SessionKey.GetCipherFunc()
		if err != nil {
			return nil, nil, errors.Wrap(err, "gopenpgp: unable to encrypt with session key")
		}
	}

	encryptWriter, err = packet.SerializeSymmetricallyEncrypted(
		dataPacketWriter,
		config.Cipher(),
		config.AEAD() != nil,
		packet.CipherSuite{Cipher: config.Cipher(), Mode: config.AEAD().Mode()},
		eh.SessionKey.Key,
		config,
	)

	if err != nil {
		return nil, nil, errors.Wrap(err, "gopenpgp: unable to encrypt")
	}

	if algo := config.Compression(); algo != packet.CompressionNone {
		encryptWriter, err = packet.SerializeCompressed(encryptWriter, algo, config.CompressionConfig)
		if err != nil {
			return nil, nil, errors.Wrap(err, "gopenpgp: error in compression")
		}
	}

	if signers != nil {
		signWriter, err = openpgp.SignWithParams(encryptWriter, signers, &openpgp.SignParams{
			Hints:      hints,
			TextSig:    eh.IsUTF8,
			OutsideSig: eh.ExternalSignature,
			Config:     config,
		})
		if err != nil {
			return nil, nil, errors.Wrap(err, "gopenpgp: unable to sign")
		}
	} else {
		encryptWriter, err = packet.SerializeLiteral(
			encryptWriter,
			!plainMessageMetadata.IsUtf8(),
			plainMessageMetadata.Filename(),
			uint32(plainMessageMetadata.Time()),
		)
		if err != nil {
			return nil, nil, errors.Wrap(err, "gopenpgp: unable to serialize")
		}
	}
	return encryptWriter, signWriter, nil
}

type encryptSignDetachedWriter struct {
	ptToCiphertextWriter  WriteCloser
	sigToCiphertextWriter WriteCloser
	ptToEncSigWriter      WriteCloser
	ptWriter              Writer
}

func (w *encryptSignDetachedWriter) Write(b []byte) (int, error) {
	return w.ptWriter.Write(b)
}

func (w *encryptSignDetachedWriter) Close() error {
	if err := w.ptToCiphertextWriter.Close(); err != nil {
		return err
	}
	if err := w.ptToEncSigWriter.Close(); err != nil {
		return err
	}
	return w.sigToCiphertextWriter.Close()
}

// encryptSignDetachedStreamWithSessionKey wraps writers to encrypt a message
// with a session key and produces a detached signature for the plaintext.
func (eh *encryptionHandle) encryptSignDetachedStreamWithSessionKey(
	plainMessageMetadata *LiteralMetadata,
	encryptedSignatureWriter io.Writer,
	encryptedDataWriter io.Writer,
) (io.WriteCloser, error) {
	signKeyRing := eh.SignKeyRing
	eh.SignKeyRing = nil
	defer func() {
		eh.SignKeyRing = signKeyRing
	}()
	// Create a writer to encrypt the message.
	ptToCiphertextWriter, err := eh.encryptStreamWithSessionKey(encryptedDataWriter, plainMessageMetadata)
	if err != nil {
		return nil, err
	}
	// Create a writer to encrypt the signature.
	sigToCiphertextWriter, err := eh.encryptStreamWithSessionKey(encryptedSignatureWriter, nil)
	if err != nil {
		return nil, err
	}
	// Create a writer to sign the message.
	ptToEncSigWriter, err := signMessageDetachedWriter(
		signKeyRing,
		sigToCiphertextWriter,
		eh.IsUTF8,
		eh.SigningContext,
		eh.clock,
		eh.profile.EncryptionConfig(),
	)
	if err != nil {
		return nil, err
	}

	// Return a wrapped plaintext writer that writes encrypted data and the encrypted signature.
	return &encryptSignDetachedWriter{
		ptToCiphertextWriter:  ptToCiphertextWriter,
		sigToCiphertextWriter: sigToCiphertextWriter,
		ptToEncSigWriter:      ptToEncSigWriter,
		ptWriter:              io.MultiWriter(ptToCiphertextWriter, ptToEncSigWriter),
	}, nil
}

func (eh *encryptionHandle) encryptSignDetachedStreamToRecipients(
	plainMessageMetadata *LiteralMetadata,
	encryptedSignatureWriter io.Writer,
	encryptedDataWriter io.Writer,
	keyPacketWriter io.Writer,
) (plaintextWriter io.WriteCloser, err error) {
	configInput := eh.profile.EncryptionConfig()
	configInput.Time = NewConstantClock(eh.clock().Unix())
	// Generate a session key for encryption.
	if eh.SessionKey == nil {
		eh.SessionKey, err = generateSessionKey(configInput)
		if err != nil {
			return nil, err
		}
		defer func() {
			eh.SessionKey.Clear()
			eh.SessionKey = nil
		}()
	}
	if keyPacketWriter == nil {
		// If no separate keyPacketWriter is given, write the key packets
		// as prefix to the encrypted data and encrypted signature.
		keyPacketWriter = io.MultiWriter(encryptedDataWriter, encryptedSignatureWriter)
	}

	encryptionTimeOverride := configInput.Now()
	if eh.encryptionTimeOverride != nil {
		encryptionTimeOverride = eh.encryptionTimeOverride()
	}
	if eh.Recipients != nil || eh.HiddenRecipients != nil {
		// Encrypt the session key to the different recipients.
		if err = encryptSessionKeyToWriter(
			eh.Recipients,
			eh.HiddenRecipients,
			eh.SessionKey,
			keyPacketWriter,
			encryptionTimeOverride,
			configInput,
		); err != nil {
			return nil, err
		}
	}
	if eh.Password != nil {
		// If not recipients present use the provided password
		if err = encryptSessionKeyWithPasswordToWriter(
			eh.Password,
			eh.SessionKey,
			keyPacketWriter,
			configInput,
		); err != nil {
			return nil, err
		}
	}
	if eh.Password == nil && eh.Recipients == nil && eh.HiddenRecipients == nil {
		return nil, errors.New("openpgp: no key material to encrypt")
	}

	// Use the session key to encrypt message + signature of the message.
	plaintextWriter, err = eh.encryptSignDetachedStreamWithSessionKey(
		plainMessageMetadata,
		encryptedSignatureWriter,
		encryptedDataWriter,
	)
	if err != nil {
		return nil, err
	}
	return plaintextWriter, err
}

func (eh *encryptionHandle) selectCompression() (config *packet.Config) {
	config = &packet.Config{}
	switch eh.Compression {
	case constants.DefaultCompression:
		config = eh.profile.CompressionConfig()
	case constants.ZIPCompression:
		config.DefaultCompressionAlgo = packet.CompressionZIP
		config.CompressionConfig = &packet.CompressionConfig{
			Level: 6,
		}
	case constants.ZLIBCompression:
		config.DefaultCompressionAlgo = packet.CompressionZLIB
		config.CompressionConfig = &packet.CompressionConfig{
			Level: 6,
		}
	}
	return config
}
