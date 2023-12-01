package crypto

import (
	"bytes"
	"io"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
	"github.com/pkg/errors"
)

type signatureHandle struct {
	SignKeyRing  *KeyRing
	SignContext  *SigningContext
	IsUTF8       bool
	Detached     bool
	ArmorHeaders map[string]string
	profile      SignProfile
	clock        Clock
}

// --- Default signature handle to build from

func defaultSignatureHandle(profile SignProfile, clock Clock) *signatureHandle {
	return &signatureHandle{
		profile:      profile,
		ArmorHeaders: internal.ArmorHeaders,
		clock:        clock,
	}
}

// --- Implements the signature handle methods

// SigningWriter returns a wrapper around underlying output Writer,
// such that any write-operation via the wrapper results in a write to a detached or inline signature message.
// The encoding argument defines the output encoding, i.e., Bytes or Armored
// Once close is called on the returned WriteCloser the final signature is written to the output.
// Thus, the returned WriteCloser must be closed after the plaintext has been written.
func (sh *signatureHandle) SigningWriter(outputWriter Writer, encoding int8) (messageWriter WriteCloser, err error) {
	var armorWriter WriteCloser
	armorOutput := armorOutput(encoding)
	if armorOutput {
		var err error
		header := constants.PGPMessageHeader
		if sh.Detached {
			header = constants.PGPSignatureHeader
			// Append checksum for GnuPG detached signature compatibility
			armorWriter, err = armor.EncodeWithChecksumOption(outputWriter, header, sh.ArmorHeaders, true)
		} else {
			armorWriter, err = armor.EncodeWithChecksumOption(outputWriter, header, sh.ArmorHeaders, false)
		}
		outputWriter = armorWriter
		if err != nil {
			return nil, err
		}
	}
	if sh.Detached {
		// Detached signature
		messageWriter, err = signMessageDetachedWriter(
			sh.SignKeyRing,
			outputWriter,
			sh.IsUTF8,
			sh.SignContext,
			sh.clock,
			sh.profile.SignConfig(),
		)
	} else {
		// Inline signature
		messageWriter, err = sh.signingWriter(outputWriter, nil)
	}
	if err != nil {
		return nil, err
	}
	if armorOutput {
		// Ensure that close is called on the armor writer for the armor suffix
		messageWriter = &armoredWriteCloser{
			armorWriter:   armorWriter,
			messageWriter: messageWriter,
		}
	}
	if sh.IsUTF8 {
		messageWriter = internal.NewUtf8CheckWriteCloser(
			openpgp.NewCanonicalTextWriteCloser(messageWriter),
		)
	}
	return messageWriter, nil
}

// Sign creates a detached or inline signature from the provided byte slice.
// The encoding argument defines the output encoding, i.e., Bytes or Armored.
func (sh *signatureHandle) Sign(message []byte, encoding int8) ([]byte, error) {
	var writer bytes.Buffer
	ptWriter, err := sh.SigningWriter(&writer, encoding)
	if err != nil {
		return nil, err
	}
	_, err = ptWriter.Write(message)
	if err != nil {
		return nil, err
	}
	err = ptWriter.Close()
	if err != nil {
		return nil, err
	}
	return writer.Bytes(), nil
}

// SignCleartext produces an armored cleartext message according to the specification.
// Returns an armored message even if the PGPSign is not configured for armored output.
func (sh *signatureHandle) SignCleartext(message []byte) ([]byte, error) {
	return sh.signCleartext(message)
}

// ClearPrivateParams clears all secret key material contained in the PGPSign from memory.
func (sh *signatureHandle) ClearPrivateParams() {
	if sh.SignKeyRing != nil {
		sh.SignKeyRing.ClearPrivateParams()
	}
}

// --- Private signature handle logic

func (sh *signatureHandle) validate() error {
	if sh.SignKeyRing == nil {
		return errors.New("gopenpgp: no signing key provided")
	}
	return nil
}

func (sh *signatureHandle) signCleartext(message []byte) ([]byte, error) {
	config := sh.profile.SignConfig()
	config.Time = NewConstantClock(sh.clock().Unix())
	var buffer bytes.Buffer
	var privateKeys []*packet.PrivateKey
	if !utf8.Valid(message) {
		return nil, internal.ErrIncorrectUtf8
	}
	for _, entity := range sh.SignKeyRing.entities {
		key, ok := entity.SigningKey(config.Now(), config)
		if ok &&
			key.PrivateKey != nil &&
			!key.PrivateKey.Encrypted {
			privateKeys = append(privateKeys, key.PrivateKey)
		} else {
			return nil, errors.New("gopenpgp: no signing key found for entity")
		}
	}
	writer, err := clearsign.EncodeMultiWithHeader(&buffer, privateKeys, config, sh.ArmorHeaders)
	if err != nil {
		return nil, err
	}
	_, err = writer.Write(message)
	if err != nil {
		return nil, err
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (sh *signatureHandle) signingWriter(messageWriter Writer, literalData *LiteralMetadata) (WriteCloser, error) {
	config := sh.profile.SignConfig()
	config.Time = NewConstantClock(sh.clock().Unix())
	signers, err := sh.SignKeyRing.signingEntities()
	if err != nil {
		return nil, err
	}
	hints := &openpgp.FileHints{
		FileName: literalData.Filename(),
		IsUTF8:   sh.IsUTF8,
		ModTime:  time.Unix(literalData.Time(), 0),
	}
	if sh.SignContext != nil {
		config.SignatureNotations = append(config.SignatureNotations, sh.SignContext.getNotation())
	}
	return openpgp.SignWithParams(messageWriter, signers, &openpgp.SignParams{
		Hints:   hints,
		TextSig: sh.IsUTF8,
		Config:  config,
	})
}

func signMessageDetachedWriter(
	signKeyRing *KeyRing,
	outputWriter io.Writer,
	isUTF8 bool,
	context *SigningContext,
	clock Clock,
	config *packet.Config,
) (ptWriter io.WriteCloser, err error) {
	config.Time = NewConstantClock(clock().Unix())

	signers, err := signKeyRing.signingEntities()
	if err != nil {
		return nil, err
	}

	if context != nil {
		config.SignatureNotations = append(config.SignatureNotations, context.getNotation())
	}

	ptWriter, err = openpgp.DetachSignWriter(outputWriter, signers, &openpgp.SignParams{
		TextSig: isUTF8,
		Config:  config,
	})
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in signing")
	}
	return ptWriter, nil
}
