package crypto

import (
	"bytes"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp"
	"github.com/ProtonMail/go-crypto/v2/openpgp/armor"
	"github.com/ProtonMail/go-crypto/v2/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
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

func (sh *signatureHandle) SigningWriter(outputWriter Writer, encoding PGPEncoding) (messageWriter WriteCloser, err error) {
	var armorWriter WriteCloser
	armorOutput := encoding.armorOutput()
	if armorOutput {
		var err error
		header := constants.PGPMessageHeader
		if sh.Detached {
			header = constants.PGPSignatureHeader
			// Append checksum for GnuPG detached signature compatibility
			armorWriter, err = armor.EncodeWithChecksumOption(outputWriter, header, sh.ArmorHeaders, true)
		} else {
			armorWriter, err = armor.Encode(outputWriter, header, sh.ArmorHeaders)
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
	if armorOutput {
		// Ensure that close is called on the armor writer for the armor suffix
		messageWriter = &armoredWriteCloser{
			armorWriter:   armorWriter,
			messageWriter: messageWriter,
		}
	}
	return
}

func (sh *signatureHandle) Sign(message []byte, encoding PGPEncoding) ([]byte, error) {
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

func (sh *signatureHandle) SignCleartext(message []byte) ([]byte, error) {
	return sh.signCleartext(message)
}

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
	for _, entity := range sh.SignKeyRing.entities {
		if entity.PrivateKey != nil && !entity.PrivateKey.Encrypted {
			privateKeys = append(privateKeys, entity.PrivateKey)
		}
	}
	writer, err := clearsign.EncodeMulti(&buffer, privateKeys, config, sh.ArmorHeaders)
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
	signEntity, err := sh.SignKeyRing.getSigningEntity()
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
	return openpgp.SignWithParams(messageWriter, []*openpgp.Entity{signEntity}, &openpgp.SignParams{
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

	signEntity, err := signKeyRing.getSigningEntity()
	if err != nil {
		return nil, err
	}

	if context != nil {
		config.SignatureNotations = append(config.SignatureNotations, context.getNotation())
	}

	ptWriter, err = openpgp.DetachSignWriter(outputWriter, []*openpgp.Entity{signEntity}, isUTF8, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in signing")
	}
	return ptWriter, nil
}
