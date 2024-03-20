package crypto

import (
	"bytes"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
	"github.com/pkg/errors"
)

type verifyHandle struct {
	VerifyKeyRing                *KeyRing
	VerificationContext          *VerificationContext
	DisableVerifyTimeCheck       bool
	DisableStrictMessageParsing  bool
	DisableAutomaticTextSanitize bool
	IsUTF8                       bool
	clock                        Clock
	profile                      SignProfile
}

// --- Default verification handle to build from

func defaultVerifyHandle(profile SignProfile, clock Clock) *verifyHandle {
	return &verifyHandle{
		clock:   clock,
		profile: profile,
	}
}

// --- Implements VerifyHandle functions

// VerifyingReader wraps a reader with a signature verify reader.
// Once all data is read from the returned verify reader, the signature can be verified
// with (VerifyDataReader).VerifySignature().
// Note that an error is only returned if it is not a signature error.
// The encoding indicates if the input signature message should be unarmored or not,
// i.e., Bytes/Armor/Auto where Auto tries to detect it automatically.
// If detachedData is nil, signatureMessage is treated as an inline signature message.
// Thus, it is expected that signatureMessage contains the data to be verified.
// If detachedData is not nil, signatureMessage must contain a detached signature,
// which is verified against the detachedData.
func (vh *verifyHandle) VerifyingReader(detachedData, signatureMessage Reader, encoding int8) (reader *VerifyDataReader, err error) {
	var armored bool
	signatureMessage, armored = unarmorInput(encoding, signatureMessage)
	if armored {
		// Wrap with decode armor reader.
		armoredBlock, err := armor.Decode(signatureMessage)
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unarmor failed")
		}
		signatureMessage = armoredBlock.Body
	}
	if detachedData != nil {
		if vh.IsUTF8 {
			detachedData = openpgp.NewCanonicalTextReader(detachedData)
		}
		reader, err = vh.verifyingDetachedReader(detachedData, signatureMessage)
	} else {
		reader, err = vh.verifyingReader(signatureMessage)
		if err == nil && vh.IsUTF8 {
			reader.internalReader = internal.NewSanitizeReader(reader.internalReader)
		}
	}
	return
}

// VerifyDetached verifies a detached signature pgp message
// and returns a VerifyResult. The VerifyResult can be checked for failure
// and allows access to information about the signatures.
// Note that an error is only returned if it is not a signature error.
// The encoding indicates if the input signature message should be unarmored or not,
// i.e., Bytes/Armor/Auto where Auto tries to detect it automatically.
func (vh *verifyHandle) VerifyDetached(data, signature []byte, encoding int8) (verifyResult *VerifyResult, err error) {
	signatureMessageReader := bytes.NewReader(signature)
	detachedDataReader := bytes.NewReader(data)
	ptReader, err := vh.VerifyingReader(detachedDataReader, signatureMessageReader, encoding)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: verifying signature failed")
	}
	_, err = io.Copy(io.Discard, ptReader)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: reading data to verify signature failed")
	}
	return ptReader.VerifySignature()
}

// VerifyInline verifies an inline signed pgp message
// and returns a VerifiedDataResult. The VerifiedDataResult can be checked for failure,
// allows access to information about the signatures, and includes the plain message.
// Note that an error is only returned if it is not a signature error.
// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
// where Auto tries to detect it automatically.
func (vh *verifyHandle) VerifyInline(message []byte, encoding int8) (verifyDataResult *VerifiedDataResult, err error) {
	var ptReader *VerifyDataReader
	messageReader := bytes.NewReader(message)
	ptReader, err = vh.VerifyingReader(nil, messageReader, encoding)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: verifying signature failed")
	}
	data, err := ptReader.ReadAll()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: reading data to verify signature failed")
	}
	verifyResult, err := ptReader.VerifySignature()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: verifying signature failed")
	}
	verifyDataResult = &VerifiedDataResult{
		data:         data,
		metadata:     ptReader.GetMetadata(),
		VerifyResult: *verifyResult,
	}
	return
}

// VerifyCleartext verifies an armored cleartext message and returns a VerifyCleartextResult.
// The VerifyCleartextResult can be checked for failure and allows access the contained message.
// Note that an error is only returned if it is not a signature error.
func (vh *verifyHandle) VerifyCleartext(cleartext []byte) (*VerifyCleartextResult, error) {
	return vh.verifyCleartext(cleartext)
}

// --- Private logic functions

func (vh *verifyHandle) validate() error {
	if vh.VerifyKeyRing == nil {
		return errors.New("gopenpgp: no verification key provided")
	}
	return nil
}

// verifyDetachedSignature verifies if a detached signature is valid with the entity list.
func (vh *verifyHandle) verifyDetachedSignature(
	origText io.Reader,
	signature []byte,
) (result *VerifyResult, err error) {
	signatureReader := bytes.NewReader(signature)
	ptReader, err := vh.verifyingDetachedReader(origText, signatureReader)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: verify signature failed")
	}
	_, err = io.Copy(io.Discard, ptReader)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: reading all data from plaintext reader failed")
	}
	return ptReader.VerifySignature()
}

func (vh *verifyHandle) verifyingReader(
	signatureMessage io.Reader,
) (reader *VerifyDataReader, err error) {
	checkPacketSequence := !vh.DisableStrictMessageParsing
	config := vh.profile.SignConfig()
	config.CheckPacketSequence = &checkPacketSequence
	verifyTime := vh.clock().Unix()
	config.Time = NewConstantClock(verifyTime)
	if vh.VerificationContext != nil {
		config.KnownNotations = map[string]bool{constants.SignatureContextName: true}
	}
	md, err := openpgp.ReadMessage(
		signatureMessage,
		vh.VerifyKeyRing.getEntities(),
		nil,
		config,
	)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: initialize signature reader failed")
	}
	return &VerifyDataReader{
		md,
		md.UnverifiedBody,
		vh.VerifyKeyRing,
		verifyTime,
		vh.DisableVerifyTimeCheck,
		false,
		vh.VerificationContext,
	}, nil
}

func (vh *verifyHandle) verifyingDetachedReader(
	data Reader,
	signature Reader,
) (*VerifyDataReader, error) {
	return verifyingDetachedReader(
		data,
		signature,
		vh.VerifyKeyRing,
		vh.VerificationContext,
		vh.DisableVerifyTimeCheck,
		vh.DisableAutomaticTextSanitize,
		vh.profile.SignConfig(),
		vh.clock,
	)
}

func (vh *verifyHandle) verifyCleartext(cleartext []byte) (*VerifyCleartextResult, error) {
	block, rest := clearsign.Decode(cleartext)
	if block == nil {
		return nil, errors.New("gopenpgp: not able to parse cleartext message")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("gopenpgp: cleartext message has trailing text")
	}
	signature, err := io.ReadAll(block.ArmoredSignature.Body)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: signature not parsable in cleartext")
	}
	reader := bytes.NewReader(block.Bytes)
	result, err := vh.verifyDetachedSignature(
		reader,
		signature,
	)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: cleartext verify failed with non-signature error")
	}
	return &VerifyCleartextResult{
		VerifyResult: *result,
		cleartext:    block.Plaintext[:len(block.Plaintext)-1],
	}, nil
}

func verifyingDetachedReader(
	data Reader,
	signature Reader,
	verifyKeyRing *KeyRing,
	verificationContext *VerificationContext,
	disableVerifyTimeCheck bool,
	disableAutomaticTextSanitize bool,
	config *packet.Config,
	clock Clock,
) (*VerifyDataReader, error) {
	if config == nil {
		config = &packet.Config{}
	}
	verifyTime := clock().Unix()
	config.Time = NewConstantClock(verifyTime)
	if verificationContext != nil {
		config.KnownNotations = map[string]bool{constants.SignatureContextName: true}
	}
	md, err := openpgp.VerifyDetachedSignatureReader(
		verifyKeyRing.getEntities(),
		data,
		signature,
		config,
	)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: verify signature reader failed")
	}
	internalReader := md.UnverifiedBody
	if len(md.SignatureCandidates) > 0 &&
		!disableAutomaticTextSanitize &&
		md.SignatureCandidates[0].SigType == packet.SigTypeText {
		internalReader = internal.NewSanitizeReader(internalReader)
	}
	return &VerifyDataReader{
		md,
		internalReader,
		verifyKeyRing,
		verifyTime,
		disableVerifyTimeCheck,
		false,
		verificationContext,
	}, nil
}
