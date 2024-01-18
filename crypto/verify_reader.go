package crypto

import (
	"io"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/pkg/errors"
)

// VerifyDataReader is used for reading data that should be verified with a signature.
// It further contains additional information about the parsed pgp message where the read
// data stems from.
type VerifyDataReader struct {
	details             *openpgp.MessageDetails
	internalReader      Reader
	verifyKeyRing       *KeyRing
	verifyTime          int64
	disableTimeCheck    bool
	readAll             bool
	verificationContext *VerificationContext
}

// GetMetadata returns the metadata of the literal data packet that
// this reader reads from. Can be nil, if the data is not read from
// a literal data packet.
func (msg *VerifyDataReader) GetMetadata() *LiteralMetadata {
	if msg.details.LiteralData == nil {
		return nil
	}
	return &LiteralMetadata{
		filename: msg.details.LiteralData.FileName,
		isUTF8:   !msg.details.LiteralData.IsBinary,
		ModTime:  int64(msg.details.LiteralData.Time),
	}
}

// Read is used read data from the pgp message.
// Makes VerifyDataReader implement the Reader interface.
func (msg *VerifyDataReader) Read(b []byte) (n int, err error) {
	n, err = msg.internalReader.Read(b)
	if errors.Is(err, io.EOF) {
		msg.readAll = true
	}
	return
}

// VerifySignature is used to verify that the embedded signatures are valid.
// This method needs to be called once all the data has been read.
// It will return an error if the signature is invalid, no verifying keys are accessible,
// or if the message hasn't been read entirely.
func (msg *VerifyDataReader) VerifySignature() (result *VerifyResult, err error) {
	if !msg.readAll {
		return nil, errors.New("gopenpgp: can't verify the signature until the message reader has been read entirely")
	}
	if msg.verifyKeyRing != nil {
		return createVerifyResult(msg.details, msg.verifyKeyRing, msg.verificationContext, msg.verifyTime, msg.disableTimeCheck)
	}

	return nil, errors.New("gopenpgp: no verify keyring was provided before decryption")
}

// ReadAll reads all plaintext data from the reader
// and returns it as a byte slice.
func (msg *VerifyDataReader) ReadAll() (plaintext []byte, err error) {
	return io.ReadAll(msg)
}

// DiscardAll reads all data from the reader and discards it.
func (msg *VerifyDataReader) DiscardAll() (err error) {
	_, err = io.Copy(io.Discard, msg)
	return err
}

// DiscardAllAndVerifySignature reads all plaintext data from the reader but discards it.
// Returns a verification result for signature verification on the read data.
func (msg *VerifyDataReader) DiscardAllAndVerifySignature() (vr *VerifyResult, err error) {
	err = msg.DiscardAll()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: discarding data from reader failed")
	}
	return msg.VerifySignature()
}

// ReadAllAndVerifySignature reads all plaintext data from the reader
// and verifies that the signatures are valid.
// Only checks the signatures if any verify keys are present.
// Returns the data in a VerifiedDataResult struct, which can be checked for signature errors.
func (msg *VerifyDataReader) ReadAllAndVerifySignature() (*VerifiedDataResult, error) {
	plaintext, err := msg.ReadAll()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: reading all data from reader failed")
	}
	if msg.verifyKeyRing != nil {
		verifyResult, err := msg.VerifySignature()
		return &VerifiedDataResult{
			VerifyResult:     *verifyResult,
			data:             plaintext,
			metadata:         msg.GetMetadata(),
			cachedSessionKey: msg.SessionKey(),
		}, err
	}
	return &VerifiedDataResult{
		data:             plaintext,
		metadata:         msg.GetMetadata(),
		cachedSessionKey: msg.SessionKey(),
	}, nil
}

// SessionKey returns the session key the data is decrypted with.
// Returns nil, if this reader does not read from an encrypted message or
// session key caching was not enabled.
func (msg *VerifyDataReader) SessionKey() *SessionKey {
	if msg.details.SessionKey == nil {
		return nil
	}
	alg := getAlgo(msg.details.DecryptedWithAlgorithm)
	return NewSessionKeyFromToken(msg.details.SessionKey, alg)
}

// VerifiedDataResult is a result that contains data and
// the result of a potential signature verification on the data.
type VerifiedDataResult struct {
	VerifyResult
	metadata         *LiteralMetadata
	data             []byte
	cachedSessionKey *SessionKey
}

// Metadata returns the associated literal metadata of the data.
func (r *VerifiedDataResult) Metadata() *LiteralMetadata {
	return r.metadata
}

// Bytes returns the result data as bytes.
func (r *VerifiedDataResult) Bytes() []byte {
	return r.data
}

// String returns the result data as string.
func (r *VerifiedDataResult) String() string {
	return string(r.data)
}

// SessionKey returns the session key the data is decrypted with.
// Returns nil, if the data was not encrypted or
// session key caching was not enabled.
func (r *VerifiedDataResult) SessionKey() *SessionKey {
	return r.cachedSessionKey
}

// VerifyCleartextResult is a result of a cleartext message verification.
type VerifyCleartextResult struct {
	VerifyResult
	cleartext []byte
}

// Cleartext returns the parsed plain text of the result.
func (vc *VerifyCleartextResult) Cleartext() []byte {
	return vc.cleartext
}
