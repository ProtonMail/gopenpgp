package crypto

import (
	"io"
	"io/ioutil"

	"github.com/ProtonMail/go-crypto/v2/openpgp"
	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
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
		isUTF8:   msg.details.LiteralData.IsUTF8,
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
		msg.details.SignatureError = processSignatureExpiration(
			msg.details.Signature,
			msg.details.SignatureError,
			msg.verifyTime,
			msg.disableTimeCheck,
		)
		err = verifyDetailsSignature(msg.details, msg.verifyKeyRing, msg.verificationContext)
		return newVerifyResult(msg.details, err)
	} else {
		err = errors.New("gopenpgp: no verify keyring was provided before decryption")
	}
	return
}

// ReadAll reads all plaintext data from the reader
// and returns it as a byte slice.
func (msg *VerifyDataReader) ReadAll() (plaintext []byte, err error) {
	return io.ReadAll(msg)
}

// DiscardAll reads all data from the reader and discards it.
func (msg *VerifyDataReader) DiscardAll() (err error) {
	_, err = io.Copy(ioutil.Discard, msg)
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

// VerifyResult is a result of a signature verification.
type VerifyResult struct {
	verifyDetails  *openpgp.MessageDetails
	signatureError *SignatureVerificationError
}

// SignatureCreationTime returns the creation time of
// the verified signature
func (vr *VerifyResult) SignatureCreationTime() int64 {
	if vr.verifyDetails == nil {
		return 0
	}
	return vr.verifyDetails.Signature.CreationTime.Unix()
}

// SignedWithType returns the type of the signature, if found, else returns 0
func (vr *VerifyResult) SignedWithType() packet.SignatureType {
	if vr.verifyDetails == nil {
		return 0
	}
	return vr.verifyDetails.SignedWithType
}

// SignedByKeyId returns the key id of the key that was used for the signature,
// if found, else returns 0
func (vr *VerifyResult) SignedByKeyId() uint64 {
	if vr.verifyDetails == nil {
		return 0
	}
	return vr.verifyDetails.SignedByKeyId
}

// SignedByFingerprint returns the key fingerprint of the key that was used for the signature,
// if found, else returns nil
func (vr *VerifyResult) SignedByFingerprint() []byte {
	if vr.verifyDetails == nil {
		return nil
	}
	key := vr.verifyDetails.SignedBy
	if key == nil {
		return nil
	}
	return key.PublicKey.Fingerprint
}

// SignedByKey returns the key that was used for the signature,
// if found, else returns nil
func (vr *VerifyResult) SignedByKey() *Key {
	if vr.verifyDetails == nil {
		return nil
	}
	key := vr.verifyDetails.SignedBy
	if key == nil {
		return nil
	}
	return &Key{
		entity: key.Entity,
	}
}

// HasSignatureError returns true if signature err occurred
// else false
func (vr *VerifyResult) HasSignatureError() bool {
	if vr == nil {
		return false
	}
	return vr.signatureError != nil
}

// SignatureError returns nil if no signature err occurred else
// the signature error.
func (vr *VerifyResult) SignatureError() error {
	if vr == nil || vr.signatureError == nil {
		return nil
	}
	return *vr.signatureError
}

// SignatureErrorExplicit returns nil if no signature err occurred else
// the explicit signature error.
func (vr *VerifyResult) SignatureErrorExplicit() *SignatureVerificationError {
	return vr.signatureError
}

// VerifiedDataResult is a result that contains data and
// the result of a potential signature verification on the data.
type VerifiedDataResult struct {
	VerifyResult
	metadata         *LiteralMetadata
	data             []byte
	cachedSessionKey *SessionKey
}

// GetMetadata returns the associated literal metadata of the data.
func (r *VerifiedDataResult) GetMetadata() *LiteralMetadata {
	return r.metadata
}

// Result returns the result data.
func (r *VerifiedDataResult) Result() []byte {
	return r.data
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

// Cleartext returns the parsed plain text of
// a the result.
func (vc *VerifyCleartextResult) Cleartext() []byte {
	return vc.cleartext
}
