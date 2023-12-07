package crypto

import (
	"bytes"
	"crypto"
	"fmt"
	"time"

	pgpErrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/pkg/errors"

	"github.com/ProtonMail/gopenpgp/v3/constants"
)

var allowedHashesSet = map[crypto.Hash]struct{}{
	crypto.SHA224: {},
	crypto.SHA256: {},
	crypto.SHA384: {},
	crypto.SHA512: {},
}

// VerifiedSignature is a result of a signature verification.
type VerifiedSignature struct {
	Signature      *packet.Signature
	SignedBy       *Key
	SignatureError *SignatureVerificationError
}

// SignatureVerificationError is returned from Decrypt and VerifyDetached
// functions when signature verification fails.
type SignatureVerificationError struct {
	Status  int
	Message string
	Cause   error
}

// VerifyResult is a result of a pgp message signature verification.
type VerifyResult struct {
	// All signatures found in the message.
	Signatures []*VerifiedSignature
	// The selected signature for the result.
	// i.e., the first successfully verified signature in Signatures
	// or the last signature Signatures[len(Signatures)-1].
	selectedSignature *VerifiedSignature
	// The signature error of the selected signature.
	// Is nil for a successful verification.
	signatureError *SignatureVerificationError
}

// SignatureCreationTime returns the creation time of
// the selected verified signature if found, else returns 0.
func (vr *VerifyResult) SignatureCreationTime() int64 {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return 0
	}
	return vr.selectedSignature.Signature.CreationTime.Unix()
}

// SignedWithType returns the type of the signature if found, else returns 0.
// Not supported in go-mobile use SignedWithTypeInteger instead.
func (vr *VerifyResult) SignedWithType() packet.SignatureType {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return 0
	}
	return vr.selectedSignature.Signature.SigType
}

// SignedWithTypeInt8 returns the type of the signature as int8 type if found, else returns 0.
// See constants.SigType... for the different types.
func (vr *VerifyResult) SignedWithTypeInt8() int8 {
	return int8(vr.SignedWithType())
}

// SignedByKeyId returns the key id of the key that was used to verify the selected signature,
// if found, else returns 0.
// Not supported in go-mobile use SignedByKeyIdString instead.
func (vr *VerifyResult) SignedByKeyId() uint64 {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return 0
	}
	return *vr.selectedSignature.Signature.IssuerKeyId
}

// SignedByKeyIdHex returns the key id of the key that was used to verify the selected signature
// as a hex encoded string.
// Helper for go-mobile.
func (vr *VerifyResult) SignedByKeyIdHex() string {
	return keyIDToHex(vr.SignedByKeyId())
}

// SignedByFingerprint returns the key fingerprint of the key that was used to verify the selected signature,
// if found, else returns nil.
func (vr *VerifyResult) SignedByFingerprint() []byte {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return nil
	}
	if vr.selectedSignature.Signature.IssuerFingerprint != nil {
		return vr.selectedSignature.Signature.IssuerFingerprint
	}
	if vr.selectedSignature.SignedBy != nil {
		return vr.selectedSignature.SignedBy.GetFingerprintBytes()
	}
	return nil
}

// SignedByKey returns the key that was used to verify the selected signature,
// if found, else returns nil.
func (vr *VerifyResult) SignedByKey() *Key {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return nil
	}
	key := vr.selectedSignature.SignedBy
	if key == nil {
		return nil
	}
	return &Key{
		entity: key.entity,
	}
}

// Signature returns the serialized openpgp signature packet of the selected signature.
func (vr *VerifyResult) Signature() ([]byte, error) {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return nil, errors.New("gopenpgp: no signature present")
	}
	var serializedSignature bytes.Buffer
	if err := vr.selectedSignature.Signature.Serialize(&serializedSignature); err != nil {
		return nil, errors.Wrap(err, "gopenpgp: signature serialization failed")
	}
	return serializedSignature.Bytes(), nil
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

// ConstrainToTimeRange updates the signature result to only consider
// signatures with a creation time within the given time frame.
// unixFrom and unixTo are in unix time and are inclusive.
func (vr *VerifyResult) ConstrainToTimeRange(unixFrom int64, unixTo int64) {
	for _, signature := range vr.Signatures {
		if signature.Signature != nil && signature.SignatureError == nil {
			sigUnixTime := signature.Signature.CreationTime.Unix()
			if sigUnixTime < unixFrom || sigUnixTime > unixTo {
				sigError := newSignatureFailed(errors.New("gopenpgp: signature creation time is out of range"))
				signature.SignatureError = &sigError
			}
		}
	}
	// Reselect
	vr.selectSignature()
}

// Error is the base method for all errors.
func (e SignatureVerificationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("Signature Verification Error: %v caused by %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("Signature Verification Error: %v", e.Message)
}

// Unwrap returns the cause of failure.
func (e SignatureVerificationError) Unwrap() error {
	return e.Cause
}

// ------------------
// Internal functions
// ------------------

// selectSignature selects the main signature to show in the result.
// Selection policy:
// first successfully verified or
// last signature with an error and a matching key or
// last signature with an error if no key matched.
func (vr *VerifyResult) selectSignature() {
	var keyMatch bool
	for _, signature := range vr.Signatures {
		if signature.SignedBy != nil {
			keyMatch = true
			vr.selectedSignature = signature
			vr.signatureError = signature.SignatureError
			if signature.SignatureError == nil {
				break
			}
		}
	}
	if !keyMatch && len(vr.Signatures) > 0 {
		signature := vr.Signatures[len(vr.Signatures)-1]
		vr.selectedSignature = signature
		vr.signatureError = signature.SignatureError
	}
}

// newSignatureFailed creates a new SignatureVerificationError, type
// SignatureFailed.
func newSignatureBadContext(cause error) SignatureVerificationError {
	return SignatureVerificationError{
		Status:  constants.SIGNATURE_BAD_CONTEXT,
		Message: "Invalid signature context",
		Cause:   cause,
	}
}

func newSignatureFailed(cause error) SignatureVerificationError {
	return SignatureVerificationError{
		Status:  constants.SIGNATURE_FAILED,
		Message: "Invalid signature",
		Cause:   cause,
	}
}

// newSignatureInsecure creates a new SignatureVerificationError, type
// SignatureFailed, with a message describing the signature as insecure.
func newSignatureInsecure() SignatureVerificationError {
	return SignatureVerificationError{
		Status:  constants.SIGNATURE_FAILED,
		Message: "Insecure signature",
	}
}

// newSignatureNotSigned creates a new SignatureVerificationError, type
// SignatureNotSigned.
func newSignatureNotSigned() SignatureVerificationError {
	return SignatureVerificationError{
		Status:  constants.SIGNATURE_NOT_SIGNED,
		Message: "Missing signature",
	}
}

// newSignatureNoVerifier creates a new SignatureVerificationError, type
// SignatureNoVerifier.
func newSignatureNoVerifier() SignatureVerificationError {
	return SignatureVerificationError{
		Status:  constants.SIGNATURE_NO_VERIFIER,
		Message: "No matching signature",
	}
}

// processSignatureExpiration handles signature time verification manually, so
// we can ignore signature expired errors if configured so.
func processSignatureExpiration(sig *packet.Signature, toCheck error, verifyTime int64, disableTimeCheck bool) error {
	if sig == nil || !errors.Is(toCheck, pgpErrors.ErrSignatureExpired) {
		return toCheck
	}
	if disableTimeCheck || verifyTime == 0 {
		return nil
	}
	return toCheck
}

func createVerifyResult(
	md *openpgp.MessageDetails,
	verifierKey *KeyRing,
	verificationContext *VerificationContext,
	verifyTime int64,
	disableTimeCheck bool,
) (*VerifyResult, error) {
	if !md.IsSigned {
		signatureError := newSignatureNotSigned()
		return &VerifyResult{
			signatureError: &signatureError,
		}, nil
	}
	if !md.IsVerified {
		return nil, errors.New("gopenpgp: message has not been verified")
	}

	verifiedSignatures := make([]*VerifiedSignature, len(md.SignatureCandidates))
	for candidateIndex, signature := range md.SignatureCandidates {
		var singedBy *Key
		if signature.SignedBy != nil {
			singedBy = &Key{
				entity: signature.SignedBy.Entity,
			}
		}
		verifiedSignature := &VerifiedSignature{
			Signature: signature.CorrespondingSig,
			SignedBy:  singedBy,
		}
		signature.SignatureError = processSignatureExpiration(
			signature.CorrespondingSig,
			signature.SignatureError,
			verifyTime,
			disableTimeCheck,
		)
		var signatureError SignatureVerificationError

		switch {
		case len(verifierKey.entities) == 0 ||
			errors.Is(signature.SignatureError, pgpErrors.ErrUnknownIssuer):
			signatureError = newSignatureNoVerifier()
		case signature.SignatureError != nil:
			signatureError = newSignatureFailed(signature.SignatureError)
		case signature.CorrespondingSig == nil || !isHashAllowed(signature.CorrespondingSig.Hash):
			signatureError = newSignatureInsecure()
		case verificationContext != nil:
			err := verificationContext.verifyContext(signature.CorrespondingSig)
			if err != nil {
				signatureError = newSignatureBadContext(err)
			}
		}
		if signatureError.Status != constants.SIGNATURE_OK {
			verifiedSignature.SignatureError = &signatureError
		}
		verifiedSignatures[candidateIndex] = verifiedSignature
	}

	verifyResult := &VerifyResult{
		Signatures: verifiedSignatures,
	}

	// Select the signature to show in the result
	verifyResult.selectSignature()
	return verifyResult, nil
}

// SigningContext gives the context that will be
// included in the signature's notation data.
type SigningContext struct {
	Value      string
	IsCritical bool
}

// NewSigningContext creates a new signing context.
// The value is set to the notation data.
// isCritical controls whether the notation is flagged as a critical packet.
func NewSigningContext(value string, isCritical bool) *SigningContext {
	return &SigningContext{Value: value, IsCritical: isCritical}
}

func (context *SigningContext) getNotation() *packet.Notation {
	return &packet.Notation{
		Name:            constants.SignatureContextName,
		Value:           []byte(context.Value),
		IsCritical:      context.IsCritical,
		IsHumanReadable: true,
	}
}

// VerificationContext gives the context that will be
// used to verify the signature.
type VerificationContext struct {
	Value         string
	IsRequired    bool
	RequiredAfter int64
}

// NewVerificationContext creates a new verification context.
// The value is checked against the signature's notation data.
// If isRequired is false, the signature is allowed to have no context set.
// If requiredAfter is != 0, the signature is allowed to have no context set if it
// was created before the unix time set in requiredAfter.
func NewVerificationContext(value string, isRequired bool, requiredAfter int64) *VerificationContext {
	return &VerificationContext{
		Value:         value,
		IsRequired:    isRequired,
		RequiredAfter: requiredAfter,
	}
}

func (context *VerificationContext) isRequiredAtTime(signatureTime time.Time) bool {
	return context.IsRequired &&
		(context.RequiredAfter == 0 || signatureTime.After(time.Unix(context.RequiredAfter, 0)))
}

func findContext(notations []*packet.Notation) (string, error) {
	context := ""
	for _, notation := range notations {
		if notation.Name == constants.SignatureContextName {
			if context != "" {
				return "", errors.New("gopenpgp: signature has multiple context notations")
			}
			if !notation.IsHumanReadable {
				return "", errors.New("gopenpgp: context notation was not set as human-readable")
			}
			context = string(notation.Value)
		}
	}
	return context, nil
}

func (context *VerificationContext) verifyContext(sig *packet.Signature) error {
	signatureContext, err := findContext(sig.Notations)
	if err != nil {
		return err
	}
	if signatureContext != context.Value {
		contextRequired := context.isRequiredAtTime(sig.CreationTime)
		if contextRequired {
			return errors.New("gopenpgp: signature did not have the required context")
		} else if signatureContext != "" {
			return errors.New("gopenpgp: signature had a wrong context")
		}
	}

	return nil
}

func isHashAllowed(h crypto.Hash) bool {
	_, ok := allowedHashesSet[h]
	return ok
}
