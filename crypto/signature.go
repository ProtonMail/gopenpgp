package crypto

import (
	"crypto"
	goerrors "errors"
	"fmt"
	"math"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp"
	pgpErrors "github.com/ProtonMail/go-crypto/v2/openpgp/errors"
	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/pkg/errors"

	"github.com/ProtonMail/gopenpgp/v3/constants"
)

var allowedHashes = []crypto.Hash{
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

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

// VerifyResult is a result of a signature verification.
type VerifyResult struct {
	Signatures        []*VerifiedSignature
	selectedSignature *VerifiedSignature
	signatureError    *SignatureVerificationError
}

// SignatureCreationTime returns the creation time of
// the selected verified signature if found, else returns 0
func (vr *VerifyResult) SignatureCreationTime() int64 {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return 0
	}
	return vr.selectedSignature.Signature.CreationTime.Unix()
}

// SignedWithType returns the type of the signature if found, else returns 0
func (vr *VerifyResult) SignedWithType() packet.SignatureType {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return 0
	}
	return vr.selectedSignature.Signature.SigType
}

// SignedByKeyId returns the key id of the key that was used for the signature,
// if found, else returns 0
func (vr *VerifyResult) SignedByKeyId() uint64 {
	if vr.selectedSignature == nil || vr.selectedSignature.Signature == nil {
		return 0
	}
	return *vr.selectedSignature.Signature.IssuerKeyId
}

// SignedByFingerprint returns the key fingerprint of the key that was used for the signature,
// if found, else returns nil
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

// SignedByKey returns the key that was used for the signature,
// if found, else returns nil
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

// filterSignatureError checks if the input is of type SignatureVerificationError
// returns the SignatureVerificationError if the type matches else nil
func filterSignatureError(err error) *SignatureVerificationError {
	if err != nil {
		castedErr := &SignatureVerificationError{}
		isType := goerrors.As(err, castedErr)
		if !isType {
			return nil
		}
		return castedErr
	}
	return nil
}

// processSignatureExpiration handles signature time verification manually, so
// we can add a margin to the creationTime check.
func processSignatureExpiration(sig *packet.Signature, toCheck error, verifyTime int64, disableTimeCheck bool) error {
	if sig == nil || !errors.Is(toCheck, pgpErrors.ErrSignatureExpired) {
		return toCheck
	}
	if disableTimeCheck {
		return nil
	}
	created := sig.CreationTime.Unix()
	expires := int64(math.MaxInt64)
	if sig.SigLifetimeSecs != nil {
		expires = int64(*sig.SigLifetimeSecs) + created
	}
	if verifyTime <= expires {
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
	var verifiedSignatures []*VerifiedSignature
	var signatureError SignatureVerificationError
	if !md.IsSigned {
		signatureError = newSignatureNotSigned()
		return &VerifyResult{
			signatureError: &signatureError,
		}, nil
	}

	for _, signature := range md.SignatureCandidates {
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
		if len(verifierKey.entities) == 0 || md.SignatureError == pgpErrors.ErrUnknownIssuer {
			signatureError = newSignatureNoVerifier()
		} else if signature.SignatureError != nil {
			signatureError = newSignatureFailed(signature.SignatureError)
		} else if signature.CorrespondingSig == nil ||
			signature.CorrespondingSig.Hash < allowedHashes[0] ||
			signature.CorrespondingSig.Hash > allowedHashes[len(allowedHashes)-1] {
			signatureError = newSignatureInsecure()
		} else if verificationContext != nil {
			err := verificationContext.verifyContext(signature.CorrespondingSig)
			if err != nil {
				signatureError = newSignatureBadContext(err)
			}
		}
		if signatureError.Status != constants.SIGNATURE_OK {
			verifiedSignature.SignatureError = &signatureError
		}
		verifiedSignatures = append(verifiedSignatures, verifiedSignature)
	}

	verifyResult := &VerifyResult{
		Signatures: verifiedSignatures,
	}

	// Is select the signature to show in the result
	// Order of priority: irst successfully verified, Last signature with an error
	for _, signature := range verifiedSignatures {
		verifyResult.selectedSignature = signature
		verifyResult.signatureError = signature.SignatureError
		if signature.SignatureError == nil {
			break
		}
	}

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
