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

// SignatureVerificationError is returned from Decrypt and VerifyDetached
// functions when signature verification fails.
type SignatureVerificationError struct {
	Status  int
	Message string
	Cause   error
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

// verifyDetailsSignature verifies signature from message details.
func verifyDetailsSignature(md *openpgp.MessageDetails, verifierKey *KeyRing, verificationContext *VerificationContext) error {
	if !md.IsSigned {
		return newSignatureNotSigned()
	}
	if md.SignedBy == nil ||
		len(verifierKey.entities) == 0 ||
		len(verifierKey.entities.KeysById(md.SignedByKeyId)) == 0 {
		return newSignatureNoVerifier()
	}
	if md.SignatureError != nil {
		return newSignatureFailed(md.SignatureError)
	}
	if md.Signature == nil ||
		md.Signature.Hash < allowedHashes[0] ||
		md.Signature.Hash > allowedHashes[len(allowedHashes)-1] {
		return newSignatureInsecure()
	}
	if verificationContext != nil {
		err := verificationContext.verifyContext(md.Signature)
		if err != nil {
			return newSignatureBadContext(err)
		}
	}

	return nil
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
