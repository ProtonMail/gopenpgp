package crypto

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgpErrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/internal"
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
}

// Error is the base method for all errors.
func (e SignatureVerificationError) Error() string {
	return fmt.Sprintf("Signature Verification Error: %v", e.Message)
}

// ------------------
// Internal functions
// ------------------

// newSignatureFailed creates a new SignatureVerificationError, type
// SignatureFailed.
func newSignatureFailed() SignatureVerificationError {
	return SignatureVerificationError{
		Status:  constants.SIGNATURE_FAILED,
		Message: "Invalid signature",
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
// we can add a margin to the creationTime check.
func processSignatureExpiration(md *openpgp.MessageDetails, verifyTime int64) {
	if !errors.Is(md.SignatureError, pgpErrors.ErrSignatureExpired) {
		return
	}
	if verifyTime == 0 {
		// verifyTime = 0: time check disabled, everything is okay
		md.SignatureError = nil
		return
	}
	created := md.Signature.CreationTime.Unix()
	expires := int64(math.MaxInt64)
	if md.Signature.SigLifetimeSecs != nil {
		expires = int64(*md.Signature.SigLifetimeSecs) + created
	}
	if created-internal.CreationTimeOffset <= verifyTime && verifyTime <= expires {
		md.SignatureError = nil
	}
}

// verifyDetailsSignature verifies signature from message details.
func verifyDetailsSignature(md *openpgp.MessageDetails, verifierKey *KeyRing) error {
	if !md.IsSigned {
		return newSignatureNotSigned()
	}
	if md.SignedBy == nil ||
		len(verifierKey.entities) == 0 ||
		len(verifierKey.entities.KeysById(md.SignedByKeyId)) == 0 {
		return newSignatureNoVerifier()
	}
	if md.SignatureError != nil {
		return newSignatureFailed()
	}
	if md.Signature == nil ||
		md.Signature.Hash < allowedHashes[0] ||
		md.Signature.Hash > allowedHashes[len(allowedHashes)-1] {
		return newSignatureInsecure()
	}
	return nil
}

// verifySignature verifies if a signature is valid with the entity list.
func verifySignature(pubKeyEntries openpgp.EntityList, origText io.Reader, signature []byte, verifyTime int64) error {
	config := &packet.Config{}
	if verifyTime == 0 {
		config.Time = func() time.Time {
			return time.Unix(0, 0)
		}
	} else {
		config.Time = func() time.Time {
			return time.Unix(verifyTime+internal.CreationTimeOffset, 0)
		}
	}
	signatureReader := bytes.NewReader(signature)

	signer, err := openpgp.CheckDetachedSignatureAndHash(pubKeyEntries, origText, signatureReader, allowedHashes, config)

	if errors.Is(err, pgpErrors.ErrSignatureExpired) && signer != nil && verifyTime > 0 {
		// if verifyTime = 0: time check disabled, everything is okay
		// Maybe the creation time offset pushed it over the edge
		// Retry with the actual verification time
		config.Time = func() time.Time {
			return time.Unix(verifyTime, 0)
		}

		_, err = signatureReader.Seek(0, io.SeekStart)
		if err != nil {
			return newSignatureFailed()
		}

		signer, err = openpgp.CheckDetachedSignatureAndHash(pubKeyEntries, origText, signatureReader, allowedHashes, config)
		if err != nil {
			return newSignatureFailed()
		}
	}

	if signer == nil {
		return newSignatureFailed()
	}

	return nil
}
