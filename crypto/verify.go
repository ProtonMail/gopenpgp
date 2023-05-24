package crypto

// PGPVerify is an interface for verifying detached signatures with GopenPGP.
type PGPVerify interface {
	// VerifyingReader wraps a reader with a signature verify reader.
	// Once all data is read from the returned verify reader, the signature can be verified
	// with (VerifyDataReader).VerifySignature().
	// Note that an error is only returned if it is not a signature error.
	// If detachedData is nil, signatureMessage is treated as an inline signature message.
	// Thus, it is expected that signatureMessage contains the data to be verified.
	// If detachedData is not nil, signatureMessage must contain a detached signature,
	// which is verified against the detachedData.
	VerifyingReader(detachedData, signatureMessage Reader) (*VerifyDataReader, error)
	// Verify verifies either a inline signature message or a detached signature
	// and returns a VerifyResult. The VerifyResult can be checked for failure
	// and allows access to information about the signature.
	// Note that an error is only returned if it is not a signature error.
	// If detachedData is nil, signatureMessage is treated as an inline signature message.
	// Thus, it is expected that signatureMessage contains the data to be verified.
	// If detachedData is not nil, signatureMessage must contain a detached signature,
	// which is verified against the detachedData.
	Verify(detachedData []byte, signatureMessage []byte) (*VerifiedDataResult, error)
	// VerifyCleartext verifies an armored cleartext message
	// and returns a VerifyCleartextResult. The VerifyCleartextResult can be checked for failure
	// and allows access the contained message
	// Note that an error is only returned if it is not a signature error.
	VerifyCleartext(cleartext []byte) (*VerifyCleartextResult, error)
}
