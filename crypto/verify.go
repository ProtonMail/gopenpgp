package crypto

// PGPVerify is an interface for verifying detached signatures with GopenPGP.
type PGPVerify interface {
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
	VerifyingReader(detachedData, signatureMessage Reader, encoding int8) (*VerifyDataReader, error)
	// VerifyDetached verifies a detached signature pgp message
	// and returns a VerifyResult. The VerifyResult can be checked for failure
	// and allows access to information about the signatures.
	// Note that an error is only returned if it is not a signature error.
	// The encoding indicates if the input signature message should be unarmored or not,
	// i.e., Bytes/Armor/Auto where Auto tries to detect it automatically.
	VerifyDetached(data []byte, signature []byte, encoding int8) (*VerifyResult, error)
	// VerifyInline verifies an inline signed pgp message
	// and returns a VerifiedDataResult. The VerifiedDataResult can be checked for failure,
	// allows access to information about the signatures, and includes the plain message.
	// Note that an error is only returned if it is not a signature error.
	// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
	// where Auto tries to detect it automatically.
	VerifyInline(message []byte, encoding int8) (*VerifiedDataResult, error)
	// VerifyCleartext verifies an armored cleartext message
	// and returns a VerifyCleartextResult. The VerifyCleartextResult can be checked for failure
	// and allows access the contained message
	// Note that an error is only returned if it is not a signature error.
	VerifyCleartext(cleartext []byte) (*VerifyCleartextResult, error)
}
