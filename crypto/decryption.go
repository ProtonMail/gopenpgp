package crypto

// PGPDecryption is an interface for decrypting pgp messages with GopenPGP.
// Use the DecryptionHandleBuilder to create a handle that implements PGPDecryption.
type PGPDecryption interface {
	// DecryptingReader returns a wrapper around underlying encryptedMessage Reader,
	// such that any read-operation via the wrapper results in a read from the decrypted pgp message.
	// The returned VerifyDataReader has to be fully read before any potential signatures can be verified.
	// Either read the message fully end then call VerifySignature or use the helper method ReadAllAndVerifySignature.
	// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
	// where Auto tries to detect automatically.
	// If encryptedMessage is of type PGPSplitReader, the method tries to verify an encrypted detached signature
	// that is read from the separate reader.
	DecryptingReader(encryptedMessage Reader, encoding int8) (*VerifyDataReader, error)
	// Decrypt decrypts an encrypted pgp message.
	// Returns a VerifiedDataResult, which can be queried for potential signature verification errors,
	// and the plaintext data. Note that on a signature error, the method does not return an error.
	// Instead, the signature error is stored within the VerifiedDataResult.
	// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
	// where Auto tries to detect automatically.
	Decrypt(pgpMessage []byte, encoding int8) (*VerifiedDataResult, error)
	// DecryptDetached provides the same functionality as Decrypt but allows
	// to supply an encrypted detached signature that should be decrypted and verified
	// against the data in the pgp message. If encDetachedSignature is nil, the behavior is similar
	// to Decrypt. The encoding indicates if the input message should be unarmored or not,
	// i.e., Bytes/Armor/Auto where Auto tries to detect automatically.
	DecryptDetached(pgpMessage []byte, encDetachedSignature []byte, encoding int8) (*VerifiedDataResult, error)
	// DecryptSessionKey decrypts an encrypted session key.
	// To decrypt a session key, the decryption handle must contain either a decryption key or a password.
	DecryptSessionKey(keyPackets []byte) (*SessionKey, error)
	// ClearPrivateParams clears all private key material contained in EncryptionHandle from memory.
	ClearPrivateParams()
}

type Reader interface {
	Read(b []byte) (n int, err error)
}

type PGPSplitReader interface {
	Reader
	Signature() Reader
}
