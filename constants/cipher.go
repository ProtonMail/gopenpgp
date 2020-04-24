package constants

// Cipher suite names.
const (
	ThreeDES  = "3des"
	TripleDES = "tripledes" // Both "3des" and "tripledes" refer to 3DES.
	CAST5     = "cast5"
	AES128    = "aes128"
	AES192    = "aes192"
	AES256    = "aes256"
)

const (
	SignatureOk         int = 0
	SignatureNotSigned  int = 1
	SignatureNoVerifier int = 2
	SignatureFailed     int = 3
)
