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
	SIGNATURE_OK          int = 0
	SIGNATURE_NOT_SIGNED  int = 1
	SIGNATURE_NO_VERIFIER int = 2
	SIGNATURE_FAILED      int = 3
	SIGNATURE_BAD_CONTEXT int = 4
)

// SecurityLevel constants.
// The type is int8 for compatibility with gomobile.
const (
	// StandardSecurity is the default security level.
	StandardSecurity int8 = 0
	// HighSecurity is the high security level.
	HighSecurity int8 = 1
)

// Wraps the packet.CipherFunction enum from go-crypto
// for go-mobile clients.
// int8 type for go-mobile support.
const (
	Cipher3DES   int8 = 2
	CipherCAST5  int8 = 3
	CipherAES128 int8 = 7
	CipherAES192 int8 = 8
	CipherAES256 int8 = 9
)
