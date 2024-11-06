package crypto

import (
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Integer enum for go-mobile compatibility.
const (
	// KeyGenerationRSA4096 allows to override the output key algorithm in key generation to rsa 4096.
	KeyGenerationRSA4096 int = 1
	// KeyGenerationC25519 allows to override the output key algorithm in key generation to curve25519.
	KeyGenerationC25519 int = 2
	// KeyGenerationC25519 allows to override the output key algorithm in key generation to curve25519 RFC9580.
	KeyGenerationC25519Refresh int = 3
	// KeyGenerationC448 allows to override the output key algorithm in key generation to curve448.
	KeyGenerationC448 int = 4
	// KeyGenerationC448Refresh allows to override the output key algorithm in key generation to curve448 RFC9580.
	KeyGenerationC448Refresh int = 5
)

type KeyGenerationProfile interface {
	KeyGenerationConfig(securityLevel int8) *packet.Config
}

// PGPKeyGeneration is an interface for generating pgp keys with GopenPGP.
// Use the KeyGenerationBuilder to create a handle that implements PGPKeyGeneration.
type PGPKeyGeneration interface {
	// GenerateKey generates a pgp key with the standard security level.
	GenerateKey() (*Key, error)
	// GenerateKeyWithSecurity generates a pgp key with the given security level.
	// The argument security allows to set the security level, either standard or high.
	GenerateKeyWithSecurity(securityLevel int8) (*Key, error)
}
