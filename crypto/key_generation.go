package crypto

import (
	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

type KeyGenerationProfile interface {
	KeyGenerationConfig(level constants.SecurityLevel) *packet.Config
}

// PGPKeyGeneration is an interface for generating pgp keys with GopenPGP.
// Use the KeyGenerationBuilder to create a handle that implements PGPKeyGeneration.
type PGPKeyGeneration interface {
	// GenerateKey generates a pgp key with the standard security level.
	GenerateKey() (*Key, error)
	// GenerateKeyWithSecurity generates a pgp key with the given security level.
	// The argument security allows to set the security level, either standard or high.
	GenerateKeyWithSecurity(security constants.SecurityLevel) (*Key, error)
}
