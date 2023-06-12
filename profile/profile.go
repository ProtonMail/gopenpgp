package profile

import (
	"crypto"

	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/ProtonMail/go-crypto/v2/openpgp/s2k"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

// Custom type represents a profile setting algorithm
// parameters for generating keys, encrypting data, and
// signing data.
type Custom struct {
	Name string

	SetKeyAlgorithm func(*packet.Config, constants.SecurityLevel)

	Hash crypto.Hash

	CipherKeyEncryption packet.CipherFunction
	AeadKeyEncryption   *packet.AEADConfig
	S2kKeyEncryption    *s2k.Config

	CipherEncryption         packet.CipherFunction
	AeadEncryption           *packet.AEADConfig
	S2kEncryption            *s2k.Config
	CompressionAlgorithm     packet.CompressionAlgo
	CompressionConfiguration *packet.CompressionConfig

	HashSign crypto.Hash
	V6       bool
}

// WithName returns the custom profile with the given name.
func WithName(name string) *Custom {
	profileFunction, ok := nameToProfile[name]
	if !ok {
		return nil
	}
	return profileFunction()
}

// Custom implements the profile interfaces:
// KeyGenerationProfile, KeyEncryptionProfile, EncryptionProfile, and SignProfile

func (p *Custom) KeyGenerationConfig(level constants.SecurityLevel) *packet.Config {
	cfg := &packet.Config{
		DefaultHash:            p.Hash,
		DefaultCipher:          p.CipherEncryption,
		AEADConfig:             p.AeadEncryption,
		DefaultCompressionAlgo: p.CompressionAlgorithm,
		CompressionConfig:      p.CompressionConfiguration,
		V6Keys:                 p.V6,
	}
	p.SetKeyAlgorithm(cfg, level)
	return cfg
}

func (p *Custom) EncryptionConfig() *packet.Config {
	return &packet.Config{
		DefaultHash:   p.Hash,
		DefaultCipher: p.CipherEncryption,
		AEADConfig:    p.AeadEncryption,
		S2KConfig:     p.S2kEncryption,
	}
}

func (p *Custom) KeyEncryptionConfig() *packet.Config {
	return &packet.Config{
		DefaultHash:   p.Hash,
		DefaultCipher: p.CipherKeyEncryption,
		AEADConfig:    p.AeadKeyEncryption,
		S2KConfig:     p.S2kKeyEncryption,
	}
}

func (p *Custom) SignConfig() *packet.Config {
	return &packet.Config{
		DefaultHash: p.HashSign,
	}
}

func (p *Custom) CompressionConfig() *packet.Config {
	return &packet.Config{
		CompressionConfig:      p.CompressionConfiguration,
		DefaultCompressionAlgo: p.CompressionAlgorithm,
	}
}
