// Package profile provides different profiles to run GopenPGP.
package profile

import (
	"crypto"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

const weakMinRSABits = 1023

// Custom type represents a profile for setting algorithm
// parameters for generating keys, encrypting data, and
// signing data.
// Use one of the pre-defined profiles if possible.
// i.e., profile.Default(), profile.RFC4880().
type Custom struct {
	// Name defines the name of the custom profile.
	Name string
	// SetKeyAlgorithm is a function that sets public key encryption
	// algorithm in the config bases on the int8 security level.
	SetKeyAlgorithm func(*packet.Config, int8)
	// AeadKeyEncryption defines the aead encryption algorithm for key encryption.
	AeadKeyEncryption *packet.AEADConfig
	// S2kKeyEncryption defines the s2k algorithm for key encryption.
	S2kKeyEncryption *s2k.Config
	// AeadEncryption defines the aead encryption algorithm for pgp encryption.
	AeadEncryption *packet.AEADConfig
	// S2kEncryption defines the s2k algorithm for pgp encryption.
	S2kEncryption *s2k.Config
	// CompressionConfiguration defines the compression configuration to be used if any.
	CompressionConfiguration *packet.CompressionConfig
	// Hash defines hash algorithm to be used.
	Hash crypto.Hash
	// SignHash defines if a different hash algorithm should be used for signing.
	// If nil, the a above field Hash is used.
	SignHash *crypto.Hash
	// CipherKeyEncryption defines the cipher to be used for key encryption.
	CipherKeyEncryption packet.CipherFunction
	// CipherEncryption defines the cipher to be used for pgp message encryption.
	CipherEncryption packet.CipherFunction
	// CompressionAlgorithm defines the compression algorithm to be used if any.
	CompressionAlgorithm packet.CompressionAlgo
	// V6 is a flag to indicate if v6 from the crypto-refresh should be used.
	V6 bool
	// AllowAllPublicKeyAlgorithms is a flag to disable all checks for deprecated public key algorithms.
	AllowAllPublicKeyAlgorithms bool
	// DisableIntendedRecipients is a flag to disable the intended recipients pgp feature from the crypto-refresh.
	DisableIntendedRecipients bool
	// AllowWeakRSA is a flag to disable checks for weak rsa keys.
	AllowWeakRSA bool
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

func (p *Custom) KeyGenerationConfig(securityLevel int8) *packet.Config {
	cfg := &packet.Config{
		DefaultHash:            p.Hash,
		DefaultCipher:          p.CipherEncryption,
		AEADConfig:             p.AeadEncryption,
		DefaultCompressionAlgo: p.CompressionAlgorithm,
		CompressionConfig:      p.CompressionConfiguration,
		V6Keys:                 p.V6,
	}
	p.SetKeyAlgorithm(cfg, securityLevel)
	return cfg
}

func (p *Custom) EncryptionConfig() *packet.Config {
	config := &packet.Config{
		DefaultHash:   p.Hash,
		DefaultCipher: p.CipherEncryption,
		AEADConfig:    p.AeadEncryption,
		S2KConfig:     p.S2kEncryption,
	}
	if p.DisableIntendedRecipients {
		intendedRecipients := false
		config.CheckIntendedRecipients = &intendedRecipients
	}
	if p.AllowAllPublicKeyAlgorithms {
		config.RejectPublicKeyAlgorithms = map[packet.PublicKeyAlgorithm]bool{}
	}
	if p.AllowWeakRSA {
		config.MinRSABits = weakMinRSABits
	}
	return config
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
	config := &packet.Config{
		DefaultHash: p.Hash,
	}
	if p.SignHash != nil {
		config.DefaultHash = *p.SignHash
	}
	if p.DisableIntendedRecipients {
		intendedRecipients := false
		config.CheckIntendedRecipients = &intendedRecipients
	}
	if p.AllowAllPublicKeyAlgorithms {
		config.RejectPublicKeyAlgorithms = map[packet.PublicKeyAlgorithm]bool{}
	}
	if p.AllowWeakRSA {
		config.MinRSABits = weakMinRSABits
	}
	return config
}

func (p *Custom) CompressionConfig() *packet.Config {
	return &packet.Config{
		CompressionConfig:      p.CompressionConfiguration,
		DefaultCompressionAlgo: p.CompressionAlgorithm,
	}
}
