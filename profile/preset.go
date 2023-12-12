package profile

import (
	"crypto"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

var nameToProfile = map[string]func() *Custom{
	"default":                              Default,
	"rfc4880":                              RFC4880,
	"draft-koch-eddsa-for-openpgp-00":      GnuPG,
	"draft-ietf-openpgp-crypto-refresh-10": CryptoRefresh,
}

// PresetProfiles returns the names of the available profiles.
func PresetProfiles() []string {
	profiles := make([]string, len(nameToProfile))
	index := 0
	for profile := range nameToProfile {
		profiles[index] = profile
		index++
	}
	return profiles
}

// Default returns a custom profile that support features
// that are widely implemented.
func Default() *Custom {
	return ProtonV1()
}

// RFC4880 returns a custom profile for this library
// that conforms with the algorithms in rfc 4880.
func RFC4880() *Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoRSA
		switch securityLevel {
		case constants.HighSecurity:
			cfg.RSABits = 4096
		default:
			cfg.RSABits = 3072
		}
	}
	return &Custom{
		Name:                 "rfc4880",
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
	}
}

// GnuPG returns a custom profile for this library
// that conforms with the algorithms in GnuPG.
// Use this profile for modern algorithms and GnuPG interoperability.
func GnuPG() *Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
		switch securityLevel {
		case constants.HighSecurity:
			cfg.Curve = packet.Curve448
			cfg.DefaultHash = crypto.SHA512
		default:
			cfg.Curve = packet.Curve25519
		}
	}
	return &Custom{
		Name:                 "draft-koch-eddsa-for-openpgp-00",
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
	}
}

// CryptoRefresh returns a custom profile for this library
// that conforms with the algorithms in draft-ietf-openpgp-crypto-refresh.
func CryptoRefresh() *Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		switch securityLevel {
		case constants.HighSecurity:
			cfg.Algorithm = packet.PubKeyAlgoEd448
			cfg.DefaultHash = crypto.SHA512
		default:
			cfg.Algorithm = packet.PubKeyAlgoEd25519
		}
	}
	return &Custom{
		Name:                 "draft-ietf-openpgp-crypto-refresh",
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
		AeadKeyEncryption:    &packet.AEADConfig{},
		AeadEncryption:       &packet.AEADConfig{},
		S2kKeyEncryption: &s2k.Config{
			S2KMode:      s2k.Argon2S2K,
			Argon2Config: &s2k.Argon2Config{},
		},
		S2kEncryption: &s2k.Config{
			S2KMode:      s2k.Argon2S2K,
			Argon2Config: &s2k.Argon2Config{},
		},
		V6: true,
	}
}

// ProtonV1 is the version 1 profile used in proton clients.
func ProtonV1() *Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
		switch securityLevel {
		case constants.HighSecurity:
			cfg.Curve = packet.Curve25519
		default:
			cfg.Curve = packet.Curve25519
		}
	}
	return &Custom{
		Name:                 "proton-v1",
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
		CompressionConfiguration: &packet.CompressionConfig{
			Level: 6,
		},
		DisableIntendedRecipients:   true,
		AllowAllPublicKeyAlgorithms: true,
		AllowWeakRSA:                true,
	}
}
