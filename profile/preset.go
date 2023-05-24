package profile

import (
	"crypto"

	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/ProtonMail/go-crypto/v2/openpgp/s2k"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

var nameToProfile = map[string]func() *Custom{
	"default":                           Default,
	"rfc4880":                           RFC4880,
	"draft-koch-openpgp":                Koch,
	"draft-ietf-openpgp-crypto-refresh": CryptoRefresh,
}

// PresetProfiles returns the names of the available profiles.
func PresetProfiles() []string {
	var profiles []string
	for profile := range nameToProfile {
		if profile != "default" {
			profiles = append(profiles, profile)
		}
	}
	return profiles
}

// Default returns the custom profile of this library.
func Default() *Custom {
	return RFC4880()
}

// RFC4880 returns a custom profile for this library
// that conforms with the algorithms in rfc 4880.
func RFC4880() *Custom {
	return &Custom{
		Name:                           "rfc4880",
		KeyAlgorithm:                   constants.RSA,
		Hash:                           crypto.SHA256,
		HashSign:                       crypto.SHA512,
		CipherEncryption:               packet.CipherAES256,
		CompressionAlgorithmEncryption: packet.CompressionZLIB,
		CompressionConfigEncryption: &packet.CompressionConfig{
			Level: 6,
		},
	}
}

// Koch returns a custom profile for this library
// that conforms with the algorithms in draft-koch-openpgp.
func Koch() *Custom {
	return &Custom{
		Name:                           "draft-koch-openpgp",
		KeyAlgorithm:                   constants.Elliptic,
		Hash:                           crypto.SHA256,
		HashSign:                       crypto.SHA512,
		CipherEncryption:               packet.CipherAES256,
		CompressionAlgorithmEncryption: packet.CompressionZLIB,
		AeadKeyEncryption:              &packet.AEADConfig{},
		AeadEncryption:                 &packet.AEADConfig{},
		CompressionConfigEncryption: &packet.CompressionConfig{
			Level: 6,
		},
	}
}

// CryptoRefresh returns a custom profile for this library
// that conforms with the algorithms in draft-ietf-openpgp-crypto-refresh.
func CryptoRefresh() *Custom {
	return &Custom{
		Name:                           "draft-ietf-openpgp-crypto-refresh",
		KeyAlgorithm:                   constants.Elliptic,
		Hash:                           crypto.SHA256,
		HashSign:                       crypto.SHA512,
		CipherEncryption:               packet.CipherAES256,
		CompressionAlgorithmEncryption: packet.CompressionZLIB,
		AeadKeyEncryption:              &packet.AEADConfig{},
		AeadEncryption:                 &packet.AEADConfig{},
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
