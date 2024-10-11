package profile

import (
	"crypto"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

// Default returns a custom profile that support features
// that are widely implemented.
func Default() *Custom {
	return ProtonV1()
}

// RFC4880 returns a custom profile for this library
// that conforms with the algorithms in RFC4880.
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

// RFC9580 returns a custom profile for this library
// that conforms with the algorithms in RFC9580 (crypto refresh).
func RFC9580() *Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		switch securityLevel {
		case constants.HighSecurity:
			cfg.Algorithm = packet.PubKeyAlgoEd448
		default:
			cfg.Algorithm = packet.PubKeyAlgoEd25519
		}
	}
	return &Custom{
		Name:                 "rfc9580",
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA512,
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
		Hash:                 crypto.SHA512,
		CipherEncryption:     packet.CipherAES256,
		CipherKeyEncryption:  packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
		KeyGenAeadEncryption: &packet.AEADConfig{
			DefaultMode: packet.AEADModeGCM,
		},
		CompressionConfiguration: &packet.CompressionConfig{
			Level: 6,
		},
		S2kKeyEncryption: &s2k.Config{
			S2KMode:  s2k.IteratedSaltedS2K,
			Hash:     crypto.SHA256,
			S2KCount: 65536,
		},
		DisableIntendedRecipients:   true,
		AllowAllPublicKeyAlgorithms: true,
		AllowWeakRSA:                true,
	}
}
