package crypto

import (
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
)

// EncryptionOption defines an interface to apply configurations to packet.Config
type EncryptionOption interface {
	apply(*packet.Config)
}

type configFunc func(*packet.Config)

func (f configFunc) apply(cfg *packet.Config) {
	f(cfg)
}

// WithDefault applies default settings for encryption
func WithDefault() EncryptionOption {
	return configFunc(func(config *packet.Config) {
		config.DefaultCipher = packet.CipherAES256
		config.DefaultCompressionAlgo = constants.DefaultCompression
		config.CompressionConfig = &packet.CompressionConfig{Level: constants.DefaultCompressionLevel}
	})
}

// WithCompression allows None, Zip or Zlib compression algorithms and sets compression level
func WithCompression(compressionAlgo packet.CompressionAlgo,
	compressionConfig *packet.CompressionConfig) EncryptionOption {
	return configFunc(func(config *packet.Config) {
		config.DefaultCompressionAlgo = compressionAlgo
		config.CompressionConfig = compressionConfig
	})
}

// WithCipher allows Cipher3DES, CipherCAST5, CipherAES128, CipherAES192, CipherAES256 ciphers to be set
func WithCipher(cipher packet.CipherFunction) EncryptionOption {
	return configFunc(func(config *packet.Config) {
		config.DefaultCipher = cipher
	})
}

// WithSigningContext defines signing context in encryption configuration
func WithSigningContext(signingContext *SigningContext) EncryptionOption {
	return configFunc(func(config *packet.Config) {
		config.SignatureNotations = append(config.SignatureNotations, signingContext.getNotation())
	})
}
