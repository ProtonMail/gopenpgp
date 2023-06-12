package crypto

import (
	"time"

	"github.com/ProtonMail/gopenpgp/v3/profile"
)

type PGPHandle struct {
	profile     *profile.Custom
	defaultTime Clock
	localTime   Clock
}

// PGP creates a PGPHandle to interact with the API.
// Uses the default profile for configuration.
func PGP() *PGPHandle {
	return PGPWithProfile(profile.Default())
}

// PGPWithProfile creates a PGPHandle to interact with the API.
// Uses the provided profile for configuration.
func PGPWithProfile(profile *profile.Custom) *PGPHandle {
	defaultClock := time.Now
	return &PGPHandle{
		profile:     profile,
		defaultTime: defaultClock,
		localTime:   defaultClock,
	}
}

// Encryption returns a builder to create an EncryptionHandle
// for encrypting messages.
func (p *PGPHandle) Encryption() *EncryptionHandleBuilder {
	return newEncryptionHandleBuilder(p.profile, p.defaultTime)
}

// Decryption returns a builder to create a DecryptionHandle
// for decrypting pgp messages.
func (p *PGPHandle) Decryption() *DecryptionHandleBuilder {
	return newDecryptionHandleBuilder(p.defaultTime)
}

// Sign returns a builder to create a SignHandle
// for signing messages.
func (p *PGPHandle) Sign() *SignHandleBuilder {
	return newSignHandleBuilder(p.profile, p.defaultTime)
}

// Verify returns a builder to create an VerifyHandle
// for verifying signatures.
func (p *PGPHandle) Verify() *VerifyHandleBuilder {
	return newVerifyHandleBuilder(p.defaultTime)
}

func (p *PGPHandle) KeyGeneration() *KeyGenerationBuilder {
	return newKeyGenerationBuilder(p.profile, p.defaultTime)
}

// LockKey encrypts the private parts of a copy of the input key with the given passphrase.
func (p *PGPHandle) LockKey(key *Key, passphrase []byte) (*Key, error) {
	return key.lock(passphrase, p.profile)
}

// GenerateSessionKey generates a random session key for the profile.
func (p *PGPHandle) GenerateSessionKey() (*SessionKey, error) {
	config := p.profile.EncryptionConfig()
	return generateSessionKey(config)
}

// SetTime sets the pgp handle time for key generation to the
// provided unix timestamp instead of using the local device time.
func (p *PGPHandle) SetKeyGenTime(unixTime int64) {
	p.localTime = NewConstantClock(unixTime)
}
