package crypto

type PGPHandle struct {
	profile Profile
}

// PGP creates a PGPHandle to interact with the API.
// Uses the default profile for configuration.
func PGP() *PGPHandle {
	return PGPWithProfile(ProfileDefault())
}

// PGPWithProfile creates a PGPHandle to interact with the API.
// Uses the provided profile for configuration.
func PGPWithProfile(profile Profile) *PGPHandle {
	return &PGPHandle{
		profile: profile,
	}
}

// Decryption returns a builder to create a DecryptionHandle
// for decrypting pgp messages.
func (p *PGPHandle) Decryption() DecryptionHandleBuilder {
	return newDecryptionParamsBuilder()
}

// Encryption returns a builder to create an EncryptionHandle
// for encrypting messages.
func (p *PGPHandle) Encryption() EncryptionHandleBuilder {
	return newEncryptionHandleBuilder(p.profile)
}

// LockKey encrypts the private parts of a copy of the input key with the given passphrase.
func (p *PGPHandle) LockKey(key *Key, passphrase []byte) (*Key, error) {
	return key.lock(passphrase, p.profile.KeyEncryptionConfig())
}

// GenerateRSAKeyWithPrimes generates a RSA key using the given primes.
func (p *PGPHandle) GenerateRSAKeyWithPrimes(
	name, email string,
	bits int,
	primeone, primetwo, primethree, primefour []byte,
) (*Key, error) {
	return generateRSAKeyWithPrimes(name, email, bits, primeone, primetwo, primethree, primefour, p.profile.KeyGenerationConfig())
}

// GenerateKey generates a key of the given keyType ("rsa", "x25519", "x25519R", "x448R").
// If keyType is "rsa", bits is the RSA bitsize of the key.
// For other key types bits is unused.
// If keyType is "" the method uses the default algorithm in this profile.
func (p *PGPHandle) GenerateKey(name, email string, keyType string, bits int) (*Key, error) {
	return generateKey(name, email, keyType, bits, p.profile.KeyGenerationConfig())
}

// GenerateProfileKey generates key according to the current PGPHandle.
func (p *PGPHandle) GenerateProfileKey(name, email string) (*Key, error) {
	return generateKey(name, email, "", 0, p.profile.KeyGenerationConfig())
}

// GenerateSessionKey generates a random key for the default cipher.
func (p *PGPHandle) GenerateSessionKey() (*SessionKey, error) {
	return generateSessionKey(p.profile.EncryptionConfig())
}
