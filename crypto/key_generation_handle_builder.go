package crypto

// KeyGenerationBuilder allows to configure a key generation handle to generate OpenPGP keys.
type KeyGenerationBuilder struct {
	handle       *keyGenerationHandle
	defaultClock Clock
}

func newKeyGenerationBuilder(profile KeyGenerationProfile, clock Clock) *KeyGenerationBuilder {
	return &KeyGenerationBuilder{
		handle:       defaultKeyGenerationHandle(profile, clock),
		defaultClock: clock,
	}
}

// GenerationTime sets the key generation time to the given unixTime.
func (kgb *KeyGenerationBuilder) GenerationTime(unixTime int64) *KeyGenerationBuilder {
	kgb.handle.clock = NewConstantClock(unixTime)
	return kgb
}

// Lifetime sets the key lifetime to the given value in seconds.
// The lifetime defaults to zero i.e., infinite lifetime.
func (kgb *KeyGenerationBuilder) Lifetime(seconds int32) *KeyGenerationBuilder {
	kgb.handle.keyLifetimeSecs = uint32(seconds)
	return kgb
}

// AddUserId adds the provided user identity to any generated key.
func (kgb *KeyGenerationBuilder) AddUserId(name, email string) *KeyGenerationBuilder {
	kgb.handle.identities = append(kgb.handle.identities, identity{name, "", email})
	return kgb
}

// New creates a new key generation handle from the internal configuration
// that allows to generate pgp keys.
func (kgb *KeyGenerationBuilder) New() PGPKeyGeneration {
	handle := kgb.handle
	kgb.handle = defaultKeyGenerationHandle(kgb.handle.profile, kgb.defaultClock)
	return handle
}
