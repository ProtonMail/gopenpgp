package crypto

import "github.com/ProtonMail/gopenpgp/v3/constants"

// EncryptionHandleBuilder allows to configure a decryption handle to decrypt an OpenPGP message.
type EncryptionHandleBuilder struct {
	handle       *encryptionHandle
	defaultClock Clock
	err          error
}

func newEncryptionHandleBuilder(profile EncryptionProfile, clock Clock) *EncryptionHandleBuilder {
	return &EncryptionHandleBuilder{
		handle:       defaultEncryptionHandle(profile, clock),
		defaultClock: clock,
	}
}

// Recipient sets the public key to which the message should be encrypted to.
// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
// The recipients are included in the intended recipient fingerprint list
// of the signature, if a signature is present.
// If not set, set another type of encryption: HiddenRecipients, SessionKey, or Password.
func (ehb *EncryptionHandleBuilder) Recipient(key *Key) *EncryptionHandleBuilder {
	var err error
	if ehb.handle.Recipients == nil {
		ehb.handle.Recipients, err = NewKeyRing(key)
	} else {
		err = ehb.handle.Recipients.AddKey(key)
	}
	ehb.err = err
	return ehb
}

// Recipients sets the public keys to which the message should be encrypted to.
// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
// The recipients are included in the intended recipient fingerprint list
// of the signature, if a signature is present.
// If not set, set another type of encryption: HiddenRecipients, SessionKey, or Password.
func (ehb *EncryptionHandleBuilder) Recipients(recipients *KeyRing) *EncryptionHandleBuilder {
	ehb.handle.Recipients = recipients
	return ehb
}

// HiddenRecipient sets a public key to which the message should be encrypted to.
// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
// The hidden recipients are NOT included in the intended recipient fingerprint list
// of the signature, if a signature is present.
// If not set, set another type of encryption: Recipients, SessionKey, or Password.
func (ehb *EncryptionHandleBuilder) HiddenRecipient(key *Key) *EncryptionHandleBuilder {
	var err error
	if ehb.handle.HiddenRecipients == nil {
		ehb.handle.HiddenRecipients, err = NewKeyRing(key)
	} else {
		err = ehb.handle.HiddenRecipients.AddKey(key)
	}
	ehb.err = err
	return ehb
}

// HiddenRecipients sets the public keys to which the message should be encrypted to.
// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
// The hidden recipients are NOT included in the intended recipient fingerprint list
// of the signature, if a signature is present.
// If not set, set another type of encryption: Recipients, SessionKey, or Password.
func (ehb *EncryptionHandleBuilder) HiddenRecipients(hiddenRecipients *KeyRing) *EncryptionHandleBuilder {
	ehb.handle.HiddenRecipients = hiddenRecipients
	return ehb
}

// SigningKey sets the signing key that are used to create signature of the message.
// Triggers that signatures are created for each signing key.
// If not set, no signature is included.
func (ehb *EncryptionHandleBuilder) SigningKey(key *Key) *EncryptionHandleBuilder {
	var err error
	if ehb.handle.SignKeyRing == nil {
		ehb.handle.SignKeyRing, err = NewKeyRing(key)
	} else {
		err = ehb.handle.SignKeyRing.AddKey(key)
	}
	ehb.err = err
	return ehb
}

// SigningKeys sets the signing keys that are used to create signature of the message.
// Triggers that signatures are created for each signing key.
// If not set, no signature is included.
func (ehb *EncryptionHandleBuilder) SigningKeys(signingKeys *KeyRing) *EncryptionHandleBuilder {
	ehb.handle.SignKeyRing = signingKeys
	return ehb
}

// SigningContext provides a signing context for the signature in the message.
// Triggers that each signature includes the sining context.
// SigningKeys have to be set if a SigningContext is provided.
func (ehb *EncryptionHandleBuilder) SigningContext(siningContext *SigningContext) *EncryptionHandleBuilder {
	ehb.handle.SigningContext = siningContext
	return ehb
}

// SessionKey sets the session key the message should be encrypted with.
// Triggers session key encryption with the included session key.
// If not set, set another the type of encryption: Recipients, HiddenRecipients, or Password.
func (ehb *EncryptionHandleBuilder) SessionKey(sessionKey *SessionKey) *EncryptionHandleBuilder {
	ehb.handle.SessionKey = sessionKey
	return ehb
}

// Password sets a password the message should be encrypted with.
// Triggers password based encryption with a key derived from the password.
// If not set, set another the type of encryption: Recipients, HiddenRecipients, or SessionKey.
func (ehb *EncryptionHandleBuilder) Password(password []byte) *EncryptionHandleBuilder {
	ehb.handle.Password = password
	return ehb
}

// Compress indicates if the plaintext should be compressed before encryption.
// Compression affects security and opens the door for side-channel attacks, which
// might allow to extract the plaintext data without a decryption key.
// The openpgp crypto refresh recommends to not use compression.
func (ehb *EncryptionHandleBuilder) Compress() *EncryptionHandleBuilder {
	ehb.handle.Compression = constants.DefaultCompression
	return ehb
}

// CompressWith indicates if the plaintext should be compressed before encryption.
// Compression affects security and opens the door for side-channel attacks, which
// might allow to extract the plaintext data without a decryption key.
// The openpgp crypto refresh recommends to not use compression.
// Allowed config options:
// constants.NoCompression: none, constants.DefaultCompression: profile default
// constants.ZIPCompression: zip, constants.ZLIBCompression: zlib.
func (ehb *EncryptionHandleBuilder) CompressWith(config int8) *EncryptionHandleBuilder {
	switch config {
	case constants.NoCompression,
		constants.DefaultCompression,
		constants.ZIPCompression,
		constants.ZLIBCompression:
		ehb.handle.Compression = config
	}
	return ehb
}

// Utf8 indicates if the plaintext should be signed with a text type
// signature. If set, the plaintext is signed after canonicalising the line endings.
func (ehb *EncryptionHandleBuilder) Utf8() *EncryptionHandleBuilder {
	ehb.handle.IsUTF8 = true
	return ehb
}

// DetachedSignature indicates that the message should be signed,
// but the signature should not be included in the same pgp message as the input data.
// Instead the detached signature is encrypted in a separate pgp message.
func (ehb *EncryptionHandleBuilder) DetachedSignature() *EncryptionHandleBuilder {
	ehb.handle.DetachedSignature = true
	return ehb
}

// IncludeExternalSignature indicates that the provided signature should be included
// in the produced encrypted message.
// Special feature: should not be used in normal use-cases,
// can lead to broken or invalid PGP messages.
func (ehb *EncryptionHandleBuilder) IncludeExternalSignature(signature []byte) *EncryptionHandleBuilder {
	ehb.handle.ExternalSignature = signature
	return ehb
}

// EncryptionTime allows to specify a separate time for selecting encryption keys
// instead of the internal clock (also used for signing). Note that the internal clock can be changed with SignTime.
// If the input unixTime is 0 no expiration checks are performed on the encryption keys.
func (ehb *EncryptionHandleBuilder) EncryptionTime(unixTime int64) *EncryptionHandleBuilder {
	if unixTime == 0 {
		ehb.handle.encryptionTimeOverride = ZeroClock()
	} else {
		ehb.handle.encryptionTimeOverride = NewConstantClock(unixTime)
	}
	return ehb
}

// SignTime sets the internal clock to always return
// the supplied unix time for signing instead of the system time.
func (ehb *EncryptionHandleBuilder) SignTime(unixTime int64) *EncryptionHandleBuilder {
	ehb.handle.clock = NewConstantClock(unixTime)
	return ehb
}

// New creates an EncryptionHandle and checks that the given
// combination of parameters is valid. If the parameters are invalid
// an error is returned.
func (ehb *EncryptionHandleBuilder) New() (PGPEncryption, error) {
	if ehb.err != nil {
		return nil, ehb.err
	}
	ehb.err = ehb.handle.validate()
	if ehb.err != nil {
		return nil, ehb.err
	}
	params := ehb.handle
	ehb.handle = defaultEncryptionHandle(ehb.handle.profile, ehb.defaultClock)
	return params, nil
}

// Error returns an errors that occurred within the builder.
func (ehb *EncryptionHandleBuilder) Error() error {
	return ehb.err
}
