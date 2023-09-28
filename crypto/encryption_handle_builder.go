package crypto

import "github.com/ProtonMail/gopenpgp/v3/constants"

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

func (epb *EncryptionHandleBuilder) Recipient(key *Key) *EncryptionHandleBuilder {
	var err error
	if epb.handle.Recipients == nil {
		epb.handle.Recipients, err = NewKeyRing(key)
	} else {
		err = epb.handle.Recipients.AddKey(key)
	}
	epb.err = err
	return epb
}

// Recipients sets the public keys to which the message should be encrypted to.
// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
// The recipients are included in the intended recipient fingerprint list
// of the signature, if a signature is present.
// If not set, set another type of encryption: HiddenRecipients, SessionKey, or Password
func (epb *EncryptionHandleBuilder) Recipients(recipients *KeyRing) *EncryptionHandleBuilder {
	epb.handle.Recipients = recipients
	return epb
}

func (epb *EncryptionHandleBuilder) HiddenRecipient(key *Key) *EncryptionHandleBuilder {
	var err error
	if epb.handle.HiddenRecipients == nil {
		epb.handle.HiddenRecipients, err = NewKeyRing(key)
	} else {
		err = epb.handle.HiddenRecipients.AddKey(key)
	}
	epb.err = err
	return epb
}

// HiddenRecipients sets the public keys to which the message should be encrypted to.
// Triggers hybrid encryption with public keys of the recipients and hidden recipients.
// The hidden recipients are NOT included in the intended recipient fingerprint list
// of the signature, if a signature is present.
// If not set, set another type of encryption: Recipients, SessionKey, or Password
func (epb *EncryptionHandleBuilder) HiddenRecipients(hiddenRecipients *KeyRing) *EncryptionHandleBuilder {
	epb.handle.HiddenRecipients = hiddenRecipients
	return epb
}

func (epb *EncryptionHandleBuilder) SigningKey(key *Key) *EncryptionHandleBuilder {
	var err error
	if epb.handle.SignKeyRing == nil {
		epb.handle.SignKeyRing, err = NewKeyRing(key)
	} else {
		err = epb.handle.SignKeyRing.AddKey(key)
	}
	epb.err = err
	return epb
}

// SigningKeys sets the signing keys that are used to create signature of the message.
// Triggers that signatures are created for each signing key.
// If not set, no signature is included.
func (epb *EncryptionHandleBuilder) SigningKeys(signingKeys *KeyRing) *EncryptionHandleBuilder {
	epb.handle.SignKeyRing = signingKeys
	return epb
}

// SigningContext provides a signing context for the signature in the message.
// Triggers that each signature includes the sining context.
// SigningKeys have to be set if a SigningContext is provided.
func (epb *EncryptionHandleBuilder) SigningContext(siningContext *SigningContext) *EncryptionHandleBuilder {
	epb.handle.SigningContext = siningContext
	return epb
}

// SessionKey sets the session key the message should be encrypted with.
// Triggers session key encryption with the included session key.
// If not set, set another the type of encryption: Recipients, HiddenRecipients, or Password
func (epb *EncryptionHandleBuilder) SessionKey(sessionKey *SessionKey) *EncryptionHandleBuilder {
	epb.handle.SessionKey = sessionKey
	return epb
}

// Password sets a password the message should be encrypted with.
// Triggers password based encryption with a key derived from the password.
// If not set, set another the type of encryption: Recipients, HiddenRecipients, or SessionKey
func (epb *EncryptionHandleBuilder) Password(password []byte) *EncryptionHandleBuilder {
	epb.handle.Password = password
	return epb
}

// Compress indicates if the plaintext should be compressed before encryption.
// Compression affects security and opens the door for side-channel attacks, which
// might allow to extract the plaintext data without a decryption key.
// The openpgp crypto refresh recommends to not use compression.
func (epb *EncryptionHandleBuilder) Compress() *EncryptionHandleBuilder {
	epb.handle.Compression = constants.DefaultCompression
	return epb
}

// CompressWith indicates if the plaintext should be compressed before encryption.
// Compression affects security and opens the door for side-channel attacks, which
// might allow to extract the plaintext data without a decryption key.
// The openpgp crypto refresh recommends to not use compression.
// Allowed config options:
// constants.NoCompression: none, constants.DefaultCompression: profile default
// constants.ZIBCompression: zib constants.ZLIBCompression: zlib
func (epb *EncryptionHandleBuilder) CompressWith(config int8) *EncryptionHandleBuilder {
	switch config {
	case constants.NoCompression,
		constants.DefaultCompression,
		constants.ZIPCompression,
		constants.ZLIBCompression:
		epb.handle.Compression = config
	}
	return epb
}

// Utf8 indicates if the plaintext should be signed with a text type
// signature. If set, the plaintext is signed after canonicalising the line endings.
func (epb *EncryptionHandleBuilder) Utf8() *EncryptionHandleBuilder {
	epb.handle.IsUTF8 = true
	return epb
}

// DetachedSignature indicates that the message should be signed,
// but the signature should not be included in the same pgp message as the input data.
// Instead the detached signature is encrypted in a separate pgp message.
func (epb *EncryptionHandleBuilder) DetachedSignature() *EncryptionHandleBuilder {
	epb.handle.DetachedSignature = true
	return epb
}

// IncludeExternalSignature indicates that the provided signature should be included
// in the produced encrypted message.
// Special feature: should not be used in normal use-cases,
// can lead to broken or invalid PGP messages.
func (epb *EncryptionHandleBuilder) IncludeExternalSignature(signature []byte) *EncryptionHandleBuilder {
	epb.handle.ExternalSignature = signature
	return epb
}

// SignTime sets the internal clock to always return
// the supplied unix time for signing instead of the system time
func (ehb *EncryptionHandleBuilder) SignTime(unixTime int64) *EncryptionHandleBuilder {
	ehb.handle.clock = NewConstantClock(unixTime)
	return ehb
}

// New creates an EncryptionHandle and checks that the given
// combination of parameters is valid. If the parameters are invalid
// an error is returned
func (epb *EncryptionHandleBuilder) New() (PGPEncryption, error) {
	if epb.err != nil {
		return nil, epb.err
	}
	epb.err = epb.handle.validate()
	if epb.err != nil {
		return nil, epb.err
	}
	params := epb.handle
	epb.handle = defaultEncryptionHandle(epb.handle.profile, epb.defaultClock)
	return params, nil
}

func (epb *EncryptionHandleBuilder) Error() error {
	return epb.err
}
