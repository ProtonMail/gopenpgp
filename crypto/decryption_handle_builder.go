package crypto

// DecryptionHandleBuilder allows to configure a decryption handle
// to decrypt a pgp message.
type DecryptionHandleBuilder struct {
	handle       *decryptionHandle
	defaultClock Clock
	err          error
	profile      EncryptionProfile
}

func newDecryptionHandleBuilder(profile EncryptionProfile, clock Clock) *DecryptionHandleBuilder {
	return &DecryptionHandleBuilder{
		handle:       defaultDecryptionHandle(profile, clock),
		defaultClock: clock,
		profile:      profile,
	}
}

// DecryptionKeys sets the secret keys for decrypting the pgp message.
// Assumes that the message was encrypted towards one of the secret keys.
// Triggers the hybrid decryption mode.
// If not set, set another field for the type of decryption: SessionKey or Password.
func (dpb *DecryptionHandleBuilder) DecryptionKeys(decryptionKeyRing *KeyRing) *DecryptionHandleBuilder {
	dpb.handle.DecryptionKeyRing = decryptionKeyRing
	return dpb
}

func (dpb *DecryptionHandleBuilder) DecryptionKey(decryptionKey *Key) *DecryptionHandleBuilder {
	var err error
	if dpb.handle.DecryptionKeyRing == nil {
		dpb.handle.DecryptionKeyRing, err = NewKeyRing(decryptionKey)
	} else {
		err = dpb.handle.DecryptionKeyRing.AddKey(decryptionKey)
	}
	dpb.err = err
	return dpb
}

// SessionKey sets a session key for decrypting the pgp message.
// Assumes that the message was encrypted with session key provided.
// Triggers the session key decryption mode.
// If not set, set another field for the type of decryption: DecryptionKeys or Password.
func (dpb *DecryptionHandleBuilder) SessionKey(sessionKey *SessionKey) *DecryptionHandleBuilder {
	dpb.handle.SessionKeys = []*SessionKey{sessionKey}
	return dpb
}

// SessionKeys sets multiple session keys for decrypting the pgp message.
// Assumes that the message was encrypted with one of the session keys provided.
// Triggers the session key decryption mode.
// If not set, set another field for the type of decryption: DecryptionKeys or Password.
// Not supported on go-mobile clients.
func (dpb *DecryptionHandleBuilder) SessionKeys(sessionKeys []*SessionKey) *DecryptionHandleBuilder {
	dpb.handle.SessionKeys = sessionKeys
	return dpb
}

// Password sets a password that is used to derive a key to decrypt the pgp message.
// Assumes that the message was encrypted with a key derived from the password.
// Triggers the password decryption mode.
// If not set, set another field for the type of decryption: DecryptionKeys or SessionKey.
func (dpb *DecryptionHandleBuilder) Password(password []byte) *DecryptionHandleBuilder {
	dpb.handle.Passwords = [][]byte{password}
	return dpb
}

// Passwords sets passwords that are used to derive keys to decrypt the pgp message.
// Assumes that the message was encrypted with one of the keys derived from the passwords.
// Triggers the password decryption mode.
// If not set, set another field for the type of decryption: DecryptionKeys or SessionKey.
// Not supported on go-mobile clients.
func (dpb *DecryptionHandleBuilder) Passwords(passwords [][]byte) *DecryptionHandleBuilder {
	dpb.handle.Passwords = passwords
	return dpb
}

// VerificationKeys sets the public keys for verifying the signatures of the pgp message, if any.
// If not set, the signatures cannot be verified.
func (dpb *DecryptionHandleBuilder) VerificationKeys(keys *KeyRing) *DecryptionHandleBuilder {
	dpb.handle.VerifyKeyRing = keys
	return dpb
}

// VerificationKey sets the public key for verifying the signatures of the pgp message, if any.
// If not set, the signatures cannot be verified.
func (dpb *DecryptionHandleBuilder) VerificationKey(key *Key) *DecryptionHandleBuilder {
	var err error
	if dpb.handle.VerifyKeyRing == nil {
		dpb.handle.VerifyKeyRing, err = NewKeyRing(key)
	} else {
		err = dpb.handle.VerifyKeyRing.AddKey(key)
	}
	dpb.err = err
	return dpb
}

// VerificationContext sets a verification context for signatures of the pgp message, if any.
// Only considered if VerifyKeys are set.
func (dpb *DecryptionHandleBuilder) VerificationContext(verifyContext *VerificationContext) *DecryptionHandleBuilder {
	dpb.handle.VerificationContext = verifyContext
	return dpb
}

// VerifyTime sets the verification time to the provided timestamp.
// If not set, the systems current time is used for signature verification.
func (dpb *DecryptionHandleBuilder) VerifyTime(unixTime int64) *DecryptionHandleBuilder {
	dpb.handle.clock = NewConstantClock(unixTime)
	return dpb
}

// Utf8 indicates if the output plaintext is Utf8 and
// should be sanitized from canonicalised line endings.
func (dpb *DecryptionHandleBuilder) Utf8() *DecryptionHandleBuilder {
	dpb.handle.IsUTF8 = true
	return dpb
}

// DisableVerifyTimeCheck disables the check for comparing the signature creation time
// against the verification time.
func (dpb *DecryptionHandleBuilder) DisableVerifyTimeCheck() *DecryptionHandleBuilder {
	dpb.handle.DisableVerifyTimeCheck = true
	return dpb
}

// DisableStrictMessageParsing disables the check that decryption inputs conform
// to the OpenPGP Message grammar.
// If set, the decryption methods return no error if the message does not conform to the
// OpenPGP message grammar.
func (dpb *DecryptionHandleBuilder) DisableStrictMessageParsing() *DecryptionHandleBuilder {
	dpb.handle.DisableStrictMessageParsing = true
	return dpb
}

// DisableIntendedRecipients indicates if the signature verification should not check if
// the decryption key matches the intended recipients of the message.
// If disabled, the decryption methods throw no error in a non-matching case.
func (dpb *DecryptionHandleBuilder) DisableIntendedRecipients() *DecryptionHandleBuilder {
	dpb.handle.DisableIntendedRecipients = true
	return dpb
}

// DisableAutomaticTextSanitize indicates that automatic text sanitization should be disabled.
// If not disabled, the output will be sanitized if a text signature is present.
func (dpb *DecryptionHandleBuilder) DisableAutomaticTextSanitize() *DecryptionHandleBuilder {
	dpb.handle.DisableAutomaticTextSanitize = true
	return dpb
}

// RetrieveSessionKey sets the flag to indicate if the session key used for decryption
// should be returned to the caller of the decryption function.
func (dpb *DecryptionHandleBuilder) RetrieveSessionKey() *DecryptionHandleBuilder {
	dpb.handle.RetrieveSessionKey = true
	return dpb
}

// New creates a DecryptionHandle and checks that the given
// combination of parameters is valid. If one of the parameters are invalid
// the latest error is returned.
func (dpb *DecryptionHandleBuilder) New() (PGPDecryption, error) {
	if dpb.err != nil {
		return nil, dpb.err
	}
	dpb.err = dpb.handle.validate()
	if dpb.err != nil {
		return nil, dpb.err
	}
	handle := dpb.handle
	dpb.handle = defaultDecryptionHandle(dpb.profile, dpb.defaultClock)
	return handle, nil
}

func (dpb *DecryptionHandleBuilder) Error() error {
	return dpb.err
}
