package crypto

// VerifyHandleBuilder configures a VerifyHandle handle.
type VerifyHandleBuilder struct {
	handle       *verifyHandle
	defaultClock Clock
	err          error
	profile      SignProfile
}

func newVerifyHandleBuilder(profile SignProfile, clock Clock) *VerifyHandleBuilder {
	return &VerifyHandleBuilder{
		handle:       defaultVerifyHandle(profile, clock),
		defaultClock: clock,
		profile:      profile,
	}
}

// VerificationKeys sets the public keys for verifying the signatures.
func (vhb *VerifyHandleBuilder) VerificationKeys(keys *KeyRing) *VerifyHandleBuilder {
	vhb.handle.VerifyKeyRing = keys
	return vhb
}

// VerificationKey sets the public key for verifying the signatures.
func (vhb *VerifyHandleBuilder) VerificationKey(key *Key) *VerifyHandleBuilder {
	var err error
	if vhb.handle.VerifyKeyRing == nil {
		vhb.handle.VerifyKeyRing, err = NewKeyRing(key)
	} else {
		err = vhb.handle.VerifyKeyRing.AddKey(key)
	}
	vhb.err = err
	return vhb
}

// VerificationContext sets a verification context for signatures of the pgp message, if any.
// Only considered if VerifyKeys are set.
func (vhb *VerifyHandleBuilder) VerificationContext(verifyContext *VerificationContext) *VerifyHandleBuilder {
	vhb.handle.VerificationContext = verifyContext
	return vhb
}

// VerifyTime sets the verification time to the provided timestamp.
// If not set, the systems current time is used for signature verification.
func (vhb *VerifyHandleBuilder) VerifyTime(unixTime int64) *VerifyHandleBuilder {
	vhb.handle.clock = NewConstantClock(unixTime)
	return vhb
}

// Utf8 indicates if the output plaintext is Utf8 and
// should be sanitized from canonicalised line endings.
// If enabled for detached verification, it canonicalises the input
// before verification independent of the signature type.
func (vhb *VerifyHandleBuilder) Utf8() *VerifyHandleBuilder {
	vhb.handle.IsUTF8 = true
	return vhb
}

// DisableVerifyTimeCheck disables the check for comparing the signature expiration time
// against the verification time.
func (vhb *VerifyHandleBuilder) DisableVerifyTimeCheck() *VerifyHandleBuilder {
	vhb.handle.DisableVerifyTimeCheck = true
	return vhb
}

// DisableStrictMessageParsing disables the check that the inputs conform
// to the OpenPGP message grammar.
// If set, no error is thrown if the input message does not conform to the
// OpenPGP specification.
func (vhb *VerifyHandleBuilder) DisableStrictMessageParsing() *VerifyHandleBuilder {
	vhb.handle.DisableStrictMessageParsing = true
	return vhb
}

// DisableAutomaticTextSanitize indicates that automatic text sanitization should be disabled.
// If not disabled, the output will be sanitized if a text signature is present.
func (vhb *VerifyHandleBuilder) DisableAutomaticTextSanitize() *VerifyHandleBuilder {
	vhb.handle.DisableAutomaticTextSanitize = true
	return vhb
}

// New creates a VerifyHandle and checks that the given
// combination of parameters is valid. If the parameters are invalid,
// an error is returned.
func (vhb *VerifyHandleBuilder) New() (PGPVerify, error) {
	if vhb.err != nil {
		return nil, vhb.err
	}
	vhb.err = vhb.handle.validate()
	if vhb.err != nil {
		return nil, vhb.err
	}
	handle := vhb.handle
	vhb.handle = defaultVerifyHandle(vhb.profile, vhb.defaultClock)
	return handle, nil
}

// Error returns any errors that occurred within the builder.
func (vhb *VerifyHandleBuilder) Error() error {
	return vhb.err
}
