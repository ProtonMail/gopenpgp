package crypto

// VerifyHandleBuilder configures a VerifyHandle handle
type VerifyHandleBuilder struct {
	handle       *verifyHandle
	defaultClock Clock
	err          error
}

func newVerifyHandleBuilder(clock Clock) *VerifyHandleBuilder {
	return &VerifyHandleBuilder{
		handle:       defaultVerifyHandle(clock),
		defaultClock: clock,
	}
}

// VerificationKeys sets the public keys for verifying the signatures.
func (vhb *VerifyHandleBuilder) VerificationKeys(keys *KeyRing) *VerifyHandleBuilder {
	vhb.handle.VerifyKeyRing = keys
	return vhb
}

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
func (vhb *VerifyHandleBuilder) Utf8() *VerifyHandleBuilder {
	vhb.handle.IsUTF8 = true
	return vhb
}

// DisableVerifyTimeCheck disables the check for comparing the signature expiration time
// against the verification time.
func (dpb *VerifyHandleBuilder) DisableVerifyTimeCheck() *VerifyHandleBuilder {
	dpb.handle.DisableVerifyTimeCheck = true
	return dpb
}

// EnableStrictMessageParsing enables the check that the inputs conform
// to the OpenPGP message grammar.
// If enabled, an error is thrown if the input message does not conform to the
// OpenPGP specification.
func (vhb *VerifyHandleBuilder) EnableStrictMessageParsing() *VerifyHandleBuilder {
	vhb.handle.EnableStrictMessageParsing = true
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
	vhb.handle = defaultVerifyHandle(vhb.defaultClock)
	return handle, nil
}

func (vhb *VerifyHandleBuilder) Error() error {
	return vhb.err
}
