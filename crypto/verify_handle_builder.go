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

// VerifyKeys sets the public keys for verifying the signatures.
func (vhb *VerifyHandleBuilder) VerifyKeys(verifyKeys *KeyRing) *VerifyHandleBuilder {
	vhb.handle.VerifyKeyRing = verifyKeys
	return vhb
}

func (vhb *VerifyHandleBuilder) VerifyKey(key *Key) *VerifyHandleBuilder {
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

// DisableVerifyTimeCheck disables the check for comparing the signature creation time
// against the verification time.
func (dpb *VerifyHandleBuilder) DisableVerifyTimeCheck() *VerifyHandleBuilder {
	dpb.handle.DisableVerifyTimeCheck = true
	return dpb
}

// Armored indicates if the signature input to the verify function is armored or not.
// In the default case, it assumes that the signature is not armored.
// Does not have an effect on VerifyHandle.VerifyCleartext.
func (vhb *VerifyHandleBuilder) Armored() *VerifyHandleBuilder {
	vhb.handle.Armored = true
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
