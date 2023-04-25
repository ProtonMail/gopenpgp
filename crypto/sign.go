package crypto

import "github.com/ProtonMail/go-crypto/openpgp/packet"

type SignProfile interface {
	SignConfig() *packet.Config
}

// PGPSign is an interface for detached signing with GopenPGP.
type PGPSign interface {
	// SigningWriter returns a wrapper around underlying output Writer,
	// such that any write-operation via the wrapper results in a write to a detached or inline signature message.
	// Once close is called on the returned WriteCloser the final signature is written to the output.
	// Thus, the returned WriteCloser must be closed after the plaintext has been written.
	SigningWriter(output Writer, metadata *LiteralMetadata) (WriteCloser, error)
	// SignDetached creates a detached or inline signature from the provided byte slice.
	// Metadata is only considered for inline signatures that embed the data in a literal data packet.
	// If metadata is nil for an inline signature, default values are used.
	Sign(message []byte, metadata *LiteralMetadata) ([]byte, error)
	// SignCleartext produces an armored cleartext message according to the specification.
	// Returns an armored message even if the PGPSign is not configured for armored output.
	SignCleartext(message []byte) ([]byte, error)
	// ClearPrivateParams clears all secret key material contained in the PGPSign from memory,
	ClearPrivateParams()
}
