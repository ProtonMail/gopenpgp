package crypto

import "github.com/ProtonMail/go-crypto/openpgp/packet"

type EncryptionProfile interface {
	EncryptionConfig() *packet.Config
	CompressionConfig() *packet.Config
}

// PGPEncryption is an interface for encrypting messages with GopenPGP.
// Use an EncryptionHandleBuilder to create a PGPEncryption handle.
type PGPEncryption interface {
	// EncryptingWriter returns a wrapper around underlying output Writer,
	// such that any write-operation via the wrapper results in a write to an encrypted pgp message.
	// If the output Writer is of type PGPSplitWriter, the output can be split to multiple writers
	// for different parts of the message. For example to write key packets and encrypted data packets
	// to different writers or to write a detached signature separately.
	// The encoding argument defines the output encoding, i.e., Bytes or Armored
	// The returned pgp message WriteCloser must be closed after the plaintext has been written.
	EncryptingWriter(output Writer, encoding int8) (WriteCloser, error)
	// Encrypt encrypts a plaintext message.
	Encrypt(message []byte) (*PGPMessage, error)
	// EncryptSessionKey encrypts a session key with the encryption handle.
	// To encrypt a session key, the handle must contain either recipients or a password.
	EncryptSessionKey(sessionKey *SessionKey) ([]byte, error)
	// ClearPrivateParams clears all private key material contained in EncryptionHandle from memory.
	ClearPrivateParams()
}

// Writer replicates the io.Writer interface for go-mobile.
type Writer interface {
	Write(b []byte) (n int, err error)
}

// WriteCloser replicates the io.WriteCloser interface for go-mobile.
type WriteCloser interface {
	Write(b []byte) (n int, err error)
	Close() (err error)
}

// PGPSplitWriter is an interface to write different parts of a PGP message
// (i.e., packets) to different streams.
type PGPSplitWriter interface {
	Writer
	// Keys returns the Writer to which the key packets are written to.
	Keys() Writer
	// Signature returns the Writer to which an encrypted detached signature is written to.
	Signature() Writer
}
