package crypto

import (
	"encoding/base64"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/pkg/errors"

	pgpErrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// SessionKey stores a decrypted session key.
type SessionKey struct {
	// Key defines the decrypted binary session key.
	Key []byte
	// Algo defines the symmetric encryption algorithm used with this key.
	// Only present if the key was not parsed from a v6 packet.
	Algo string
	// v6 is a flag to indicate that the session key was parsed from a v6 PKESK or SKESK packet
	v6 bool
}

var symKeyAlgos = map[string]packet.CipherFunction{
	constants.ThreeDES:  packet.Cipher3DES,
	constants.TripleDES: packet.Cipher3DES,
	constants.CAST5:     packet.CipherCAST5,
	constants.AES128:    packet.CipherAES128,
	constants.AES192:    packet.CipherAES192,
	constants.AES256:    packet.CipherAES256,
}

var algosToSymKey = map[packet.CipherFunction]string{
	packet.Cipher3DES:   constants.TripleDES,
	packet.CipherCAST5:  constants.CAST5,
	packet.CipherAES128: constants.AES128,
	packet.CipherAES192: constants.AES192,
	packet.CipherAES256: constants.AES256,
}

type checkReader struct {
	decrypted io.ReadCloser
	body      io.Reader
}

func (cr checkReader) Read(buf []byte) (int, error) {
	n, sensitiveParsingError := cr.body.Read(buf)
	if sensitiveParsingError == io.EOF {
		mdcErr := cr.decrypted.Close()
		if mdcErr != nil {
			return n, mdcErr
		}
		return n, io.EOF
	}

	if sensitiveParsingError != nil {
		return n, pgpErrors.StructuralError("parsing error")
	}

	return n, nil
}

// GetCipherFunc returns the cipher function corresponding to the algorithm used
// with this SessionKey.
// Not supported in go-mobile clients use sk.GetCipherFuncInt instead.
func (sk *SessionKey) GetCipherFunc() (packet.CipherFunction, error) {
	if sk.v6 {
		return 0, errors.New("gopenpgp: no cipher function available for a v6 session key")
	}
	cf, ok := symKeyAlgos[sk.Algo]
	if !ok {
		return cf, errors.New("gopenpgp: unsupported cipher function: " + sk.Algo)
	}
	return cf, nil
}

// GetCipherFuncInt returns the cipher function as int8 corresponding to the algorithm used
// with this SessionKey.
// The int8 type is used for go-mobile clients, see constant.Cipher...
func (sk *SessionKey) GetCipherFuncInt() (int8, error) {
	cipherFunc, err := sk.GetCipherFunc()
	return int8(cipherFunc), err
}

// GetBase64Key returns the session key as base64 encoded string.
func (sk *SessionKey) GetBase64Key() string {
	return base64.StdEncoding.EncodeToString(sk.Key)
}

// RandomToken generates a random token with the specified key size.
func RandomToken(size int) ([]byte, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256}
	symKey := make([]byte, size)
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in generating random token")
	}
	return symKey, nil
}

// GenerateSessionKeyAlgo generates a random key of the correct length for the
// specified algorithm.
func GenerateSessionKeyAlgo(algo string) (sk *SessionKey, err error) {
	cf, ok := symKeyAlgos[algo]
	if !ok {
		return nil, errors.New("gopenpgp: unknown symmetric key generation algorithm")
	}
	r, err := RandomToken(cf.KeySize())
	if err != nil {
		return nil, err
	}

	sk = &SessionKey{
		Key:  r,
		Algo: algo,
	}
	return sk, nil
}

// GenerateSessionKey generates a random key for the default cipher.
func generateSessionKey(config *packet.Config) (*SessionKey, error) {
	cf, ok := algosToSymKey[config.DefaultCipher]
	if !ok {
		return nil, errors.New("gopenpgp: unsupported cipher function")
	}
	return GenerateSessionKeyAlgo(cf)
}

// NewSessionKeyFromToken creates a SessionKey struct with the given token and algorithm.
// Clones the token for compatibility with go-mobile.
func NewSessionKeyFromToken(token []byte, algo string) *SessionKey {
	return &SessionKey{
		Key:  clone(token),
		Algo: algo,
	}
}

func newSessionKeyFromEncrypted(ek *packet.EncryptedKey) (*SessionKey, error) {
	var algo string
	for k, v := range symKeyAlgos {
		if v == ek.CipherFunc {
			algo = k
			break
		}
	}
	if algo == "" && ek.Version < 6 {
		return nil, fmt.Errorf("gopenpgp: unsupported cipher function: %v", ek.CipherFunc)
	}

	sk := &SessionKey{
		Key:  ek.Key,
		Algo: algo,
		v6:   ek.Version == 6,
	}
	if ek.Version < 6 {
		if err := sk.checkSize(); err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to decrypt session key")
		}
	}
	return sk, nil
}

func (sk *SessionKey) checkSize() error {
	if sk.v6 {
		// cannot check size
		return errors.New("unknown key size")
	}
	cf, ok := symKeyAlgos[sk.Algo]
	if !ok {
		return errors.New("unknown symmetric key algorithm")
	}

	if cf.KeySize() != len(sk.Key) {
		return errors.New("wrong session key size")
	}

	return nil
}

func getAlgo(cipher packet.CipherFunction) string {
	algo := ""
	for k, v := range symKeyAlgos {
		if v == cipher {
			algo = k
			break
		}
	}
	return algo
}
