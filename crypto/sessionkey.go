package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v3/constants"

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
	// v6 is a flag to indicate that the session key is capable
	// to be used in v6 PKESK or SKESK, and SEIPDv2 packets
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
	if !sk.hasAlgorithm() {
		return 0, errors.New("gopenpgp: no cipher function available for the session key")
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

// IsV6 indicates if the session key can be used with SEIPDv2, PKESKv6/SKESKv6.
func (sk *SessionKey) IsV6() bool {
	return sk.v6
}

// RandomToken generates a random token with the specified key size.
func RandomToken(size int) ([]byte, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256}
	symKey := make([]byte, size)
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return nil, fmt.Errorf("gopenpgp: error in generating random token: %w", err)
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

// GenerateSessionKey generates a random key.
// Considers the cipher and aead preferences in recipients and hiddenRecipients for
// session key generation.
func generateSessionKey(config *packet.Config, recipients *KeyRing, hiddenRecipients *KeyRing) (*SessionKey, error) {
	candidateCiphers := []uint8{
		uint8(packet.CipherAES256),
		uint8(packet.CipherAES128),
	}

	currentTime := config.Now()
	aeadSupport := config.AEADConfig != nil
	for _, e := range append(recipients.getEntities(), hiddenRecipients.getEntities()...) {
		primarySelfSignature, _ := e.PrimarySelfSignature(currentTime, config)
		if primarySelfSignature == nil {
			continue
		}

		if !primarySelfSignature.SEIPDv2 {
			aeadSupport = false
		}

		candidateCiphers = intersectPreferences(candidateCiphers, primarySelfSignature.PreferredSymmetric)
	}

	if len(candidateCiphers) == 0 {
		candidateCiphers = []uint8{uint8(packet.CipherAES128)}
	}
	cipher := packet.CipherFunction(candidateCiphers[0])

	// If the cipher specified by config is a candidate, we'll use that.
	configuredCipher := config.Cipher()
	for _, c := range candidateCiphers {
		cipherFunc := packet.CipherFunction(c)
		if cipherFunc == configuredCipher {
			cipher = cipherFunc
			break
		}
	}

	algo, ok := algosToSymKey[cipher]
	if !ok {
		return nil, errors.New("gopenpgp: unsupported cipher function")
	}

	r, err := RandomToken(cipher.KeySize())
	if err != nil {
		return nil, err
	}

	sk := &SessionKey{
		Key:  r,
		Algo: algo,
		v6:   aeadSupport,
	}
	return sk, nil
}

// NewSessionKeyFromToken creates a SessionKey struct with the given token and algorithm.
// Clones the token for compatibility with go-mobile.
func NewSessionKeyFromToken(token []byte, algo string) *SessionKey {
	return &SessionKey{
		Key:  clone(token),
		Algo: algo,
	}
}

// NewSessionKeyFromTokenWithAead creates a SessionKey struct with the given token and algorithm.
// If aead is set to true, the key is used with v6 PKESK or SKESK, and SEIPDv2 packets.
func NewSessionKeyFromTokenWithAead(token []byte, algo string, aead bool) *SessionKey {
	return &SessionKey{
		Key:  clone(token),
		Algo: algo,
		v6:   aead,
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
			return nil, fmt.Errorf("gopenpgp: unable to decrypt session key: %w", err)
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

func (sk *SessionKey) hasAlgorithm() bool {
	return sk.Algo != ""
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

func intersectPreferences(a []uint8, b []uint8) (intersection []uint8) {
	var currentIndex int
	for _, valueFirst := range a {
		for _, valueSecond := range b {
			if valueFirst == valueSecond {
				a[currentIndex] = valueFirst
				currentIndex++
				break
			}
		}
	}
	return a[:currentIndex]
}
