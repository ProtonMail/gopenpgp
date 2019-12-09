package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/pkg/errors"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// SessionKey stores a decrypted session key.
type SessionKey struct {
	// The decrypted binary session key.
	Key []byte
	// The symmetric encryption algorithm used with this key.
	Algo string
}

var symKeyAlgos = map[string]packet.CipherFunction{
	constants.ThreeDES:  packet.Cipher3DES,
	constants.TripleDES: packet.Cipher3DES,
	constants.CAST5:     packet.CipherCAST5,
	constants.AES128:    packet.CipherAES128,
	constants.AES192:    packet.CipherAES192,
	constants.AES256:    packet.CipherAES256,
}

// GetCipherFunc returns the cipher function corresponding to the algorithm used
// with this SessionKey.
func (sk *SessionKey) GetCipherFunc() packet.CipherFunction {
	cf, ok := symKeyAlgos[sk.Algo]
	if ok {
		return cf
	}

	panic("gopenpgp: unsupported cipher function: " + sk.Algo)
}

// GetBase64Key returns the session key as base64 encoded string.
func (sk *SessionKey) GetBase64Key() string {
	return base64.StdEncoding.EncodeToString(sk.Key)
}

// RandomToken generates a random token with the specified key size
func RandomToken(size int) ([]byte, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256}
	symKey := make([]byte, size)
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return nil, err
	}
	return symKey, nil
}

// GenerateSessionKeyAlgo generates a random key of the correct length for the specified algorithm
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
		Key: r,
		Algo: algo,
	}
	return sk, nil
}

// GenerateSessionKey generates a random key for the default cipher
func GenerateSessionKey() (*SessionKey, error) {
	return GenerateSessionKeyAlgo(constants.AES256)
}

func NewSessionKeyFromToken(token []byte, algo string) *SessionKey {
	return &SessionKey{
		Key:  token,
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
	if algo == "" {
		return nil, fmt.Errorf("gopenpgp: unsupported cipher function: %v", ek.CipherFunc)
	}

	symmetricKey := &SessionKey{
		Key:  ek.Key,
		Algo: algo,
	}
	
	return symmetricKey, nil
}

// Encrypt encrypts a PlainMessage to PGPMessage with a SessionKey
// * message : The plain data as a PlainMessage
// * output  : The encrypted data as PGPMessage
func (sk *SessionKey) Encrypt(message *PlainMessage) ([]byte, error) {
	var encBuf bytes.Buffer
	var encryptWriter io.WriteCloser
	config := &packet.Config{
		Time:          getTimeGenerator(),
		DefaultCipher: sk.GetCipherFunc(),
	}

	encryptWriter, err := packet.SerializeSymmetricallyEncrypted(&encBuf, config.Cipher(), sk.Key, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to encrypt")
	}

	if algo := config.Compression(); algo != packet.CompressionNone {
		encryptWriter, err = packet.SerializeCompressed(encryptWriter, algo, config.CompressionConfig)
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to encrypt")
		}
	}

	encryptWriter, err = packet.SerializeLiteral(encryptWriter, false, "", 0)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to serialize")
	}

	_, err = encryptWriter.Write(message.GetBinary())
	if err != nil {
		return nil, err
	}

	err = encryptWriter.Close()
	if err != nil {
		return nil, err
	}

	return encBuf.Bytes(), nil
}

// Decrypt decrypts password protected pgp binary messages
// * encrypted: PGPMessage
// * output: PlainMessage
func (sk *SessionKey) Decrypt(dataPacket []byte) (*PlainMessage, error) {
	var messageReader = bytes.NewReader(dataPacket)
	var decrypted io.ReadCloser
	var decBuf bytes.Buffer

	// Read symmetrically encrypted data packet
	packets := packet.NewReader(messageReader)
	p, err := packets.Next()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to read symmetric packet")
	}

	// Decrypt data packet
	switch p := p.(type) {
		case *packet.SymmetricallyEncrypted:
			decrypted, err = p.Decrypt(sk.GetCipherFunc(), sk.Key)
			if err != nil {
				return nil, errors.Wrap(err, "gopenpgp: unable to decrypt symmetric packet")
			}

		default:
			return nil, errors.New("gopenpgp: invalid packet type")
	}
	_, err = decBuf.ReadFrom(decrypted)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to decrypt symmetric packet")
	}

	config := &packet.Config{
		Time: getTimeGenerator(),
	}

	// Push decrypted packet as literal packet and use openpgp's reader
	keyring := openpgp.EntityList{} // Ignore signatures, since we have no private key
	md, err := openpgp.ReadMessage(&decBuf, keyring, nil, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to decode symmetric packet")
	}

	messageBuf := new(bytes.Buffer)
	_, err = messageBuf.ReadFrom(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	return NewPlainMessage(messageBuf.Bytes()), nil
}

func getAlgo(cipher packet.CipherFunction) string {
	algo := constants.AES256
	for k, v := range symKeyAlgos {
		if v == cipher {
			algo = k
			break
		}
	}

	return algo
}
