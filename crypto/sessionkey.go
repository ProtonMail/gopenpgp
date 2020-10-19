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
func (sk *SessionKey) GetCipherFunc() (packet.CipherFunction, error) {
	cf, ok := symKeyAlgos[sk.Algo]
	if !ok {
		return cf, errors.New("gopenpgp: unsupported cipher function: " + sk.Algo)
	}
	return cf, nil
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
func GenerateSessionKey() (*SessionKey, error) {
	return GenerateSessionKeyAlgo(constants.AES256)
}

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
	if algo == "" {
		return nil, fmt.Errorf("gopenpgp: unsupported cipher function: %v", ek.CipherFunc)
	}

	sk := &SessionKey{
		Key:  ek.Key,
		Algo: algo,
	}

	if err := sk.checkSize(); err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to decrypt session key")
	}

	return sk, nil
}

// Encrypt encrypts a PlainMessage to PGPMessage with a SessionKey.
// * message : The plain data as a PlainMessage.
// * output  : The encrypted data as PGPMessage.
func (sk *SessionKey) Encrypt(message *PlainMessage) ([]byte, error) {
	dc, err := sk.GetCipherFunc()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to encrypt with session key")
	}

	config := &packet.Config{
		Time:          getTimeGenerator(),
		DefaultCipher: dc,
	}

	return encryptWithSessionKey(message, sk, config)
}

// EncryptWithCompression encrypts and compresses a PlainMessage to PGPMessage with a SessionKey.
// * message : The plain data as a PlainMessage.
// * compressionAlgorithm:
//    CompressionNone CompressionAlgo = 0
//	  CompressionZIP  CompressionAlgo = 1
//	  CompressionZLIB CompressionAlgo = 2
// * level: integer between -1 and 9. -1 for automatic, 0 to 9 for manual selection.
// * output  : The encrypted data as PGPMessage.
func (sk *SessionKey) EncryptWithCompression(
	message *PlainMessage,
	compressionAlgorithm packet.CompressionAlgo,
	level int,
) ([]byte, error) {
	dc, err := sk.GetCipherFunc()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to encrypt with session key")
	}

	config := &packet.Config{
		Time:                   getTimeGenerator(),
		DefaultCipher:          dc,
		DefaultCompressionAlgo: compressionAlgorithm,
		CompressionConfig:      &packet.CompressionConfig{Level: level},
	}

	return encryptWithSessionKey(message, sk, config)
}

func encryptWithSessionKey(message *PlainMessage, sk *SessionKey, config *packet.Config) ([]byte, error) {
	var encBuf bytes.Buffer
	var encryptWriter io.WriteCloser

	encryptWriter, err := packet.SerializeSymmetricallyEncrypted(&encBuf, config.Cipher(), sk.Key, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to encrypt")
	}

	if algo := config.Compression(); algo != packet.CompressionNone {
		encryptWriter, err = packet.SerializeCompressed(encryptWriter, algo, config.CompressionConfig)
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: error in compression")
		}
	}

	encryptWriter, err = packet.SerializeLiteral(
		encryptWriter,
		message.IsBinary(),
		message.Filename,
		message.Time,
	)

	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to serialize")
	}

	_, err = encryptWriter.Write(message.GetBinary())
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in writing message")
	}

	err = encryptWriter.Close()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in closing message")
	}

	return encBuf.Bytes(), nil
}

// Decrypt decrypts password protected pgp binary messages.
// * encrypted: PGPMessage.
// * output: PlainMessage.
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
		dc, err := sk.GetCipherFunc()
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to decrypt with session key")
		}

		decrypted, err = p.Decrypt(dc, sk.Key)
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to decrypt symmetric packet")
		}

	default:
		return nil, errors.New("gopenpgp: invalid packet type")
	}
	_, err = decBuf.ReadFrom(decrypted)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to read from decrypted symmetric packet")
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
		return nil, errors.Wrap(err, "gopenpgp: error in reading message body")
	}

	return &PlainMessage{
		Data:     messageBuf.Bytes(),
		TextType: !md.LiteralData.IsBinary,
		Filename: md.LiteralData.FileName,
		Time:     md.LiteralData.Time,
	}, nil
}

func (sk *SessionKey) checkSize() error {
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
	algo := constants.AES256
	for k, v := range symKeyAlgos {
		if v == cipher {
			algo = k
			break
		}
	}

	return algo
}
