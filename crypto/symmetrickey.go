package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/constants"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// SymmetricKey stores a decrypted session key.
type SymmetricKey struct {
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
// with this SymmetricKey.
func (symmetricKey *SymmetricKey) GetCipherFunc() packet.CipherFunction {
	cf, ok := symKeyAlgos[symmetricKey.Algo]
	if ok {
		return cf
	}

	panic("gopenpgp: unsupported cipher function: " + symmetricKey.Algo)
}

// GetBase64Key returns the session key as base64 encoded string.
func (symmetricKey *SymmetricKey) GetBase64Key() string {
	return base64.StdEncoding.EncodeToString(symmetricKey.Key)
}

func NewSymmetricKeyFromToken(passphrase, algo string) *SymmetricKey {
	return &SymmetricKey{
		Key:  []byte(passphrase),
		Algo: algo,
	}
}

func newSymmetricKeyFromEncrypted(ek *packet.EncryptedKey) (*SymmetricKey, error) {
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

	symmetricKey := &SymmetricKey{
		Key:  ek.Key,
		Algo: algo,
	}
	
	return symmetricKey, nil
}

// Encrypt encrypts a PlainMessage to PGPMessage with a SymmetricKey
// message : The plain data as a PlainMessage
// output  : The encrypted data as PGPMessage
func (symmetricKey *SymmetricKey) Encrypt(message *PlainMessage) (*PGPMessage, error) {
	encrypted, err := symmetricEncrypt(message.GetBinary(), symmetricKey)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// Decrypt decrypts password protected pgp binary messages
// encrypted: PGPMessage
// output: PlainMessage
func (symmetricKey *SymmetricKey) Decrypt(message *PGPMessage) (*PlainMessage, error) {
	decrypted, err := symmetricDecrypt(message.NewReader(), symmetricKey)
	if err != nil {
		return nil, err
	}

	binMessage := NewPlainMessage(decrypted)
	return binMessage, nil
}

// NewSymmetricKeyFromKeyPacket decrypts the binary symmetrically encrypted
// session key packet and returns the session key.
func NewSymmetricKeyFromKeyPacket(keyPacket []byte, password string) (*SymmetricKey, error) {
	keyReader := bytes.NewReader(keyPacket)
	packets := packet.NewReader(keyReader)

	var symKeys []*packet.SymmetricKeyEncrypted
	for {

		var p packet.Packet
		var err error
		if p, err = packets.Next(); err != nil {
			break
		}

		switch p := p.(type) {
		case *packet.SymmetricKeyEncrypted:
			symKeys = append(symKeys, p)
		}
	}

	pwdRaw := []byte(password)
	// Try the symmetric passphrase first
	if len(symKeys) != 0 && pwdRaw != nil {
		for _, s := range symKeys {
			key, cipherFunc, err := s.Decrypt(pwdRaw)
			if err == nil {
				return &SymmetricKey{
					Key:  key,
					Algo: getAlgo(cipherFunc),
				}, nil
			}

		}
	}

	return nil, errors.New("gopenpgp: password incorrect")
}

// EncryptToKeyPacket encrypts the session key with the password and
// returns a binary symmetrically encrypted session key packet.
func (symmetricKey *SymmetricKey) EncryptToKeyPacket(password string) ([]byte, error) {
	outbuf := &bytes.Buffer{}

	cf := symmetricKey.GetCipherFunc()

	if len(password) <= 0 {
		return nil, errors.New("gopenpgp: password can't be empty")
	}

	pwdRaw := []byte(password)

	config := &packet.Config{
		DefaultCipher: cf,
	}

	err := packet.SerializeSymmetricKeyEncryptedReuseKey(outbuf, symmetricKey.Key, pwdRaw, config)
	if err != nil {
		return nil, err
	}
	return outbuf.Bytes(), nil
}

// ----- INTERNAL FUNCTIONS ------

func symmetricEncrypt(message []byte, sk *SymmetricKey) ([]byte, error) {
	var outBuf bytes.Buffer

	config := &packet.Config{
		Time:          pgp.getTimeGenerator(),
		DefaultCipher: sk.GetCipherFunc(),
	}

	encryptWriter, err := openpgp.SymmetricallyEncrypt(&outBuf, sk.Key, nil, config)
	if err != nil {
		return nil, err
	}
	_, err = encryptWriter.Write(message)
	encryptWriter.Close()

	if err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}

func symmetricDecrypt(encryptedIO io.Reader, sk *SymmetricKey) ([]byte, error) {
	firstTimeCalled := true
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return sk.Key, nil
		}
		return nil, errors.New("gopenpgp: wrong password in symmetric decryption")
	}

	config := &packet.Config{
		Time: pgp.getTimeGenerator(),
	}
	md, err := openpgp.ReadMessage(encryptedIO, nil, prompt, config)
	if err != nil {
		return nil, err
	}

	messageBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(messageBuf, md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	return messageBuf.Bytes(), nil
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
