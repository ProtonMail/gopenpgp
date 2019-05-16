package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/internal"

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
func (simmetricKey *SymmetricKey) GetCipherFunc() packet.CipherFunction {
	cf, ok := symKeyAlgos[simmetricKey.Algo]
	if ok {
		return cf
	}

	panic("gopenpgp: unsupported cipher function: " + simmetricKey.Algo)
}

// GetBase64Key returns the session key as base64 encoded string.
func (simmetricKey *SymmetricKey) GetBase64Key() string {
	return base64.StdEncoding.EncodeToString(simmetricKey.Key)
}

func newSymmetricKey(ek *packet.EncryptedKey) (*SymmetricKey, error) {
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

	return &SymmetricKey{
		Key:  ek.Key,
		Algo: algo,
	}, nil
}

// EncryptMessage encrypts a CleartextMessage to PGPMessage with a SymmetricKey
// plainText: CleartextMessage
// trimNewlines bool: if trim new lines before encryption
// output: PGPMessage
func (simmetricKey *SymmetricKey) EncryptMessage(message *CleartextMessage, trimNewlines bool) (*PGPMessage, error) {
	plainText := message.GetString()
	if trimNewlines {
		plainText = internal.TrimNewlines(plainText)
	}
	encrypted, err := symmetricEncrypt([]byte(plainText), simmetricKey)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// Encrypt encrypts a BinaryMessage to PGPMessage with a SymmetricKey
// plainText: BinaryMessage
// output: PGPMessage
func (simmetricKey *SymmetricKey) Encrypt(message *BinaryMessage) (*PGPMessage, error) {
	encrypted, err := symmetricEncrypt(message.GetBinary(), simmetricKey)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// DecryptMessage decrypts a password protected text PGPMessage
// encrypted: PGPMessage
// output: CleartextMessage
func (simmetricKey *SymmetricKey) DecryptMessage(message *PGPMessage) (*CleartextMessage, error) {
	decrypted, err := symmetricDecrypt(message.NewReader(), simmetricKey)
	if err != nil {
		return nil, err
	}

	cleartext := NewCleartextMessage(string(decrypted))
	cleartext.Verified = constants.SIGNATURE_NOT_SIGNED
	return cleartext, nil
}

// Decrypt decrypts password protected pgp binary messages
// encrypted: PGPMessage
// output: BinaryMessage
func (simmetricKey *SymmetricKey) Decrypt(message *PGPMessage) (*BinaryMessage, error) {
	decrypted, err := symmetricDecrypt(message.NewReader(), simmetricKey)
	if err != nil {
		return nil, err
	}

	binMessage := NewBinaryMessage(decrypted)
	binMessage.Verified = constants.SIGNATURE_NOT_SIGNED
	return binMessage, nil
}

// ----- INTERNAL FUNCTIONS ------

func symmetricEncrypt(message []byte, sk *SymmetricKey) ([]byte, error) {
	var outBuf bytes.Buffer

	config := &packet.Config{
		Time: pgp.getTimeGenerator(),
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
		DefaultCipher: sk.GetCipherFunc(),
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
