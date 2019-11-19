package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp/packet"
)

// RandomToken generated a random token of the same size of the keysize of the default cipher.
func RandomToken() ([]byte, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256}
	return RandomTokenSize(config.DefaultCipher.KeySize())
}

// RandomTokenSize generates a random token with the specified key size
func RandomTokenSize(size int) ([]byte, error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256}
	symKey := make([]byte, size)
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return nil, err
	}
	return symKey, nil
}

// DecryptSessionKey returns the decrypted session key from a binary encrypted session key packet.
func (keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SymmetricKey, error) {
	keyReader := bytes.NewReader(keyPacket)
	packets := packet.NewReader(keyReader)

	var p packet.Packet
	var err error
	if p, err = packets.Next(); err != nil {
		return nil, err
	}

	ek := p.(*packet.EncryptedKey)
	var decryptErr error
	for _, key := range keyRing.entities.DecryptionKeys() {
		priv := key.PrivateKey
		if priv.Encrypted {
			continue
		}

		if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
			break
		}
	}

	if decryptErr != nil {
		return nil, decryptErr
	}

	if ek == nil {
		return nil, errors.New("gopenpgp: unable to decrypt session key")
	}

	return newSymmetricKeyFromEncrypted(ek)
}

// EncryptSessionKey encrypts the session key with the unarmored
// publicKey and returns a binary public-key encrypted session key packet.
func (keyRing *KeyRing) EncryptSessionKey(sessionSplit *SymmetricKey) ([]byte, error) {
	outbuf := &bytes.Buffer{}

	cf := sessionSplit.GetCipherFunc()

	var pub *packet.PublicKey
	for _, e := range keyRing.entities {
		if encryptionKey, ok := e.EncryptionKey(getNow()); ok {
			pub = encryptionKey.PublicKey
			break
		}
	}
	if pub == nil {
		return nil, errors.New("cannot set key: no public key available")
	}

	if err := packet.SerializeEncryptedKey(outbuf, pub, cf, sessionSplit.Key, nil); err != nil {
		err = fmt.Errorf("gopenpgp: cannot set key: %v", err)
		return nil, err
	}
	return outbuf.Bytes(), nil
}
