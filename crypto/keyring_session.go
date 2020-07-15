package crypto

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/pkg/errors"

	"golang.org/x/crypto/openpgp/packet"
)

// DecryptSessionKey returns the decrypted session key from a binary encrypted session key packet.
func (keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SessionKey, error) {
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

	return newSessionKeyFromEncrypted(ek)
}

// EncryptSessionKey encrypts the session key with the unarmored
// publicKey and returns a binary public-key encrypted session key packet.
func (keyRing *KeyRing) EncryptSessionKey(sk *SessionKey) ([]byte, error) {
	outbuf := &bytes.Buffer{}
	cf, err := sk.GetCipherFunc()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to encrypt session key")
	}

	pubKeys := make([]*packet.PublicKey, 0, len(keyRing.entities))
	for _, e := range keyRing.entities {
		encryptionKey, ok := e.EncryptionKey(getNow())
		if !ok {
			return nil, errors.New("gopenpgp: encryption key is unavailable for key id " + strconv.FormatUint(e.PrimaryKey.KeyId, 16))
		}
		pubKeys = append(pubKeys, encryptionKey.PublicKey)
	}
	if len(pubKeys) == 0 {
		return nil, errors.New("cannot set key: no public key available")
	}

	for _, pub := range pubKeys {
		if err := packet.SerializeEncryptedKey(outbuf, pub, cf, sk.Key, nil); err != nil {
			err = fmt.Errorf("gopenpgp: cannot set key: %v", err)
			return nil, err
		}
	}
	return outbuf.Bytes(), nil
}
