package crypto

import (
	"bytes"
	"strconv"

	"github.com/pkg/errors"

	"golang.org/x/crypto/openpgp/packet"
)

// DecryptSessionKey returns the decrypted session key from one or multiple binary encrypted session key packets.
func (keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SessionKey, error) {
	var p packet.Packet
	var ek *packet.EncryptedKey

	var err error
	var hasPacket = false
	var decryptErr error

	keyReader := bytes.NewReader(keyPacket)
	packets := packet.NewReader(keyReader)

	for {
		if p, err = packets.Next(); err != nil {
			break
		}

		var ok bool
		ek, ok = p.(*packet.EncryptedKey)
		if !ok {
			continue
		}

		hasPacket = true
		for _, key := range keyRing.entities.DecryptionKeys() {
			priv := key.PrivateKey
			if priv.Encrypted {
				continue
			}

			if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
				break
			}
		}
	}

	if !hasPacket {
		return nil, errors.Wrap(err, "gopenpgp: error in reading packets")
	}

	if decryptErr != nil {
		return nil, errors.Wrap(decryptErr, "gopenpgp: error in decrypting")
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
			return nil, errors.Wrap(err, "gopenpgp: cannot set key")
		}
	}
	return outbuf.Bytes(), nil
}
