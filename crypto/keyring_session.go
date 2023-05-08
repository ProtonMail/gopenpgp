package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

Loop:
	for {
		if p, err = packets.Next(); err != nil {
			break
		}

		switch p := p.(type) {
		case *packet.EncryptedKey:
			hasPacket = true
			ek = p

			for _, key := range keyRing.entities.DecryptionKeys() {
				priv := key.PrivateKey
				if priv.Encrypted {
					continue
				}

				if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
					break Loop
				}
			}

		case *packet.SymmetricallyEncrypted,
			*packet.AEADEncrypted,
			*packet.Compressed,
			*packet.LiteralData:
			break Loop

		default:
			continue Loop
		}
	}

	if !hasPacket {
		return nil, fmt.Errorf("gopenpgp: couldn't find a session key packet: %w", err)
	}

	if decryptErr != nil {
		return nil, fmt.Errorf("gopenpgp: error in decrypting: %w", decryptErr)
	}

	if ek == nil || ek.Key == nil {
		return nil, errors.New("gopenpgp: unable to decrypt session key: no valid decryption key")
	}

	return newSessionKeyFromEncrypted(ek)
}

// EncryptSessionKey encrypts the session key with the unarmored
// publicKey and returns a binary public-key encrypted session key packet.
func (keyRing *KeyRing) EncryptSessionKey(sk *SessionKey) ([]byte, error) {
	outbuf := &bytes.Buffer{}
	cf, err := sk.GetCipherFunc()
	if err != nil {
		return nil, fmt.Errorf("gopenpgp: unable to encrypt session key: %w", err)
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
			return nil, fmt.Errorf("gopenpgp: cannot set key: %w", err)
		}
	}
	return outbuf.Bytes(), nil
}
