package crypto

import (
	"bytes"
	"io"
	"strconv"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

// decryptSessionKey returns the decrypted session key from one or multiple binary encrypted session key packets.
func decryptSessionKey(keyRing *KeyRing, keyPacket []byte) (*SessionKey, error) {
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
			unverifiedEntities := keyRing.entities.EntitiesById(p.KeyId)
			for _, unverifiedEntity := range unverifiedEntities {
				keys := unverifiedEntity.DecryptionKeys(p.KeyId, time.Time{})
				for _, key := range keys {
					priv := key.PrivateKey
					if priv.Encrypted {
						continue
					}

					if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
						break Loop
					}
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
		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: couldn't find a session key packet")
		} else {
			return nil, errors.New("gopenpgp: couldn't find a session key packet")
		}
	}

	if decryptErr != nil {
		return nil, errors.Wrap(decryptErr, "gopenpgp: error in decrypting")
	}

	if ek == nil || ek.Key == nil {
		return nil, errors.New("gopenpgp: unable to decrypt session key: no valid decryption key")
	}

	return newSessionKeyFromEncrypted(ek)
}

// encryptSessionKey encrypts the session key with the unarmored
// publicKey and returns a binary public-key encrypted session key packet.
func encryptSessionKey(
	recipients *KeyRing,
	hiddenRecipients *KeyRing,
	sk *SessionKey,
	date time.Time,
	config *packet.Config) ([]byte, error) {
	outbuf := &bytes.Buffer{}
	err := encryptSessionKeyToWriter(recipients, hiddenRecipients, sk, outbuf, date, config)
	if err != nil {
		return nil, err
	}
	return outbuf.Bytes(), nil
}

// EncryptSessionKeyToWriter encrypts the session key with the unarmored
// publicKey and returns a binary public-key encrypted session key packet.
func encryptSessionKeyToWriter(
	recipients *KeyRing,
	hiddenRecipients *KeyRing,
	sk *SessionKey,
	outputWriter io.Writer,
	date time.Time,
	config *packet.Config,
) (err error) {
	var cf packet.CipherFunction
	if sk.v6 {
		cf = config.Cipher()
	} else {
		cf, err = sk.GetCipherFunc()
	}
	if err != nil {
		return errors.Wrap(err, "gopenpgp: unable to encrypt session key")
	}
	pubKeys := make([]*packet.PublicKey, 0, len(recipients.getEntities())+len(hiddenRecipients.getEntities()))
	aeadSupport := config.AEAD() != nil
	for _, e := range append(recipients.getEntities(), hiddenRecipients.getEntities()...) {
		encryptionKey, ok := e.EncryptionKey(date, config)
		if !ok {
			return errors.New("gopenpgp: encryption key is unavailable for key id " + strconv.FormatUint(e.PrimaryKey.KeyId, 16))
		}
		primarySelfSignature, _ := e.PrimarySelfSignature(date)
		if primarySelfSignature == nil {
			return errors.Wrap(err, "gopenpgp: entity without a self-signature")
		}

		if !primarySelfSignature.SEIPDv2 {
			aeadSupport = false
		}
		pubKeys = append(pubKeys, encryptionKey.PublicKey)
	}
	if len(pubKeys) == 0 {
		return errors.New("gopenpgp: cannot set key: no public key available")
	}

	for index, pub := range pubKeys {
		isHidden := index >= len(recipients.getEntities())
		err := packet.SerializeEncryptedKeyAEADwithHiddenOption(outputWriter, pub, cf, aeadSupport, sk.Key, isHidden, nil)
		if err != nil {
			return errors.Wrap(err, "gopenpgp: cannot set key")
		}
	}
	return nil
}

// decryptSessionKeyWithPassword decrypts the binary symmetrically encrypted
// session key packet and returns the session key.
func decryptSessionKeyWithPassword(keyPacket, password []byte) (*SessionKey, error) {
	keyReader := bytes.NewReader(keyPacket)
	packets := packet.NewReader(keyReader)

	var symKeys []*packet.SymmetricKeyEncrypted
	for {
		var p packet.Packet
		var err error
		if p, err = packets.Next(); err != nil {
			break
		}

		if p, ok := p.(*packet.SymmetricKeyEncrypted); ok {
			symKeys = append(symKeys, p)
		}
	}

	// Try the symmetric passphrase first
	if len(symKeys) != 0 && password != nil {
		for _, s := range symKeys {
			key, cipherFunc, err := s.Decrypt(password)
			if err == nil {
				sk := &SessionKey{
					Key:  key,
					Algo: getAlgo(cipherFunc),
					v6:   cipherFunc == 0, // for v6 there is not algorithm specified
				}

				if err = sk.checkSize(); !sk.v6 && err != nil {
					return nil, errors.Wrap(err, "gopenpgp: unable to decrypt session key with password")
				}

				return sk, nil
			}
		}
	}

	return nil, errors.New("gopenpgp: unable to decrypt any packet")
}

// encryptSessionKeyWithPassword encrypts the session key with the password and
// returns a binary symmetrically encrypted session key packet.
func encryptSessionKeyWithPassword(sk *SessionKey, password []byte, config *packet.Config) (encrypted []byte, err error) {
	outbuf := &bytes.Buffer{}
	err = encryptSessionKeyWithPasswordToWriter(password, sk, outbuf, config)
	if err != nil {
		return nil, err
	}
	return outbuf.Bytes(), nil
}

func encryptSessionKeyWithPasswordToWriter(password []byte, sk *SessionKey, outputWriter io.Writer, config *packet.Config) (err error) {
	var cf packet.CipherFunction
	if sk.v6 {
		cf = config.Cipher()
	} else {
		cf, err = sk.GetCipherFunc()
	}
	if err != nil {
		return errors.Wrap(err, "gopenpgp: unable to encrypt session key with password")
	}

	if len(password) == 0 {
		return errors.New("gopenpgp: password can't be empty")
	}

	if err = sk.checkSize(); !sk.v6 && err != nil {
		return errors.Wrap(err, "gopenpgp: unable to encrypt session key with password")
	}
	config.DefaultCipher = cf

	err = packet.SerializeSymmetricKeyEncryptedReuseKey(outputWriter, sk.Key, password, config)
	if err != nil {
		return errors.Wrap(err, "gopenpgp: unable to encrypt session key with password")
	}
	return nil
}
