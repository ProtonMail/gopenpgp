package crypto

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/armor"
	"github.com/ProtonMail/gopenpgp/constants"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// IsBinKeyExpired checks whether the given (unarmored, binary) key is expired.
func (pgp *GopenPGP) IsBinKeyExpired(publicKey []byte) (bool, error) {
	now := pgp.getNow()
	pubKeyReader := bytes.NewReader(publicKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return true, err
	}
	candidateSubkey := -1
	for _, e := range pubKeyEntries {
		var maxTime time.Time
		for i, subkey := range e.Subkeys {
			if subkey.Sig.FlagsValid &&
				subkey.Sig.FlagEncryptCommunications &&
				subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
				!subkey.PublicKey.KeyExpired(subkey.Sig, now) &&
				(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
				candidateSubkey = i
				maxTime = subkey.Sig.CreationTime
			}
		}

		if candidateSubkey != -1 {
			return false, nil
		}

		// If we don't have any candidate subkeys for encryption and
		// the primary key doesn't have any usage metadata then we
		// assume that the primary key is ok. Or, if the primary key is
		// marked as ok to encrypt to, then we can obviously use it.
		var firstIdentity *openpgp.Identity
		for _, ident := range e.Identities {
			if firstIdentity == nil {
				firstIdentity = ident
			}
			if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
				firstIdentity = ident
				break
			}
		}
		if firstIdentity != nil {
			i := firstIdentity
			if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagEncryptCommunications &&
				e.PrimaryKey.PubKeyAlgo.CanEncrypt() &&
				!e.PrimaryKey.KeyExpired(i.SelfSignature, now) {
				return false, nil
			}
		}
	}
	return true, errors.New("keys expired")
}

// IsKeyStringExpired checks whether the given armored key is expired.
func (pgp *GopenPGP) IsStringKeyExpired(publicKey string) (bool, error) {
	rawPubKey, err := armor.Unarmor(publicKey)
	if err != nil {
		return false, err
	}
	return pgp.IsBinKeyExpired(rawPubKey)
}

func (pgp *GopenPGP) generateKey(
	userName, domain, passphrase, keyType string,
	bits int,
	prime1, prime2, prime3, prime4 []byte,
) (string, error) {
	if len(userName) <= 0 {
		return "", errors.New("invalid user name format")
	}
	var email = userName

	if len(domain) > 0 {
		email = email + "@" + domain
	}

	comments := ""

	cfg := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       bits,
		Time:          pgp.getTimeGenerator(),
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	if keyType == "x25519" {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	}

	if prime1 != nil && prime2 != nil && prime3 != nil && prime4 != nil {
		var bigPrimes [4]*big.Int
		bigPrimes[0] = new(big.Int)
		bigPrimes[0].SetBytes(prime1)
		bigPrimes[1] = new(big.Int)
		bigPrimes[1].SetBytes(prime2)
		bigPrimes[2] = new(big.Int)
		bigPrimes[2].SetBytes(prime3)
		bigPrimes[3] = new(big.Int)
		bigPrimes[3].SetBytes(prime4)

		cfg.RSAPrimes = bigPrimes[:]
	}

	newEntity, err := openpgp.NewEntity(email, comments, email, cfg)
	if err != nil {
		return "", err
	}

	if err := newEntity.SelfSign(nil); err != nil {
		return "", err
	}

	rawPwd := []byte(passphrase)
	if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
		if err := newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
			return "", err
		}
	}

	for _, sub := range newEntity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
			if err := sub.PrivateKey.Encrypt(rawPwd); err != nil {
				return "", err
			}
		}
	}

	w := bytes.NewBuffer(nil)
	if err := newEntity.SerializePrivateNoSign(w, nil); err != nil {
		return "", err
	}
	serialized := w.Bytes()
	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// GenerateRSAKeyWithPrimes generates a RSA key using the given primes.
func (pgp *GopenPGP) GenerateRSAKeyWithPrimes(
	userName, domain, passphrase string,
	bits int,
	primeone, primetwo, primethree, primefour []byte,
) (string, error) {
	return pgp.generateKey(userName, domain, passphrase, "rsa", bits, primeone, primetwo, primethree, primefour)
}

// GenerateKey generates a key of the given keyType ("rsa" or "x25519"). If
// keyType is "rsa", bits is the RSA bitsize of the key. If keyType is "x25519",
// bits is unused.
func (pgp *GopenPGP) GenerateKey(userName, domain, passphrase, keyType string, bits int) (string, error) {
	return pgp.generateKey(userName, domain, passphrase, keyType, bits, nil, nil, nil, nil)
}

// UpdatePrivateKeyPassphrase decrypts the given armored privateKey with
// oldPassphrase, re-encrypts it with newPassphrase, and returns the new armored
// key.
func (pgp *GopenPGP) UpdatePrivateKeyPassphrase(
	privateKey string, oldPassphrase string, newPassphrase string,
) (string, error) {
	privKey := strings.NewReader(privateKey)
	privKeyEntries, err := openpgp.ReadArmoredKeyRing(privKey)
	if err != nil {
		return "", err
	}

	oldrawPwd := []byte(oldPassphrase)
	newRawPwd := []byte(newPassphrase)
	w := bytes.NewBuffer(nil)
	for _, e := range privKeyEntries {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt(oldrawPwd); err != nil {
				return "", err
			}
		}
		if e.PrivateKey != nil && !e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Encrypt(newRawPwd); err != nil {
				return "", err
			}
		}

		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Decrypt(oldrawPwd); err != nil {
					return "", err
				}
			}
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Encrypt(newRawPwd); err != nil {
					return "", err
				}
			}
		}
		if err := e.SerializePrivateNoSign(w, nil); err != nil {
			return "", err
		}
	}

	serialized := w.Bytes()
	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// PrintFingerprints is a debug helper function that prints the key and subkey fingerprints.
func (pgp *GopenPGP) PrintFingerprints(pubKey string) (string, error) {
	pubKeyReader := strings.NewReader(pubKey)
	entries, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return "", err
	}

	for _, e := range entries {
		for _, subKey := range e.Subkeys {
			if !subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications {
				fmt.Println("SubKey:" + hex.EncodeToString(subKey.PublicKey.Fingerprint[:]))
			}
		}
		fmt.Println("PrimaryKey:" + hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))
	}
	return "", nil
}
