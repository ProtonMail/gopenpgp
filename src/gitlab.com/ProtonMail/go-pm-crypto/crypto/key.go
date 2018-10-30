package crypto

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"math/big"
	"gitlab.com/ProtonMail/go-pm-crypto/armor"
)

const (
	ok         = 0
	notSigned  = 1
	noVerifier = 2
	failed     = 3
)

//IsKeyExpiredBin ...
func (pm *PmCrypto) IsKeyExpiredBin(publicKey []byte) (bool, error) {
	now := pm.getNow()
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
				!subkey.Sig.KeyExpired(now) &&
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
				!i.SelfSignature.KeyExpired(now) {
				return false, nil
			}
		}
	}
	return true, errors.New("keys expired")
}

//IsKeyExpired ....
// will user the cached time to check
func (pm *PmCrypto) IsKeyExpired(publicKey string) (bool, error) {
	rawPubKey, err := armor.Unarmor(publicKey)
	if err != nil {
		return false, err
	}
	return pm.IsKeyExpiredBin(rawPubKey)
}

func (pm *PmCrypto) generateKey(userName string, domain string, passphrase string, keyType string, bits int,
	prime1 []byte, prime2 []byte, prime3 []byte, prime4 []byte) (string, error) {

	if len(userName) <= 0 {
		return "", errors.New("Invalid user name format")
	}
	var email = userName

	if len(domain) > 0 {
		email = email + "@" + domain
	}

	comments := ""

	cfg := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       bits,
		Time:          pm.getTimeGenerator(),
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
	return armor.ArmorWithType(serialized, armor.PRIVATE_KEY_HEADER)
}

func (pm *PmCrypto) GenerateRSAKeyWithPrimes(userName string, domain string, passphrase string, bits int,
	primeone []byte, primetwo []byte, primethree []byte, primefour []byte) (string, error) {
	return pm.generateKey(userName, domain, passphrase, "rsa", bits, primeone, primetwo, primethree, primefour)
}

// GenerateKey ...
// disabled now, will enable later
// #generat new key with email address. Fix the UserID issue in protonmail system. on Feb 28, 17
// #static generate_key_with_email(email : string, passphrase : string, bits : i32) : open_pgp_key;
// # generate new key
// #static generate_new_key(user_id : string, email : string, passphrase : string, bits : i32) : open_pgp_key;
func (pm *PmCrypto) GenerateKey(userName string, domain string, passphrase string, keyType string, bits int) (string, error) {
	return pm.generateKey(userName, domain, passphrase, keyType, bits, nil, nil, nil, nil)
}

// UpdatePrivateKeyPassphrase ...
func (pm *PmCrypto) UpdatePrivateKeyPassphrase(privateKey string, oldPassphrase string, newPassphrase string) (string, error) {

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
	return armor.ArmorWithType(serialized, armor.PRIVATE_KEY_HEADER)
}

// CheckKey print out the key and subkey fingerprint
func (pm *PmCrypto) CheckKey(pubKey string) (string, error) {
	pubKeyReader := strings.NewReader(pubKey)
	entries, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return "", err
	}

	for _, e := range entries {
		for _, subKey := range e.Subkeys {
			if !subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications {

				println("SubKey:" + hex.EncodeToString(subKey.PublicKey.Fingerprint[:]))

			}
		}
		println("PrimaryKey:" + hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))

	}
	return "", nil
}
